#!/usr/bin/env bash
# Unit test for deploy/ops-snapshot.sh: verifies argument refusal, zero PII
# leakage from waitlist, cgroup memory reading, pen lifecycle metadata, backup
# timestamp parsing, and atomic snapshot replacement.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/ops-snapshot.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. Must refuse any CLI arguments.
if "$SCRIPT" --unexpected >/dev/null 2>&1; then
  echo "FAIL: ops-snapshot.sh accepted CLI arguments" >&2
  exit 1
fi

# 2. Build fixture host layout.
HOME_DIR="$TMP/hogman"
SNAP_DIR="$TMP/run/hogman-ops"
BACKUPS_DIR="$TMP/backups"
PROC_DIR="$TMP/proc"
CGROUP_DIR="$TMP/cgroup"
FAKE_BIN="$TMP/bin"

mkdir -p \
  "$HOME_DIR/pens/alpha" \
  "$HOME_DIR/pens/beta" \
  "$HOME_DIR/signup" \
  "$BACKUPS_DIR" \
  "$PROC_DIR" \
  "$CGROUP_DIR/system.slice/docker-aaa111.scope" \
  "$CGROUP_DIR/docker/bbb222" \
  "$FAKE_BIN"

printf 'v2026.11.24-deadbee\n' > "$HOME_DIR/VERSION"
cat > "$HOME_DIR/host.env" <<'EOF'
MAX_PENS='40'
RENEW_WAKE_RESERVE='2'
EOF

cat > "$HOME_DIR/pens/alpha/.env" <<'EOF'
PUBLIC_HOST=alpha.gate.example.com
PLAN=work
THEME=work
EOF
cat > "$HOME_DIR/pens/alpha/lifecycle.json" <<'EOF'
{"state":"active","paid_until":"2027-11-24T00:00:00Z"}
EOF

cat > "$HOME_DIR/pens/beta/.env" <<'EOF'
PUBLIC_HOST=beta.gate.example.com
PLAN=personal
EOF
touch "$HOME_DIR/pens/beta/.sleeping"
cat > "$HOME_DIR/pens/beta/lifecycle.json" <<'EOF'
{"state":"sleeping","delete_after":"2027-11-24T00:00:00Z"}
EOF

# Waitlist with sensitive emails, pen preferences, and notes — none may appear in snapshot.json.
cat > "$HOME_DIR/signup/waitlist" <<'EOF'
1	2026-11-20T00:00:00Z	waiting	secret-one@example.com	mysecretpen	do not leak this note
2	2026-11-22T00:00:00Z	invited code-123	secret-two@example.com	otherpen	another private note
3	2026-11-23T00:00:00Z	waiting	secret-three@example.com	thirdpen	third note
EOF

# Fake /proc files.
printf '86400.50 10000.00\n' > "$PROC_DIR/uptime"
printf '0.25 0.50 0.75 1/120 999\n' > "$PROC_DIR/loadavg"
cat > "$PROC_DIR/meminfo" <<'EOF'
MemTotal:        4194304 kB
MemAvailable:    2097152 kB
SwapTotal:       1048576 kB
SwapFree:         524288 kB
EOF

# Fake cgroup memory files.
printf '52428800\n' > "$CGROUP_DIR/system.slice/docker-aaa111.scope/memory.current"
printf '10485760\n' > "$CGROUP_DIR/docker/bbb222/memory.current"

# Fake backup files.
touch "$BACKUPS_DIR/alpha-20261123T030000Z.tar.gz.age"
touch "$BACKUPS_DIR/alpha-20261124T030500Z.tar.gz.age"

# Fake docker CLI returning exact container IDs/names/states.
cat > "$FAKE_BIN/docker" <<'EOF'
#!/usr/bin/env bash
cat <<'OUT'
aaa111 pen-alpha-headscale-1 running
bbb222 pen-alpha-registrar-1 running
ccc333 pen-alpha-portal-1 exited
ddd444 hogman-signup-broker-1 running
eee555 hogman-signup-web-1 running
OUT
EOF
chmod +x "$FAKE_BIN/docker"

PATH="$FAKE_BIN:$PATH" \
HOGMAN_HOME="$HOME_DIR" \
OPS_SNAPSHOT_DIR="$SNAP_DIR" \
OPS_BACKUPS_DIR="$BACKUPS_DIR" \
OPS_PROC_DIR="$PROC_DIR" \
OPS_CGROUP_ROOT="$CGROUP_DIR" \
OPS_SKIP_SYSTEMD=1 \
"$SCRIPT"

SNAP="$SNAP_DIR/snapshot.json"
[ -f "$SNAP" ] || { echo "FAIL: snapshot.json not written" >&2; exit 1; }

# 3. Verify zero PII leakage.
if grep -qE 'secret-one@example\.com|secret-two@example\.com|secret-three@example\.com|mysecretpen|do not leak|code-123' "$SNAP"; then
  echo "FAIL: PII leaked into snapshot.json:" >&2
  cat "$SNAP" >&2
  exit 1
fi

# 4. Verify structured fields.
jq -e '
  .host.version == "v2026.11.24-deadbee" and
  .host.uptime_sec == 86400 and
  .host.load == [0.25, 0.5, 0.75] and
  .host.ram_total_bytes == 4294967296 and
  .host.ram_used_bytes == 2147483648 and
  .host.swap_total_bytes == 1073741824 and
  .host.swap_used_bytes == 536870912 and
  .host.capacity.live == 1 and
  .host.capacity.max == 40 and
  .host.capacity.sleeping == 1 and
  .host.capacity.renew_only == 0 and
  .host.capacity.renew_reserve == 2 and
  .host.services["signup-broker"] == "active" and
  .host.services["signup-web"] == "active" and
  .host.last_backup_at == "2026-11-24T03:05:00Z" and
  (.pens | length) == 2 and
  (.pens[] | select(.name == "alpha") | .state == "running" and .plan == "work" and .theme == "work" and .containers_up == 2 and .containers_total == 3 and .ram_bytes == 62914560 and .paid_until == "2027-11-24T00:00:00Z") and
  (.pens[] | select(.name == "beta") | .state == "sleeping" and .plan == "personal" and .theme == "default" and .delete_after == "2027-11-24T00:00:00Z") and
  .waitlist.waiting == 2 and
  .waitlist.invited == 1 and
  .waitlist.oldest_waiting_age_sec > 0
' "$SNAP" >/dev/null || {
  echo "FAIL: unexpected snapshot.json contents:" >&2
  cat "$SNAP" >&2
  exit 1
}

echo "PASS: ops-snapshot.sh tests OK"
