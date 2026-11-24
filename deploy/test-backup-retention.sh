#!/usr/bin/env bash
# Unit tests for I-16 / D-37 30-day deleted-pen backup expiry on host
# (`hogman-host backup-prune`) and off-host non-deletion (`deploy/backup-pull.sh`).
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST="$DEPLOY_DIR/hogman-host"
PULL="$DEPLOY_DIR/backup-pull.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

HOME_DIR="$TMP/hogman"
BACKUPS="$TMP/backups"
mkdir -p "$HOME_DIR/pens/foo" "$HOME_DIR/pens/foo-bar" "$BACKUPS"

# Live pen `foo-bar` (must never be touched when `foo` is pruned).
printf 'NETWORK=foo-bar\n' > "$HOME_DIR/pens/foo-bar/.env"
printf 'age-encryption.org/v1\nfoo-bar' > "$BACKUPS/foo-bar-20261001T033000Z.tar.gz.age"

# Retired pen `foo` deleted at 2026-10-01T00:00:00Z.
printf 'deleted_at=2026-10-01T00:00:00Z\n' > "$HOME_DIR/pens/foo/.retired"
touch "$HOME_DIR/pens/foo/.removed"
printf 'age-encryption.org/v1\nfoo1' > "$BACKUPS/foo-20260928T033000Z.tar.gz.age"
printf 'age-encryption.org/v1\nfoo2' > "$BACKUPS/foo-20261001T000000Z.tar.gz.age"

# Legacy deleted pen `orphan-old` (no folder in pens/) with one 35-day-old and one 10-day-old backup.
printf 'age-encryption.org/v1\nold' > "$BACKUPS/orphan-old-20260925T033000Z.tar.gz.age"
printf 'age-encryption.org/v1\nnew' > "$BACKUPS/orphan-old-20261020T033000Z.tar.gz.age"

# Host challenge-dns backup (must never be pruned as an orphan pen).
printf 'age-encryption.org/v1\ncdns' > "$BACKUPS/challenge-dns-20260801T033000Z.tar.gz.age"

# 1. Day 29 after foo's deletion (2026-10-30T00:00:00Z = 1793318400):
#    foo's backups MUST stay; orphan-old's 35-day backup IS pruned; orphan-old's 10-day backup stays.
day29=1793318400
HOGMAN_HOME="$HOME_DIR" HOGMAN_BACKUPS="$BACKUPS" BACKUP_NOW_EPOCH="$day29" "$HOST" backup-prune >/dev/null 2>&1

[ -f "$BACKUPS/foo-20260928T033000Z.tar.gz.age" ] || { echo "FAIL: foo backup deleted on day 29" >&2; exit 1; }
[ -f "$BACKUPS/foo-20261001T000000Z.tar.gz.age" ] || { echo "FAIL: foo final backup deleted on day 29" >&2; exit 1; }
[ -f "$BACKUPS/foo-bar-20261001T033000Z.tar.gz.age" ] || { echo "FAIL: live foo-bar backup deleted" >&2; exit 1; }
[ ! -e "$BACKUPS/orphan-old-20260925T033000Z.tar.gz.age" ] || { echo "FAIL: 35-day legacy orphan backup not pruned" >&2; exit 1; }
[ -f "$BACKUPS/orphan-old-20261020T033000Z.tar.gz.age" ] || { echo "FAIL: 10-day legacy orphan backup pruned early" >&2; exit 1; }
[ -f "$BACKUPS/challenge-dns-20260801T033000Z.tar.gz.age" ] || { echo "FAIL: challenge-dns backup pruned" >&2; exit 1; }

# 2. Day 31 with --dry-run keeps foo's backups.
day31=1793491200
HOGMAN_HOME="$HOME_DIR" HOGMAN_BACKUPS="$BACKUPS" BACKUP_NOW_EPOCH="$day31" "$HOST" backup-prune --dry-run >/dev/null 2>&1
[ -f "$BACKUPS/foo-20261001T000000Z.tar.gz.age" ] || { echo "FAIL: --dry-run deleted foo backup" >&2; exit 1; }

# 3. Day 31 real prune removes all of foo's backups and leaves foo-bar + challenge-dns untouched.
out="$(HOGMAN_HOME="$HOME_DIR" HOGMAN_BACKUPS="$BACKUPS" BACKUP_NOW_EPOCH="$day31" "$HOST" backup-prune 2>&1)"
grep -q "pruned 2 expired backup(s) for deleted pen foo" <<<"$out" || { echo "FAIL: expected one summary log line for foo, got: $out" >&2; exit 1; }
[ ! -e "$BACKUPS/foo-20260928T033000Z.tar.gz.age" ] || { echo "FAIL: foo backup survived past day 30" >&2; exit 1; }
[ ! -e "$BACKUPS/foo-20261001T000000Z.tar.gz.age" ] || { echo "FAIL: foo final backup survived past day 30" >&2; exit 1; }
[ -f "$BACKUPS/foo-bar-20261001T033000Z.tar.gz.age" ] || { echo "FAIL: live foo-bar backup damaged by foo prune" >&2; exit 1; }
[ -f "$BACKUPS/challenge-dns-20260801T033000Z.tar.gz.age" ] || { echo "FAIL: challenge-dns backup damaged" >&2; exit 1; }

# 4. Fail-closed orphan guard: missing or empty $PENS deletes nothing (even old archives).
GUARD_BACKUPS="$TMP/guard-backups"
mkdir -p "$GUARD_BACKUPS"
printf 'age-encryption.org/v1\nlive-old' > "$GUARD_BACKUPS/live-20260801T033000Z.tar.gz.age"

# 4a. Missing $PENS directory (e.g. wrong HOGMAN_HOME or unmounted disk).
HOGMAN_HOME="$TMP/missing-home" HOGMAN_BACKUPS="$GUARD_BACKUPS" BACKUP_NOW_EPOCH="$day31" "$HOST" backup-prune >/dev/null 2>&1
[ -f "$GUARD_BACKUPS/live-20260801T033000Z.tar.gz.age" ] || { echo "FAIL: missing PENS deleted backup" >&2; exit 1; }

# 4b. Empty $PENS directory (exists, zero pen folders).
EMPTY_HOME="$TMP/empty-home"
mkdir -p "$EMPTY_HOME/pens"
HOGMAN_HOME="$EMPTY_HOME" HOGMAN_BACKUPS="$GUARD_BACKUPS" BACKUP_NOW_EPOCH="$day31" "$HOST" backup-prune >/dev/null 2>&1
[ -f "$GUARD_BACKUPS/live-20260801T033000Z.tar.gz.age" ] || { echo "FAIL: empty PENS deleted backup" >&2; exit 1; }

# 5. Off-host backup-pull.sh never deletes local archives on the host's say-so
#    (a partial remote list missing `foo` still pulls new files and keeps local `foo`).
PULL_DIR="$TMP/offhost"
FAKE_BIN="$TMP/fakebin"
REMOTE_DIR="$TMP/remote"
mkdir -p "$PULL_DIR" "$FAKE_BIN" "$REMOTE_DIR"

printf 'age-encryption.org/v1\nfoo-local' > "$PULL_DIR/foo-20261120T033000Z.tar.gz.age"
printf 'age-encryption.org/v1\nfoobar-new' > "$REMOTE_DIR/foo-bar-20261124T033000Z.tar.gz.age"

cat > "$FAKE_BIN/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cmd=""
arg=""
for a in "$@"; do
  if [ "$cmd" = "get" ]; then arg="$a"; fi
  if [ "$a" = "list" ] || [ "$a" = "get" ]; then cmd="$a"; fi
done
if [ "$cmd" = "list" ]; then
  printf 'foo-bar-20261124T033000Z.tar.gz.age\n'
elif [ "$cmd" = "get" ]; then
  cat "$FAKE_REMOTE_DIR/$arg"
fi
EOF
chmod +x "$FAKE_BIN/ssh"

PATH="$FAKE_BIN:$PATH" FAKE_REMOTE_DIR="$REMOTE_DIR" "$PULL" test-host "$PULL_DIR" >/dev/null 2>&1
[ -f "$PULL_DIR/foo-bar-20261124T033000Z.tar.gz.age" ] || { echo "FAIL: new foo-bar backup not pulled" >&2; exit 1; }
[ -f "$PULL_DIR/foo-20261120T033000Z.tar.gz.age" ] || { echo "FAIL: partial remote list deleted local foo backup" >&2; exit 1; }

echo "PASS: backup-retention (D-37 / I-16) tests OK"
