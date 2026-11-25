#!/usr/bin/env bash
# Prove an off-site backup can be restored (D-48), on the maintainer's machine.
#
#   deploy/backup-b2/restore-check.sh <backup-key-file> [pen]
#
# <backup-key-file> is your offline age backup key (the AGE-SECRET-KEY-1... one
# from your password manager, saved to a temporary file). The script:
#   1. decrypts your B2 restore key with it (default
#      ~/Documents/hogman-maintainer-restore-b2.env.age; override with
#      HOGMAN_RESTORE_KEY=/path/to/maintainer-restore-b2.env.age),
#   2. finds the newest backup of <pen> (default: ops) in the bucket, ignoring
#      any with a timestamp in the future,
#   3. downloads it (streamed, size-capped, SHA-1 checked), decrypts it, checks
#      every archive entry, and unpacks it,
#   4. prints what's inside: files, and member/device counts if sqlite3 is installed.
#
# Treat what comes back as untrusted: a compromised server holds a key that can
# ADD files to the bucket and the public key backups are encrypted to, so it
# could plant a crafted "backup". So: only regular files and directories are
# unpacked (no links, devices, absolute or ../ paths), total size is capped,
# the database is opened read-only, and everything lives in a private temp
# folder (umask 077) that is deleted on exit. Nothing is written to the bucket.
set -euo pipefail
umask 077

key="${1:-}"; pen="${2:-ops}"
[ -f "$key" ] || { echo "usage: $0 <backup-key-file> [pen]" >&2; exit 2; }
[[ "$pen" =~ ^[a-z][a-z0-9-]{1,40}$ ]] || { echo "bad pen name: $pen" >&2; exit 2; }
restore_key="${HOGMAN_RESTORE_KEY:-$HOME/Documents/hogman-maintainer-restore-b2.env.age}"
[ -f "$restore_key" ] || { echo "no restore key at $restore_key (set HOGMAN_RESTORE_KEY)" >&2; exit 2; }
command -v age >/dev/null || { echo "install age first (brew install age)" >&2; exit 2; }
b2="$(cd "$(dirname "$0")" && pwd)/b2.py"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

age -d -i "$key" -o "$work/read.env" "$restore_key"

# List on its own line so an auth or network error aborts loudly (set -e).
python3 -I "$b2" list --env "$work/read.env" > "$work/list.txt"

# Newest by the timestamp in the file name (across all hosts), skipping any
# dated more than a day in the future.
name="$(python3 -I - "$pen" "$work/list.txt" <<'PY'
import re, sys, time
pen, path = sys.argv[1], sys.argv[2]
pat = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}/" + re.escape(pen) + r"-([0-9]{8}T[0-9]{6}Z)\.tar\.gz\.age$")
limit = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(time.time() + 86400))
best = None
for line in open(path):
    name = line.split("\t", 1)[0].strip()
    m = pat.match(name)
    if m and m.group(1) <= limit and (best is None or m.group(1) > best[0]):
        best = (m.group(1), name)
print(best[1] if best else "")
PY
)"
[ -n "$name" ] || { echo "no off-site backups of '$pen' found" >&2; exit 1; }
echo "newest backup of $pen: $name"

python3 -I "$b2" download "$name" --env "$work/read.env" -o "$work/backup.tar.gz.age"
age -d -i "$key" -o "$work/backup.tar.gz" "$work/backup.tar.gz.age"
mkdir "$work/x"

# Check every entry before unpacking anything.
python3 -I - "$work/backup.tar.gz" "$work/x" <<'PY'
import os, sys, tarfile
src, dest = sys.argv[1], sys.argv[2]
MAX_TOTAL, MAX_ENTRIES = 2 << 30, 10000
total = 0
with tarfile.open(src, "r:gz") as tf:
    members = tf.getmembers()
    if len(members) > MAX_ENTRIES:
        sys.exit(f"refusing: {len(members)} entries")
    for m in members:
        n = m.name
        if not (m.isfile() or m.isdir()):
            sys.exit(f"refusing: {n!r} is not a regular file or directory")
        if n.startswith("/") or ".." in n.replace("\\", "/").split("/"):
            sys.exit(f"refusing: unsafe path {n!r}")
        total += m.size
        if total > MAX_TOTAL:
            sys.exit("refusing: archive too large when unpacked")
    # Entries are already vetted above; the "data" filter (Python 3.12+ and
    # patched older versions) is an extra guard where available.
    kw = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
    for m in members:
        m.mode = 0o700 if m.isdir() else 0o600
        tf.extract(m, dest, set_attrs=False, **kw)
PY

echo "decrypted, checked and unpacked OK; contents:"
(cd "$work/x" && find . -type f | sort | sed 's/^/  /')

db="$(find "$work/x" -name registrar.db -type f | head -n 1)"
if [ -n "$db" ] && command -v sqlite3 >/dev/null; then
  echo "registrar.db: $(sqlite3 -readonly "$db" "SELECT count(*) FROM members WHERE status != 'removed'") members, $(sqlite3 -readonly "$db" "SELECT count(*) FROM devices WHERE removed_at IS NULL") live devices, integrity $(sqlite3 -readonly "$db" 'PRAGMA integrity_check')"
fi
echo "✓ restore check passed for $pen"
