#!/usr/bin/env bash
# Prove an off-site backup can be restored (D-48), on the maintainer's machine.
#
#   deploy/backup-b2/restore-check.sh <backup-key-file> [pen]
#
# <backup-key-file> is your offline age backup key (the AGE-SECRET-KEY-1... one
# from your password manager, saved to a temporary file). The script:
#   1. decrypts your B2 restore key (~/Documents/hogman-maintainer-restore-b2.env.age,
#      or $HOGMAN_RESTORE_KEY) with it,
#   2. finds the newest backup of <pen> (default: ops) in the bucket,
#   3. downloads it (SHA-1 checked), decrypts it, and unpacks it,
#   4. prints what's inside: files, and member/device counts if sqlite3 is installed.
# Everything goes in a private temp folder that is deleted on exit. Nothing is
# written to the bucket (the restore key can only list and read).
set -euo pipefail

key="${1:-}"; pen="${2:-ops}"
[ -f "$key" ] || { echo "usage: $0 <backup-key-file> [pen]" >&2; exit 2; }
[[ "$pen" =~ ^[a-z][a-z0-9-]{1,40}$ ]] || { echo "bad pen name: $pen" >&2; exit 2; }
restore_key="${HOGMAN_RESTORE_KEY:-$HOME/Documents/hogman-maintainer-restore-b2.env.age}"
[ -f "$restore_key" ] || { echo "no restore key at $restore_key" >&2; exit 2; }
command -v age >/dev/null || { echo "install age first (brew install age)" >&2; exit 2; }
b2="$(cd "$(dirname "$0")" && pwd)/b2.py"

work="$(mktemp -d)"; chmod 700 "$work"
trap 'rm -rf "$work"' EXIT

age -d -i "$key" -o "$work/read.env" "$restore_key"
name="$(python3 -I "$b2" list --env "$work/read.env" | cut -f1 | grep -E "/${pen}-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.age$" | sort | tail -n 1 || true)"
[ -n "$name" ] || { echo "no off-site backups of '$pen' found" >&2; exit 1; }
echo "newest backup of $pen: $name"

python3 -I "$b2" download "$name" --env "$work/read.env" -o "$work/backup.tar.gz.age"
mkdir "$work/x"
age -d -i "$key" "$work/backup.tar.gz.age" | tar -xzf - -C "$work/x"
echo "decrypted and unpacked OK; contents:"
(cd "$work/x" && find . -type f | sort | sed 's/^/  /')

db="$(find "$work/x" -name registrar.db -type f | head -n 1)"
if [ -n "$db" ] && command -v sqlite3 >/dev/null; then
  echo "registrar.db: $(sqlite3 "$db" "SELECT count(*) FROM members WHERE status != 'removed'") members, $(sqlite3 "$db" "SELECT count(*) FROM devices WHERE removed_at IS NULL") live devices, integrity $(sqlite3 "$db" 'PRAGMA integrity_check')"
fi
echo "✓ restore check passed for $pen"
