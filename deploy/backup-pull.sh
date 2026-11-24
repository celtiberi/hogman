#!/bin/bash
# Pull new encrypted Hogman backups from a server onto this machine.
#
#   backup-pull.sh <server> [folder]      folder defaults to ~/hogman-backups
#
# Uses ~/.ssh/hogman_backup, a key the server allows to list and download
# backups and nothing else (hogman-host backup-allow). The files stay
# encrypted: this machine never holds the key that opens them.
#
# Off-host copies age out 30 days after they were pulled (via the find rule
# below) and are never deleted on the host's say-so, so a broken or compromised
# host cannot wipe off-host archives of live pens.
#
# Run it on a schedule: cron on Linux, a LaunchDaemon on a Mac (see deploy/README.md).
set -euo pipefail
SERVER="${1:?usage: backup-pull.sh <server> [folder]}"
D="${2:-$HOME/hogman-backups}"
mkdir -p "$D" && chmod 700 "$D"
SSH=(ssh -n -i "$HOME/.ssh/hogman_backup" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 "hogman-backup@$SERVER")
while IFS= read -r f; do
  [[ "$f" =~ ^[a-z0-9-]+-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.age$ ]] || continue
  [ -s "$D/$f" ] && continue
  "${SSH[@]}" get "$f" </dev/null > "$D/.$f.part"
  head -c 21 "$D/.$f.part" | grep -q "^age-encryption.org/v1" \
    || { rm -f "$D/.$f.part"; echo "$(date -u +%FT%TZ) $f is not an age file; skipped" >&2; continue; }
  mv "$D/.$f.part" "$D/$f"
  echo "$(date -u +%FT%TZ) pulled $f ($(wc -c < "$D/$f" | tr -d ' ') bytes)"
done < <("${SSH[@]}" list)
find "$D" -maxdepth 1 -name "*.tar.gz.age" -mtime +30 -delete
