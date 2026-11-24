#!/bin/bash
# Pull new encrypted Hogman backups from a server onto this machine.
#
#   backup-pull.sh <server> [folder]      folder defaults to ~/hogman-backups
#
# Uses ~/.ssh/hogman_backup, a key the server allows to list and download
# backups and nothing else (hogman-host backup-allow). The files stay
# encrypted: this machine never holds the key that opens them.
#
# Retention (D-37):
# - Keeps up to 30 days of local archives for live pens.
# - Mirrors post-deletion expiry: when a pen's backups are completely gone from
#   a valid, non-empty remote list (after the host's 30-day D-37 prune), local
#   archives for that pen are removed too. Fails closed: if the host is
#   unreachable or returns an empty list, nothing local is deleted.
#
# Run it on a schedule: cron on Linux, a LaunchDaemon on a Mac (see deploy/README.md).
set -euo pipefail
SERVER="${1:?usage: backup-pull.sh <server> [folder]}"
D="${2:-$HOME/hogman-backups}"
mkdir -p "$D" && chmod 700 "$D"
SSH=(ssh -n -i "$HOME/.ssh/hogman_backup" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=20 "hogman-backup@$SERVER")

# Fail closed if the host cannot be reached: never mirror deletions on error.
if ! remote_raw="$("${SSH[@]}" list)"; then
  echo "$(date -u +%FT%TZ) failed to list backups on $SERVER; leaving local backups untouched" >&2
  exit 1
fi

remote_files=()
remote_pens=$'\n'
while IFS= read -r f; do
  [[ "$f" =~ ^([a-z0-9-]+)-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.age$ ]] || continue
  remote_files+=("$f")
  pen="${BASH_REMATCH[1]}"
  case "$remote_pens" in
    *$'\n'"$pen"$'\n'*) ;;
    *) remote_pens+="$pen"$'\n' ;;
  esac
done <<<"$remote_raw"

# Fail closed if the remote returned an empty list: a broken or wiped host must
# never wipe the off-host copies of live pens.
if [ "${#remote_files[@]}" -eq 0 ]; then
  echo "$(date -u +%FT%TZ) remote backup list on $SERVER is empty; leaving local backups untouched" >&2
  exit 0
fi

for f in "${remote_files[@]}"; do
  [ -s "$D/$f" ] && continue
  "${SSH[@]}" get "$f" </dev/null > "$D/.$f.part"
  head -c 21 "$D/.$f.part" | grep -q "^age-encryption.org/v1" \
    || { rm -f "$D/.$f.part"; echo "$(date -u +%FT%TZ) $f is not an age file; skipped" >&2; continue; }
  mv "$D/.$f.part" "$D/$f"
  echo "$(date -u +%FT%TZ) pulled $f ($(wc -c < "$D/$f" | tr -d ' ') bytes)"
done

# Mirror host-side deletion expiry (D-37): remove local archives for pens that
# no longer appear anywhere in the host's non-empty backup list (never touch
# host-level challenge-dns archives here).
pruned_pens=$'\n'
for path in "$D"/*.tar.gz.age; do
  [ -f "$path" ] || continue
  base="$(basename "$path")"
  [[ "$base" =~ ^([a-z0-9-]+)-[0-9]{8}T[0-9]{6}Z\.tar\.gz\.age$ ]] || continue
  pen="${BASH_REMATCH[1]}"
  [ "$pen" = "challenge-dns" ] && continue
  case "$remote_pens" in
    *$'\n'"$pen"$'\n'*) continue ;;
  esac
  rm -f -- "$path"
  case "$pruned_pens" in
    *$'\n'"$pen"$'\n'*) ;;
    *)
      pruned_pens+="$pen"$'\n'
      echo "$(date -u +%FT%TZ) pruned local backups for removed pen $pen (no longer on $SERVER, D-37)"
      ;;
  esac
done

find "$D" -maxdepth 1 -name "*.tar.gz.age" -mtime +30 -delete
