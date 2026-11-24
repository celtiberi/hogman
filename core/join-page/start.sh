#!/bin/sh
# Join a Hogman pen.
#
#   curl -fsSL https://<your pen's address>/start | sh
#
# It's safe to read this first: it's short. It asks for your invite link, then
# downloads hogman for this computer from the address in that link,
# checks it against the SHA-256 published there, saves it as ~/hogman
# (keep it: it updates, shares things and leaves the pen later), and runs it.
#
# Your invite link is pasted here, on your computer. It's never part of the
# command and never sent to a server except the pen it's for.
#
# For scripts: curl -fsSL https://<address>/start | sh -s -- '<invite link>' [hogman options]
set -eu

say() { printf '%s\n' "$*"; }
die() { printf '\n✗ %s\n' "$*" >&2; exit 1; }
# A terminal we can really open (/dev/tty exists even where opening it fails).
have_tty() { (exec </dev/tty) 2>/dev/null; }

link="${1:-}"
[ $# -gt 0 ] && shift   # anything after the link goes to hogman (e.g. --handle NAME)
if [ -z "$link" ]; then
  have_tty || die "no terminal to ask for your invite link on; pass it: curl -fsSL <address>/start | sh -s -- '<link>'"
  printf 'Paste your invite link (the page you opened has a button to copy it): ' >/dev/tty
  IFS= read -r link </dev/tty || die "no link given"
fi
link="$(printf '%s' "$link" | tr -d ' \r\n\t')"

# https://<host>/join#t=... (an invite) or #k=... (a device link).
case "$link" in
  https://*) ;;
  *) die "that doesn't look like a Hogman invite link (it starts https:// and contains /join#)" ;;
esac
host="${link#https://}"
host="${host%%/*}"
case "$host" in
  ""|*[!a-zA-Z0-9.:-]*) die "the link's address looks wrong: $host" ;;
esac
# Anchor the path strictly to /join#t=... or /join#k=... on that exact host.
case "$link" in
  "https://$host/join#t="*|"https://$host/join#k="*) ;;
  *) die "that doesn't look like a Hogman invite link (expected https://<host>/join#t=... or #k=...)" ;;
esac
if [ -n "${HOGMAN_EXPECTED_HOST:-}" ] && [ "$host" != "$HOGMAN_EXPECTED_HOST" ]; then
  die "refusing link for $host (expected $HOGMAN_EXPECTED_HOST)"
fi

case "$(uname -s)" in
  Darwin|Linux) os="$(uname -s)" ;;
  *) die "this computer isn't supported yet ($(uname -s)): use a Mac or Linux computer" ;;
esac
arch="$(uname -m)"
file="hogman-$os-$arch"

if command -v sha256sum >/dev/null 2>&1; then sum() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
else die "no sha256sum or shasum on this computer to check the download with"; fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/hogman.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

say ""
say "• Downloading hogman for $os $arch from $host"
curl -fsSL --proto =https --proto-redir =https "https://$host/join/dl/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "couldn't reach https://$host"
want="$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS")"
[ -n "$want" ] || die "there's no hogman for $os $arch yet"
curl -fsSL --proto =https --proto-redir =https "https://$host/join/dl/$file" -o "$tmp/hogman" || die "the download failed; try again"
got="$(sum "$tmp/hogman")"
[ "$got" = "$want" ] || die "the download doesn't match its published SHA-256 (want $want, got $got); not running it"
say "  checked: SHA-256 matches"

dest="$HOME/hogman"
chmod 0755 "$tmp/hogman"
mv -f "$tmp/hogman" "$dest"
say "  saved as $dest (keep it: it updates, shares and leaves later)"

rm -rf "$tmp"; trap - EXIT INT TERM

# The tool asks questions (your name in the pen; your password once, for the
# browser proxy setting), so it gets the keyboard, not this download.
if have_tty; then
  exec "$dest" "$@" "$link" </dev/tty
fi
exec "$dest" "$@" "$link"
