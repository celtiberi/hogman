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
# Your invite link is only sent to the pen host it belongs to — never to any
# third party. Passing it on the command line (below) avoids a second prompt;
# treat the command like a password and don't share it.
#
# Usage: curl -fsSL --proto '=https' --proto-redir '=https' https://<address>/start | sh -s -- '<invite link>' [hogman options]
set -eu

say() { printf '%s\n' "$*"; }
die() { printf '\n✗ %s\n' "$*" >&2; exit 1; }
# A terminal we can really open (/dev/tty exists even where opening it fails).
have_tty() { (exec </dev/tty) 2>/dev/null; }

case "$(uname -s)" in
  Darwin) os="Darwin"; config_base="$HOME/Library/Application Support/hogman" ;;
  Linux)  os="Linux";  config_base="${XDG_CONFIG_HOME:-$HOME/.config}/hogman" ;;
  *) die "this computer isn't supported yet ($(uname -s)): use a Mac or Linux computer" ;;
esac
arch="$(uname -m)"
file="hogman-$os-$arch"

if command -v sha256sum >/dev/null 2>&1; then sum() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
else die "no sha256sum or shasum on this computer to check the download with"; fi

_cleanup_dl() {
  [ -n "${_stage:-}" ] && rm -f "$_stage"
  [ -n "${_tmp:-}" ] && rm -rf "$_tmp"
  _stage=""
  _tmp=""
  trap - EXIT INT TERM
}

download_and_install() {
  _src_label="$1"
  _sums_url="$2"
  _bin_url="$3"
  _tmp=""
  _stage=""
  _tmp="$(mktemp -d "${TMPDIR:-/tmp}/hogman.XXXXXX")" || return 4
  trap '_cleanup_dl' EXIT
  trap 'trap - EXIT; _cleanup_dl; exit 130' INT
  trap 'trap - EXIT; _cleanup_dl; exit 143' TERM
  say ""
  say "• Downloading hogman for $os $arch from $_src_label"
  curl -fsSL --proto =https --proto-redir =https "$_sums_url" -o "$_tmp/SHA256SUMS" || {
    _cleanup_dl; return 1
  }
  _want="$(awk -v f="$file" '{ sub(/\r$/, "") } $2 == f || $2 == "*" f { print $1; exit }' "$_tmp/SHA256SUMS")"
  [ -n "$_want" ] || { _cleanup_dl; return 2; }
  curl -fsSL --proto =https --proto-redir =https "$_bin_url" -o "$_tmp/hogman" || {
    _cleanup_dl; return 3
  }
  _got="$(sum "$_tmp/hogman")"
  if [ "$_got" != "$_want" ]; then
    _cleanup_dl
    die "the download doesn't match its published SHA-256 (want $_want, got $_got); not running it"
  fi
  say "  checked: SHA-256 matches"
  # Stage inside $HOME via mktemp (O_CREAT|O_EXCL) before rename so replacing a
  # running ~/hogman is an atomic same-filesystem rename (avoiding ETXTBSY across
  # tmpfs -> $HOME and avoiding predictable temp filenames).
  _stage="$(mktemp "$HOME/.hogman.tmp.XXXXXX")" || { _cleanup_dl; return 4; }
  if ! { cp "$_tmp/hogman" "$_stage" && chmod 0755 "$_stage" && mv -f "$_stage" "$HOME/hogman"; }; then
    _cleanup_dl
    return 4
  fi
  _stage=""
  say "  saved as $HOME/hogman (keep it: it updates, shares and leaves later)"
  _cleanup_dl
  return 0
}

# Check if this computer already belongs to any Hogman pens.
has_pens=0
host_in_pens=0
first_pen_host=""
for cfg in "$config_base"/*/config.json; do
  [ -f "$cfg" ] || continue
  has_pens=1
  ls_host="$(sed -n 's/.*"login_server"[[:space:]]*:[[:space:]]*"https:\/\/\([^/"[:space:]]*\)".*/\1/p' "$cfg" | head -n 1)"
  case "$ls_host" in
    ""|*[!a-zA-Z0-9.:-]*) ls_host="" ;;
  esac
  if [ -n "$ls_host" ]; then
    [ -z "$first_pen_host" ] && first_pen_host="$ls_host"
    if [ -n "${HOGMAN_EXPECTED_HOST:-}" ] && [ "$ls_host" = "$HOGMAN_EXPECTED_HOST" ]; then
      host_in_pens=1
    fi
  fi
done

link="${1:-}"
[ $# -gt 0 ] && shift   # anything after the link goes to hogman (e.g. --handle NAME)

# If run with no link on a machine that already has pens (and not explicitly
# pinned to a brand-new pen host via HOGMAN_EXPECTED_HOST), install ~/hogman
# and run `hogman update` instead of asking for an invite link (I-9).
if [ -z "$link" ] && [ "$has_pens" = 1 ] && { [ -z "${HOGMAN_EXPECTED_HOST:-}" ] || [ "$host_in_pens" = 1 ]; }; then
  say "• Existing Hogman pen(s) found on this computer — installing ~/hogman and running update"
  installed=0
  if [ -n "${HOGMAN_EXPECTED_HOST:-}" ]; then
    case "$HOGMAN_EXPECTED_HOST" in
      ""|*[!a-zA-Z0-9.:-]*) die "unexpected host: $HOGMAN_EXPECTED_HOST" ;;
    esac
    download_and_install "$HOGMAN_EXPECTED_HOST" \
      "https://$HOGMAN_EXPECTED_HOST/join/dl/SHA256SUMS" \
      "https://$HOGMAN_EXPECTED_HOST/join/dl/$file" && installed=1 || true
  else
    if [ -n "$first_pen_host" ]; then
      download_and_install "$first_pen_host" \
        "https://$first_pen_host/join/dl/SHA256SUMS" \
        "https://$first_pen_host/join/dl/$file" && installed=1 || true
    fi
    if [ "$installed" != 1 ]; then
      gh_base="https://github.com/celtiberi/hogman/releases/latest/download"
      download_and_install "GitHub Releases" \
        "$gh_base/hogman-SHA256SUMS" \
        "$gh_base/$file" && installed=1 || true
    fi
  fi
  [ "$installed" = 1 ] || die "could not download $file; try: curl -fsSL --proto '=https' --proto-redir '=https' -o ~/hogman https://hogman.network/dl/$file && chmod +x ~/hogman && ~/hogman update"
  [ -e "$HOME/hogman-join" ] && say "  note: once updated, you can delete $HOME/hogman-join"
  say "  (to join another pen later, run: ~/hogman '<invite link>')"
  if have_tty; then
    exec "$HOME/hogman" update </dev/tty
  fi
  exec "$HOME/hogman" update
fi

if [ -z "$link" ]; then
  have_tty || die "no terminal to ask for your invite link on; pass it: curl -fsSL <address>/start | sh -s -- '<link>'"
  printf 'Paste your invite link (the full link you were sent, including everything after the #): ' >/dev/tty
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
# Anchor the path strictly to non-empty /join#t=... or /join#k=... on that exact host.
case "$link" in
  "https://$host/join#t=&"*|"https://$host/join#k=&"*)
    die "that doesn't look like a Hogman invite link (empty token)" ;;
  "https://$host/join#t="?*|"https://$host/join#k="?*) ;;
  *) die "that doesn't look like a Hogman invite link (expected https://<host>/join#t=... or #k=...)" ;;
esac
if [ -n "${HOGMAN_EXPECTED_HOST:-}" ] && [ "$host" != "$HOGMAN_EXPECTED_HOST" ]; then
  die "refusing link for $host (expected $HOGMAN_EXPECTED_HOST)"
fi

rc=0
download_and_install "$host" "https://$host/join/dl/SHA256SUMS" "https://$host/join/dl/$file" || rc=$?
case "$rc" in
  0) ;;
  1) die "couldn't reach https://$host" ;;
  2) die "there's no hogman for $os $arch yet" ;;
  4) die "could not write $HOME/hogman (check permissions on $HOME)" ;;
  *) die "the download failed; try again" ;;
esac

# Give hogman the controlling terminal for interactive handle prompts (never asks for a password).
if have_tty; then
  exec "$HOME/hogman" "$@" "$link" </dev/tty
fi
exec "$HOME/hogman" "$@" "$link"
