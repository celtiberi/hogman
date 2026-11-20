#!/usr/bin/env bash
# Install or update Hogman on a server.
#
#   curl -fsSL https://hogman.network/install.sh | sudo bash
#
# First run, on a fresh Ubuntu 24.04 server: sets the server up (security
# updates, Docker, Tailscale, firewall, swap), installs Hogman into
# /opt/hogman and starts the shared front door. Then you add pens.
#
# Later runs: downloads the newest Hogman and installs it, without touching
# your pens or your server setup. Then: hogman-host upgrade <pen>.
#
# Everything this script does is in the open: read it first if you like.
#   curl -fsSL https://hogman.network/install.sh | less
set -euo pipefail

main() {
  local base="${HOGMAN_BASE:-https://hogman.network}"
  local home="${HOGMAN_HOME:-/opt/hogman}"

  [ "$(id -u)" = 0 ] || die "run as root:  curl -fsSL $base/install.sh | sudo bash"
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    [ "${ID:-}" = ubuntu ] || die "Hogman's installer supports Ubuntu (24.04). This is ${PRETTY_NAME:-unknown}."
  fi
  command -v curl >/dev/null || die "curl is needed"

  say "Finding the newest Hogman"
  local ver tmp
  ver="$(curl -fsSL "$base/dl/latest")" || die "could not reach $base"
  [[ "$ver" =~ ^[0-9A-Za-z._-]+$ ]] || die "unexpected version from $base: $ver"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  local tarball="hogman-$ver.tar.gz"
  curl -fsSL -o "$tmp/$tarball" "$base/dl/$tarball"
  curl -fsSL "$base/dl/SHA256SUMS" | grep "  $tarball\$" > "$tmp/SHA256SUMS" || die "no checksum for $tarball"
  (cd "$tmp" && sha256sum -c --quiet SHA256SUMS) || die "checksum mismatch for $tarball: not installing"
  mkdir "$tmp/x" && tar -xzf "$tmp/$tarball" -C "$tmp/x"
  echo "    version $ver, checksum OK"

  local first=true
  [ -f "$home/host.env" ] && first=false

  if [ "$first" = true ]; then
    say "Setting up the server (this takes a few minutes)"
    bash "$tmp/x/deploy/bootstrap.sh"
  fi

  say "Installing Hogman $ver into $home"
  mkdir -p "$home/src"
  rsync -a --delete --exclude data --exclude .env "$tmp/x/core/" "$home/src/"
  install -m 0755 "$tmp/x/deploy/hogman-host" /usr/local/bin/hogman-host
  install -m 0644 "$tmp/x/deploy/bootstrap.sh" "$home/bootstrap.sh"
  echo "$ver" > "$home/VERSION"

  if [ "$first" = true ]; then
    hogman-host init
    cat <<EOF

✓ Hogman $ver is installed and the front door is up.

Next:
  1. Manage this server over your own Tailscale network, and close SSH to the internet:
       tailscale up --hostname=\$(hostname)        (open the link it prints)
       bash $home/bootstrap.sh --lock-ssh
  2. Point a hostname at this server (for example hs.example.com), then raise a pen:
       hogman-host add mypen hs.example.com
       hogman-host pen mypen member add you --role owner
       hogman-host pen mypen invite create
  3. Move the pen's root key off the server (hogman-host add says where it is).
EOF
  else
    cat <<EOF

✓ Hogman $ver is installed. Your pens are untouched until you upgrade them:
EOF
    hogman-host list | sed 's/^/    /'
    echo
    echo "  hogman-host upgrade <pen>     (restarts that pen on the new version)"
  fi
}

say() { echo; echo "==> $*"; }
die() { echo "hogman install: $*" >&2; exit 1; }

# Everything runs from here, so a half-downloaded script does nothing.
main "$@"
