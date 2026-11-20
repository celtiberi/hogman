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
  local ver
  ver="$(curl -fsSL "$base/dl/latest")" || die "could not reach $base"
  [[ "$ver" =~ ^[0-9A-Za-z._-]+$ ]] || die "unexpected version from $base: $ver"
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp:-}"' EXIT   # tmp is global: the trap runs after main returns
  local tarball="hogman-$ver.tar.gz"
  curl -fsSL -o "$tmp/$tarball" "$base/dl/$tarball"
  curl -fsSL "$base/dl/SHA256SUMS" | grep "  $tarball\$" > "$tmp/SHA256SUMS" || die "no checksum for $tarball"
  (cd "$tmp" && sha256sum -c --quiet SHA256SUMS) || die "checksum mismatch for $tarball: not installing"
  mkdir "$tmp/x" && tar -xzf "$tmp/$tarball" -C "$tmp/x"
  echo "    version $ver, checksum OK"

  # The compiled join tool and registrar, so this server doesn't build them.
  local bins="hogman-bin-$ver.tar.gz"
  if curl -fsSL -o "$tmp/$bins" "$base/dl/$bins" 2>/dev/null; then
    curl -fsSL "$base/dl/SHA256SUMS" | grep "  $bins\$" > "$tmp/BINSUMS" || die "no checksum for $bins"
    (cd "$tmp" && sha256sum -c --quiet BINSUMS) || die "checksum mismatch for $bins: not installing"
    tar -xzf "$tmp/$bins" -C "$tmp/x/core"
    echo "    compiled parts, checksum OK"
  else
    echo "    no compiled parts for this version; they will be built on this server (slow on small servers)"
  fi

  local first=true
  [ -f "$home/host.env" ] && first=false

  if [ "$first" = true ]; then
    say "Setting up the server (this takes a few minutes)"
    bash "$tmp/x/deploy/bootstrap.sh"
  fi

  say "Installing Hogman $ver into $home"
  mkdir -p "$home/src"
  rsync -a --delete --exclude data --exclude .env "$tmp/x/core/" "$home/src/"
  [ -d "$tmp/x/core/prebuilt" ] || rm -rf "$home/src/prebuilt"
  install -m 0755 "$tmp/x/deploy/hogman-host" /usr/local/bin/hogman-host
  install -m 0644 "$tmp/x/deploy/bootstrap.sh" "$home/bootstrap.sh"
  if [ -d "$tmp/x/deploy/signup" ]; then
    rsync -a --delete "$tmp/x/deploy/signup/" "$home/signup-src/"
  fi
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
  3. Get your own laptop in: open the link this prints, on the laptop:
       hogman-host pen mypen device key you personal
  4. Move the pen's root key off the server (hogman-host add says where it is).
  5. Invite others:  hogman-host pen mypen invite create

The whole guide, with backups and alerts:
  https://github.com/celtiberi/hogman/blob/main/deploy/README.md
EOF
  else
    cat <<EOF

✓ Hogman $ver is installed. Your pens are untouched until you upgrade them:
EOF
    hogman-host list | sed 's/^/    /'
    echo
    if grep -q '^SIGNUP_HOST=.' "$home/host.env" 2>/dev/null; then
      say "Updating the sign-up page"
      hogman-host signup-setup
    fi
    echo "  hogman-host upgrade <pen>     (restarts that pen on the new version)"
  fi
}

say() { echo; echo "==> $*"; }
die() { echo "hogman install: $*" >&2; exit 1; }

# Everything runs from here, so a half-downloaded script does nothing.
main "$@"
