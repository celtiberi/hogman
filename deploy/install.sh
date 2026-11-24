#!/usr/bin/env bash
# Install or update Hogman on a server.
#
#   curl -fsSL https://github.com/celtiberi/hogman/releases/latest/download/install.sh | sudo bash
#
# First run, on a fresh Ubuntu 24.04 server: sets the server up (security
# updates, Docker, Tailscale, firewall, swap), installs Hogman into
# /opt/hogman and starts the shared front door. Then you add pens.
#
# Later runs: downloads the newest Hogman and installs it, without touching
# your pens or your server setup. Then: hogman-host upgrade <pen>.
#
# Everything this script does is in the open: read it first if you like.
#   curl -fsSL https://github.com/celtiberi/hogman/releases/latest/download/install.sh | less
set -euo pipefail

main() {
  local base="${HOGMAN_BASE:-https://github.com/celtiberi/hogman/releases}"
  base="${base%/}"
  local home="${HOGMAN_HOME:-/opt/hogman}"

  [ "$(id -u)" = 0 ] || die "run as root:  curl -fsSL $base/latest/download/install.sh | sudo bash"
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    [ "${ID:-}" = ubuntu ] || die "Hogman's installer supports Ubuntu (24.04). This is ${PRETTY_NAME:-unknown}."
  fi
  command -v curl >/dev/null || die "curl is needed"

  local curl_opts=(-fsSL)
  if [[ "$base" == https://* ]]; then
    curl_opts+=(--proto '=https' --proto-redir '=https')
  fi

  # Resolve the release version once, then fetch every file from that pinned tag
  # so a release published mid-install can never mix tarballs and checksums.
  local raw_ver ver tag dl
  if [ -n "${HOGMAN_VERSION:-}" ]; then
    raw_ver="$HOGMAN_VERSION"
    say "Installing pinned Hogman release $raw_ver"
  else
    say "Finding the newest Hogman"
    raw_ver="$(curl "${curl_opts[@]}" "$base/latest/download/latest" | tr -d '\r\n')" || die "could not reach $base"
  fi
  ver="${raw_ver#v}"
  [[ "$ver" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] && [[ "$ver" != *..* ]] || die "unexpected version from $base: $raw_ver"
  tag="v$ver"
  dl="$base/download/$tag"

  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp:-}"' EXIT INT TERM   # tmp is global: the trap runs after main returns

  curl "${curl_opts[@]}" -o "$tmp/ALLSUMS" "$dl/SHA256SUMS" || die "could not download checksums for $tag from $dl"

  local tarball="hogman-$ver.tar.gz"
  curl "${curl_opts[@]}" -o "$tmp/$tarball" "$dl/$tarball"
  awk -v f="$tarball" 'NF == 2 && $2 == f { print }' "$tmp/ALLSUMS" > "$tmp/SHA256SUMS"
  [ "$(wc -l < "$tmp/SHA256SUMS")" -eq 1 ] || die "expected exactly one checksum for $tarball"
  (cd "$tmp" && sha256sum -c --quiet SHA256SUMS) || die "checksum mismatch for $tarball: not installing"
  mkdir "$tmp/x" && tar --no-same-owner -xzf "$tmp/$tarball" -C "$tmp/x"
  echo "    version $ver ($tag), checksum OK"

  # The compiled join tool and registrar, so this server doesn't build them.
  # If SHA256SUMS lists the prebuilt archive, downloading and verifying it is
  # mandatory (fail closed rather than silently deleting prebuilt/ on a transient error).
  local bins="hogman-bin-$ver.tar.gz"
  awk -v f="$bins" 'NF == 2 && $2 == f { print }' "$tmp/ALLSUMS" > "$tmp/BINSUMS"
  if [ -s "$tmp/BINSUMS" ]; then
    [ "$(wc -l < "$tmp/BINSUMS")" -eq 1 ] || die "expected exactly one checksum for $bins"
    curl "${curl_opts[@]}" -o "$tmp/$bins" "$dl/$bins" || die "could not download $bins from $dl"
    (cd "$tmp" && sha256sum -c --quiet BINSUMS) || die "checksum mismatch for $bins: not installing"
    tar --no-same-owner -xzf "$tmp/$bins" -C "$tmp/x/core"
    echo "    compiled parts, checksum OK"
  else
    echo "    no compiled parts listed for this version; they will be built on this server (slow on small servers)"
  fi

  # Everything installed from a release belongs to root, whatever uid the
  # archive recorded. rsync -a below then also corrects files that an earlier
  # install left owned by another uid.
  chown -R 0:0 "$tmp/x"

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
    say "Pre-pulling container images"
    hogman-host pull-images
    cat <<EOF

✓ Hogman $ver is installed and the front door is up.

Next:
  1. Manage this server over your own Tailscale network, and close SSH to the internet:
       tailscale up --hostname=\$(hostname)        (open the link it prints)
       bash $home/bootstrap.sh --lock-ssh
  2. Set up the challenge DNS server and wildcard gate certificate, then raise a pen:
       hogman-host challenge-dns-setup <public-ip>
       hogman-host gate-cert-setup <gate-domain>
       hogman-host pens-zone <pens-zone>
       hogman-host add mypen
       hogman-host pen mypen member add you --role owner
  3. Get your own laptop in: open the link this prints, on the laptop:
       hogman-host pen mypen device key you personal
  4. Invite others:  hogman-host pen mypen invite create

The whole guide, with backups and alerts:
  https://github.com/celtiberi/hogman/blob/main/deploy/README.md
EOF
  else
    cat <<EOF

✓ Hogman $ver is installed. Your pens are untouched until you upgrade them:
EOF
    hogman-host list | sed 's/^/    /'
    say "Updating the host's own services (challenge DNS, gate certificate)"
    hogman-host refresh-services
    say "Pre-pulling container images for offline pen sign-ups"
    hogman-host pull-images
    echo
    if ( . "$home/host.env" 2>/dev/null && [ -n "${SIGNUP_HOST:-}" ] ); then
      if ( . "$home/host.env" 2>/dev/null && [ -n "${PENS_ZONE:-}" ] && [ -n "${GATE_DOMAIN:-}" ] ); then
        say "Updating the sign-up page"
        hogman-host signup-setup
      else
        echo "  (sign-up page not refreshed yet: run hogman-host gate-cert-setup, pens-zone, then signup-setup)"
      fi
    fi
    echo "  hogman-host upgrade <pen>     (restarts that pen on the new version)"
  fi
}

say() { echo; echo "==> $*"; }
die() { echo "hogman install: $*" >&2; exit 1; }

# Everything runs from here, so a half-downloaded script does nothing.
main "$@"
