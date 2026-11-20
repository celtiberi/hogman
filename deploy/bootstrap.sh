#!/usr/bin/env bash
# One-time setup of a fresh Ubuntu 24.04 server to host Hogman pens.
# Run as root:  bash bootstrap.sh
#
#   - security updates install themselves
#   - Docker (from Docker's own repository)
#   - Tailscale, so the server can be managed over your own tailnet
#   - firewall: only the pens' public ports are open to the internet;
#     SSH is closed to the internet once you run:  bash bootstrap.sh --lock-ssh
#   - 2 GB of swap, so a burst can't knock a pen over
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
. /etc/os-release
[ "${ID:-}" = ubuntu ] || { echo "this script is for Ubuntu" >&2; exit 1; }

say() { echo; echo "==> $*"; }

if [ "${1:-}" = --lock-ssh ]; then
  tailscale status >/dev/null 2>&1 || { echo "Tailscale is not up; refusing to close SSH" >&2; exit 1; }
  say "Closing SSH to the internet (it stays open over Tailscale)"
  ufw allow in on tailscale0 to any port 22 proto tcp >/dev/null
  ufw delete allow OpenSSH >/dev/null 2>&1 || true
  ufw delete allow 22/tcp >/dev/null 2>&1 || true
  ufw delete allow 22 >/dev/null 2>&1 || true
  if ufw status | grep -E '^(22(/tcp)?|OpenSSH)[[:space:]]+ALLOW[[:space:]]+Anywhere' >/dev/null; then
    echo "WARNING: an unrestricted public SSH rule is still present in UFW; remove it manually" >&2
    ufw status numbered >&2
    exit 1
  fi
  auth_keys="/root/.ssh/authorized_keys"
  if [ ! -s "$auth_keys" ] && [ -n "${SUDO_USER:-}" ]; then
    sudo_home="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)"
    [ -n "$sudo_home" ] && auth_keys="$sudo_home/.ssh/authorized_keys"
  fi
  if [ -s "$auth_keys" ] && grep -Eq '^(ssh-|ecdsa-|sk-)' "$auth_keys"; then
    install -d -m 0755 /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/99-hogman-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
    chmod 644 /etc/ssh/sshd_config.d/99-hogman-hardening.conf
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  else
    echo "Note: no SSH public key found in authorized_keys; leaving SSH password auth unchanged" >&2
  fi
  ufw status verbose
  exit 0
fi

export DEBIAN_FRONTEND=noninteractive

say "Updating the system"
apt-get update -q
apt-get -yq upgrade
apt-get -yq install ca-certificates curl gnupg rsync jq sqlite3 ufw unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

say "Installing Docker"
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get -yq install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker >/dev/null

say "Installing Tailscale"
if ! command -v tailscale >/dev/null; then
  curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.noarmor.gpg" -o /usr/share/keyrings/tailscale-archive-keyring.gpg
  curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.tailscale-keyring.list" -o /etc/apt/sources.list.d/tailscale.list
  apt-get update -q
  apt-get -yq install tailscale
fi

say "Adding swap"
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q /swapfile /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
fi

# Docker publishes ports via iptables DOCKER chains, bypassing UFW; keep
# internal services unpublished or bound to 127.0.0.1.
say "Firewall"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow OpenSSH >/dev/null                    # until --lock-ssh
ufw allow 80/tcp >/dev/null                     # front door (certificates, redirect)
ufw allow 443/tcp >/dev/null                    # front door
ufw allow 3478:3577/udp >/dev/null              # each pen's relay (STUN)
ufw allow in on tailscale0 >/dev/null
ufw --force enable >/dev/null
ufw status verbose

mkdir -p /opt/hogman

say "Done. Next:"
echo "  1. tailscale up --hostname=$(hostname)   (open the link it prints, to add this server to your tailnet)"
echo "  2. bash bootstrap.sh --lock-ssh           (closes SSH to the internet; it stays open over Tailscale)"
