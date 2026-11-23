#!/usr/bin/env bash
# Bootstrap a disposable Ubuntu 24.04 Linux droplet for the Hogman Bot Arena.
#
# Safety boundaries:
# - Must NOT run on a production host or any machine joined to a Tailscale tailnet.
# - Locks inbound SSH strictly to the operator's IP/CIDR via ufw AND installs a
#   persistent DOCKER-USER iptables/ip6tables firewall so Docker-published ports
#   (80, 443, STUN UDP) are never exposed to the public internet.
# - Installs native Linux Docker Engine + arena prerequisites; stores zero prod secrets.
#
# usage:
#   sudo test-arena/setup-droplet.sh --allow-ssh-from <YOUR_IP/32> [--repo-dir /opt/hogman-arena]
set -euo pipefail

ALLOW_SSH_FROM=""
REPO_DIR="/opt/hogman-arena"

usage() {
  cat <<'EOF' >&2
usage: sudo test-arena/setup-droplet.sh --allow-ssh-from <CIDR> [--repo-dir DIR]

options:
  --allow-ssh-from CIDR   required; restrict inbound SSH and Docker-published ports to this IP/CIDR (e.g. 203.0.113.10/32)
  --repo-dir DIR          target directory for the arena checkout (default: /opt/hogman-arena)
EOF
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --allow-ssh-from)
      [ $# -ge 2 ] || usage
      ALLOW_SSH_FROM="$2"
      shift 2
      ;;
    --repo-dir)
      [ $# -ge 2 ] || usage
      REPO_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "ERROR: run as root (sudo)" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "ERROR: Linux only" >&2; exit 1; }
[ -n "$ALLOW_SSH_FROM" ] || { echo "ERROR: --allow-ssh-from <IP/32> is required" >&2; usage; }

# Refuse to run on any host connected to Tailscale or hosting Hogman.
if command -v tailscale >/dev/null 2>&1 || [ -S /var/run/tailscale/tailscaled.sock ]; then
  echo "ERROR: Tailscale detected on this machine. Run the Bot Arena only on a separate disposable droplet." >&2
  exit 1
fi
if [ -d /opt/hogman ]; then
  echo "ERROR: /opt/hogman detected. Refusing to run on a Hogman host." >&2
  exit 1
fi

# Validate CIDR format before touching ufw or iptables.
IS_IPV6=false
if printf '%s' "$ALLOW_SSH_FROM" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$'; then
  IS_IPV6=false
elif printf '%s' "$ALLOW_SSH_FROM" | grep -Eq '^[0-9a-fA-F:]+/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$'; then
  IS_IPV6=true
else
  echo "ERROR: --allow-ssh-from must be a valid IPv4 or IPv6 CIDR (for example 203.0.113.10/32)" >&2
  exit 1
fi

echo "[setup] Installing packages (Docker Engine, iptables, jq, openssl, rsync, python3, ufw)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  ca-certificates \
  curl \
  docker.io \
  docker-compose-v2 \
  git \
  iptables \
  jq \
  openssl \
  python3 \
  rsync \
  ufw

systemctl enable --now docker

# Add 2 GB swapfile if total RAM is under 4 GB so 2 pens + Pebble + 5 sandboxes stay comfortable.
mem_mb="$(awk '/MemTotal:/ {print int($2/1024)}' /proc/meminfo)"
if [ "$mem_mb" -lt 3800 ] && [ ! -f /swapfile ]; then
  echo "[setup] RAM is ${mem_mb}MB (<4GB); creating 2G /swapfile"
  fallocate -l 2G /swapfile
  chmod 0600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo "[setup] Configuring ufw (inbound SSH from ${ALLOW_SSH_FROM} only; default deny incoming)"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow from "$ALLOW_SSH_FROM" to any port 22 proto tcp >/dev/null
ufw --force enable >/dev/null

# Docker bypasses ufw for published container ports (80/443/STUN). Install a
# persistent DOCKER-USER firewall service so external traffic to any published
# port is dropped unless it originates from ALLOW_SSH_FROM or a local Docker bridge.
echo "[setup] Installing persistent DOCKER-USER firewall (blocks external access to Docker-published ports)"
cat > /usr/local/sbin/hogman-arena-docker-firewall <<EOF
#!/usr/bin/env bash
set -euo pipefail

ALLOW_CIDR='${ALLOW_SSH_FROM}'
IS_IPV6='${IS_IPV6}'

apply_chain() {
  local ipt="\$1"
  local allow_v="\$2"
  "\$ipt" -N DOCKER-USER 2>/dev/null || true
  "\$ipt" -F DOCKER-USER
  # Allow established replies and container-initiated / inter-bridge traffic.
  "\$ipt" -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  "\$ipt" -A DOCKER-USER -i lo -j RETURN
  "\$ipt" -A DOCKER-USER -i docker0 -j RETURN
  "\$ipt" -A DOCKER-USER -i br-+ -j RETURN
  if [ "\$allow_v" = true ]; then
    "\$ipt" -A DOCKER-USER -s "\$ALLOW_CIDR" -j RETURN
  fi
  "\$ipt" -A DOCKER-USER -j DROP
}

apply_chain iptables "\$( [ "\$IS_IPV6" = false ] && echo true || echo false )"
if command -v ip6tables >/dev/null 2>&1 && ip6tables -L FORWARD >/dev/null 2>&1; then
  apply_chain ip6tables "\$IS_IPV6"
fi
EOF
chmod 0750 /usr/local/sbin/hogman-arena-docker-firewall

cat > /etc/systemd/system/hogman-arena-firewall.service <<'UNIT'
[Unit]
Description=Hogman Bot Arena DOCKER-USER firewall
After=docker.service ufw.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/hogman-arena-docker-firewall

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now hogman-arena-firewall.service

mkdir -p "$REPO_DIR"
chmod 0750 "$REPO_DIR"

cat <<EOF

[setup] Disposable Bot Arena droplet is ready.

Firewall note:
  ufw + DOCKER-USER drop all external inbound traffic except from ${ALLOW_SSH_FROM}.
  As defense-in-depth, also attach a DigitalOcean Cloud Firewall allowing only
  inbound TCP 22 from ${ALLOW_SSH_FROM}.

Next steps:
  1. Clone the repository into ${REPO_DIR} (if not already present):
       git clone https://github.com/celtiberi/hogman.git ${REPO_DIR}
  2. Set your LLM API key on the host only (never inside containers):
       export GEMINI_API_KEY='...'
     (Or for an OpenAI-compatible endpoint such as DeepSeek:
       export ARENA_LLM_PROVIDER=openai-compat
       export ARENA_LLM_BASE_URL='https://api.deepseek.com/v1'
       export ARENA_LLM_MODEL='deepseek-chat'
       export DEEPSEEK_API_KEY='...')
  3. Boot the arena stack:
       cd ${REPO_DIR} && sudo test-arena/arena.sh up
  4. Run the v1 scenario and deterministic Judge:
       sudo -E python3 test-arena/run.py
  5. Wipe and rebuild between runs:
       sudo test-arena/arena.sh reset
EOF
