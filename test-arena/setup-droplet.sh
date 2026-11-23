#!/usr/bin/env bash
# Bootstrap a disposable Ubuntu 24.04 Linux droplet for the Hogman Bot Arena.
#
# Safety boundaries:
# - Must NOT run on a production host or any machine joined to a Tailscale tailnet.
# - Locks inbound SSH strictly to the operator's IP/CIDR via ufw.
# - Installs a DOCKER-USER firewall via a docker.service ExecStartPre drop-in
#   (and systemd unit) so Docker-published ports (80/443/STUN) are NEVER exposed
#   externally, even during a reboot before containers restart.
# - Configures Docker json-file log rotation so adversarial traffic cannot fill disk.
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
  --allow-ssh-from CIDR   required; restrict inbound SSH (port 22) to this IP/CIDR (e.g. 203.0.113.10/32)
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
if command -v tailscale >/dev/null 2>&1 || [ -x /usr/sbin/tailscaled ] || [ -S /var/run/tailscale/tailscaled.sock ]; then
  echo "ERROR: Tailscale detected on this machine. Run the Bot Arena only on a separate disposable droplet." >&2
  exit 1
fi
if [ -d /opt/hogman ] || [ -f /etc/systemd/system/hogman-challenge-dns.service ] || [ -f /etc/systemd/system/hogman-gate-cert.service ]; then
  echo "ERROR: Existing Hogman host files/services detected. Refusing to run on a Hogman host." >&2
  exit 1
fi

echo "[setup] Installing packages (Docker Engine, iptables, jq, openssl, rsync, python3, ufw)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  ca-certificates \
  curl \
  docker.io \
  docker-buildx \
  docker-compose-v2 \
  git \
  iptables \
  jq \
  openssl \
  python3 \
  rsync \
  ufw

# Validate CIDR strictly with Python ipaddress BEFORE touching ufw or iptables.
python3 - "$ALLOW_SSH_FROM" <<'PY' || exit 1
import ipaddress, sys
raw = sys.argv[1]
try:
    net = ipaddress.ip_network(raw, strict=False)
except ValueError as exc:
    print(f"ERROR: invalid --allow-ssh-from CIDR {raw!r}: {exc}", file=sys.stderr)
    sys.exit(1)
if net.prefixlen == 0:
    print(f"ERROR: refusing wildcard CIDR {raw!r}; specify your operator IP (e.g. /32 or /128)", file=sys.stderr)
    sys.exit(1)
PY

# Configure Docker json-file log rotation before starting Docker so noisy bots
# cannot fill the droplet's root filesystem.
mkdir -p /etc/docker
if [ ! -f /etc/docker/daemon.json ]; then
  cat > /etc/docker/daemon.json <<'JSON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
JSON
fi

# Install the DOCKER-USER firewall script BEFORE starting Docker and wire it
# into docker.service via ExecStartPre + ExecStartPost so external traffic to
# Docker-published ports (80/443/STUN) is dropped even across reboots.
# Bots talk exclusively on local bridges; operators connect over SSH (port 22).
echo "[setup] Installing persistent DOCKER-USER firewall (drops all external access to Docker-published ports)"
cat > /usr/local/sbin/hogman-arena-docker-firewall <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

apply_chain() {
  local ipt="$1"
  "$ipt" -N DOCKER-USER 2>/dev/null || true
  "$ipt" -C FORWARD -j DOCKER-USER 2>/dev/null || "$ipt" -I FORWARD 1 -j DOCKER-USER
  "$ipt" -F DOCKER-USER
  # Allow established replies and local Docker bridge traffic only.
  "$ipt" -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  "$ipt" -A DOCKER-USER -i lo -j RETURN
  "$ipt" -A DOCKER-USER -i docker0 -j RETURN
  "$ipt" -A DOCKER-USER -i br-+ -j RETURN
  "$ipt" -A DOCKER-USER -j DROP
}

apply_chain iptables
if command -v ip6tables >/dev/null 2>&1 && ip6tables -L FORWARD >/dev/null 2>&1; then
  apply_chain ip6tables
fi
EOF
chmod 0750 /usr/local/sbin/hogman-arena-docker-firewall

install -d -m 0755 /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/arena-firewall.conf <<'DROPIN'
[Service]
ExecStartPre=/usr/local/sbin/hogman-arena-docker-firewall
ExecStartPost=/usr/local/sbin/hogman-arena-docker-firewall
DROPIN

systemctl daemon-reload
/usr/local/sbin/hogman-arena-docker-firewall
systemctl enable --now docker
systemctl restart docker

# Add 2 GB swapfile if total RAM is under 4 GB so 2 pens + Pebble + sandboxes stay comfortable.
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

mkdir -p "$REPO_DIR"
chmod 0750 "$REPO_DIR"

cat <<EOF

[setup] Disposable Bot Arena droplet is ready.

Firewall note:
  - ufw allows inbound SSH (TCP 22) ONLY from ${ALLOW_SSH_FROM}.
  - DOCKER-USER drops ALL external inbound traffic to Docker-published ports
    (IPv4 and IPv6) before and after docker.service starts.
  - As defense-in-depth, also attach a DigitalOcean Cloud Firewall allowing only
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
