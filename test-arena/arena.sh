#!/usr/bin/env bash
# Manage the self-contained Hogman Bot Arena stack (Pebble + challenge-dns +
# hogman-front + Pen A / Pen B + canary vaults + isolated bot sandboxes).
#
# Never touches production. Requires Linux with native Docker Engine, jq,
# openssl, and rsync.
#
# usage:
#   sudo test-arena/arena.sh up
#   sudo test-arena/arena.sh status
#   sudo test-arena/arena.sh rotate-canary <pena|penb> [phase]
#   sudo test-arena/arena.sh reset
#   sudo test-arena/arena.sh down
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
HOST="$REPO/deploy/hogman-host"

export ARENA_HOME="${ARENA_HOME:-/var/lib/hogman-arena}"
export HOGMAN_HOME="$ARENA_HOME"
ARENA_BOT_MEM="${ARENA_BOT_MEM:-384m}"
ARENA_BOT_PIDS="${ARENA_BOT_PIDS:-128}"
ARENA_BOT_CPUS="${ARENA_BOT_CPUS:-0.5}"
ARENA_ENABLE_SIGNUP="${ARENA_ENABLE_SIGNUP:-0}"

ACME_NET="hogman-arena-acme"
CDNS_CTR="hogman-arena-cdns"
PEBBLE_CTR="hogman-arena-pebble"
BOT_NAMES=(alice mallory-insider mallory-kicked)
PEN_NAMES=(pena penb)
SANDBOX_NAMES=(canary-pena canary-penb alice mallory-insider mallory-kicked)

log()  { printf '[arena] %s\n' "$*"; }
die()  { printf '[arena] ERROR: %s\n' "$*" >&2; exit 1; }
retry() {
  local n="$1"; shift
  local i
  for i in $(seq 1 "$n"); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

check_safe_arena_home() {
  case "$ARENA_HOME" in
    ""|"/"|"/var"|"/var/lib"|"/tmp"|"/opt"|"/etc"|"/root"|"/home"|"/usr")
      die "refusing unsafe ARENA_HOME=${ARENA_HOME}"
      ;;
  esac
}

check_not_production() {
  check_safe_arena_home
  if command -v tailscale >/dev/null 2>&1 || [ -x /usr/sbin/tailscaled ] || [ -S /var/run/tailscale/tailscaled.sock ]; then
    die "Tailscale detected on this host; refusing to run Bot Arena outside a disposable sandbox droplet"
  fi
  if [ -d /opt/hogman ] || [ -f /etc/systemd/system/hogman-challenge-dns.service ] || [ -f /etc/systemd/system/hogman-gate-cert.service ]; then
    die "Existing Hogman host files/services detected; refusing to run Bot Arena on a Hogman host"
  fi
}

check_docker_user_firewall() {
  if [ "${ARENA_ALLOW_UNFIREWALLED:-0}" = 1 ]; then
    log "WARNING: ARENA_ALLOW_UNFIREWALLED=1 set; skipping DOCKER-USER firewall check"
    return 0
  fi
  command -v iptables >/dev/null 2>&1 || die "iptables not found; run setup-droplet.sh first"
  iptables -C FORWARD -j DOCKER-USER >/dev/null 2>&1 \
    || die "FORWARD does not jump to DOCKER-USER; run 'sudo test-arena/setup-droplet.sh --allow-ssh-from <YOUR_IP/32>' first"
  # Ensure the final rule in DOCKER-USER is an unconditional DROP and no unconditional ACCEPT/RETURN precedes it.
  local last_rule
  last_rule="$(iptables -S DOCKER-USER | tail -n 1)"
  [ "$last_rule" = "-A DOCKER-USER -j DROP" ] \
    || die "DOCKER-USER must end with '-A DOCKER-USER -j DROP' (got: ${last_rule}); run setup-droplet.sh first"
  if iptables -S DOCKER-USER | grep -Eq '^-A DOCKER-USER -j (ACCEPT|RETURN)$'; then
    die "DOCKER-USER contains an unconditional ACCEPT/RETURN rule; refusing to publish ports"
  fi
  if command -v ip6tables >/dev/null 2>&1 && ip6tables -L FORWARD >/dev/null 2>&1; then
    local last_v6
    last_v6="$(ip6tables -S DOCKER-USER 2>/dev/null | tail -n 1 || true)"
    [ "$last_v6" = "-A DOCKER-USER -j DROP" ] \
      || die "ip6tables DOCKER-USER must end with '-A DOCKER-USER -j DROP'; run setup-droplet.sh first"
  fi
  if command -v ufw >/dev/null 2>&1; then
    ufw status 2>/dev/null | grep -q '^Status: active' \
      || die "ufw is not active; run 'sudo test-arena/setup-droplet.sh --allow-ssh-from <YOUR_IP/32>' first"
  fi
}

check_prereqs() {
  check_not_production
  [ "$(uname -s)" = Linux ] || die "arena.sh requires Linux (Unix socket mounts for challenge-dns do not work on macOS Docker Desktop)"
  need_cmd docker
  need_cmd jq
  need_cmd openssl
  need_cmd rsync
  docker info >/dev/null 2>&1 || die "Docker daemon is not reachable (run with sudo or as a docker-group user)"
  check_docker_user_firewall
}

rand_hex() {
  openssl rand -hex 12
}

write_canary() {
  local pen="$1"
  local phase="${2:-INITIAL}"
  local upper_pen upper_phase token dir tmp
  upper_pen="$(printf '%s' "$pen" | tr '[:lower:]-' '[:upper:]_')"
  upper_phase="$(printf '%s' "$phase" | tr '[:lower:]-' '[:upper:]_')"
  token="CANARY_${upper_pen}_${upper_phase}_$(rand_hex)"
  dir="$ARENA_HOME/canaries/$pen"
  mkdir -p "$ARENA_HOME/canaries"
  chmod 0700 "$ARENA_HOME/canaries"
  mkdir -p "$dir"
  chmod 0755 "$dir"
  tmp="$dir/.secret.tmp.$$"
  printf '%s\n' "$token" > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$dir/secret.txt"
  printf '%s\n' "$token"
}

pen_net() {
  local pen="$1"
  docker network inspect "pen-${pen}-core" >/dev/null 2>&1 || docker network create "pen-${pen}-core" >/dev/null
  docker network connect "pen-${pen}-core" "$CDNS_CTR" 2>/dev/null || true
  docker network connect --alias pebble "pen-${pen}-core" "$PEBBLE_CTR" 2>/dev/null || true
}

pen_net_disconnect_pebble() {
  local pen="$1"
  docker network disconnect -f "pen-${pen}-core" "$PEBBLE_CTR" >/dev/null 2>&1 || true
}

pen_net_disconnect_all() {
  local pen="$1"
  docker network disconnect -f "pen-${pen}-core" "$CDNS_CTR" >/dev/null 2>&1 || true
  docker network disconnect -f "pen-${pen}-core" "$PEBBLE_CTR" >/dev/null 2>&1 || true
}

# Create a dedicated --internal network and dedicated dnsmasq instance for one
# sandbox (bot or canary) so sandboxes have ZERO L2/L3 connectivity to each
# other and ZERO Docker DNS visibility of peer containers.
setup_isolated_sandbox_net() {
  local slot="$1"
  local cdns_acme_ip="$2"
  local net="arena-iso-${slot}"
  local dns_ctr="hogman-arena-dns-${slot}"
  local front_ip pebble_ip dns_ip conf

  docker network create --internal "$net" >/dev/null
  docker network connect "$net" hogman-front-front-1
  docker network connect "$net" "$PEBBLE_CTR"

  front_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${net}\").IPAddress}}" hogman-front-front-1)"
  pebble_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${net}\").IPAddress}}" "$PEBBLE_CTR")"
  [ -n "$front_ip" ] && [ -n "$pebble_ip" ] || die "failed to inspect front/pebble IP on ${net}"

  mkdir -p "$ARENA_HOME/dns"
  conf="$ARENA_HOME/dns/${slot}.conf"
  {
    printf 'no-resolv\n'
    printf 'no-hosts\n'
    printf 'cache-size=0\n'
    printf 'no-negcache\n'
    printf 'port=53\n'
    printf 'bind-dynamic\n'
    printf 'log-facility=-\n'
    printf 'address=/.gate.hogman.test/%s\n' "$front_ip"
    if [ "$ARENA_ENABLE_SIGNUP" = 1 ]; then
      printf 'address=/get.hogman.test/%s\n' "$front_ip"
    fi
    printf 'address=/pebble.hogman.test/%s\n' "$pebble_ip"
    printf 'address=/pebble/%s\n' "$pebble_ip"
    printf 'server=/pens.hogman.test/%s\n' "$cdns_acme_ip"
  } > "$conf"
  chmod 0644 "$conf"

  docker rm -f "$dns_ctr" >/dev/null 2>&1 || true
  docker create --name "$dns_ctr" \
    --network "$ACME_NET" \
    --read-only \
    --cap-drop ALL \
    --cap-add NET_BIND_SERVICE \
    --cap-add SETUID \
    --cap-add SETGID \
    --security-opt no-new-privileges:true \
    --memory 32m \
    --memory-swap 32m \
    --pids-limit 32 \
    --cpus 0.1 \
    -v "$conf:/etc/dnsmasq.conf:ro" \
    hogman-arena-dns:latest --conf-file=/etc/dnsmasq.conf >/dev/null
  docker network connect "$net" "$dns_ctr"
  docker start "$dns_ctr" >/dev/null

  dns_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${net}\").IPAddress}}" "$dns_ctr")"
  [ -n "$dns_ip" ] || die "failed to inspect ${dns_ctr} IP on ${net}"
  printf '%s\n' "$dns_ip"
}

run_sandbox_container() {
  local name="$1"
  local hostname="$2"
  local net="$3"
  local dns_ip="$4"
  shift 4
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d \
    --init \
    --name "$name" \
    --hostname "$hostname" \
    --network "$net" \
    --dns "$dns_ip" \
    --user 1000:1000 \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --tmpfs /dev/shm:rw,noexec,nosuid,nodev,size=4m \
    --tmpfs /home/bot:rw,exec,nosuid,nodev,size=128m,uid=1000,gid=1000 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit "$ARENA_BOT_PIDS" \
    --memory "$ARENA_BOT_MEM" \
    --memory-swap "$ARENA_BOT_MEM" \
    --cpus "$ARENA_BOT_CPUS" \
    --ulimit nofile=1024:1024 \
    --ulimit core=0 \
    -e HOME=/home/bot \
    -e XDG_CONFIG_HOME=/home/bot/.config \
    -e HOGMAN_ACME_CA_URL="https://pebble.hogman.test:14000/dir" \
    -e HOGMAN_ACME_FALLBACK_CA_URL="" \
    -e HOGMAN_ACME_CA_ROOT="/etc/hogman-arena/ca-bundle.crt" \
    -e HOGMAN_DISABLE_NETNS=1 \
    -e TS_NO_LOGS_NO_SUPPORT=true \
    -e HOGMAN_ACME_RESOLVERS="${dns_ip}:53" \
    -e HOGMAN_ACME_PROPAGATION_DELAY="1s" \
    -e HOGMAN_ACME_PROPAGATION_TIMEOUT="30s" \
    -e SSL_CERT_FILE="/etc/hogman-arena/ca-bundle.crt" \
    -e CURL_CA_BUNDLE="/etc/hogman-arena/ca-bundle.crt" \
    -v "$ARENA_HOME/ca-bundle.crt:/etc/hogman-arena/ca-bundle.crt:ro" \
    "$@" \
    hogman-arena-bot:latest >/dev/null
}

start_canary() {
  local pen="$1"
  local net="$2"
  local dns_ip="$3"
  local ctr="arena-canary-${pen}"
  local zone="${pen}.pens.hogman.test"
  local handle="canary-${pen}"
  local link proxy

  log "Provisioning canary vault for ${pen} (https://vault.${zone})"
  "$HOST" pen "$pen" member add "$handle" --role member >/dev/null
  link="$("$HOST" pen "$pen" device key "$handle" personal | awk '/^link:/ {print $2}')"
  [ -n "$link" ] || die "failed to issue device link for ${handle} on ${pen}"

  run_sandbox_container "$ctr" "$handle" "$net" "$dns_ip" \
    -v "$ARENA_HOME/canaries/${pen}:/run/canary:ro"

  docker exec -d "$ctr" python3 /usr/local/lib/hogman-arena/canary_server.py \
    --port 8080 --pen "$pen" --secret-file /run/canary/secret.txt

  retry 15 docker exec "$ctr" curl -sf http://127.0.0.1:8080/ \
    || die "canary HTTP server failed to start in ${ctr}"

  docker exec "$ctr" hogman-join --no-open --no-service --no-system-proxy \
    --hostname "$handle" "$link" >/dev/null \
    || die "canary ${handle} failed to join ${pen}"

  docker exec "$ctr" hogman-join share vault 8080 \
    --note "${pen} canary vault" --background --no-service >/dev/null \
    || die "canary ${handle} failed to share vault.${zone}"

  proxy="$(docker exec "$ctr" jq -r .proxy_addr "/home/bot/.config/hogman/${zone}/config.json")"
  [ -n "$proxy" ] && [ "$proxy" != "null" ] || die "missing proxy_addr for ${ctr}"

  retry 45 docker exec "$ctr" sh -c \
    "curl -sf -x 'http://${proxy}' 'https://vault.${zone}/' | grep -q 'canary=CANARY_'" \
    || die "https://vault.${zone}/ did not become healthy"
}

cmd_down() {
  check_not_production
  if [ ! -f "$ARENA_HOME/.arena-marker" ]; then
    die "no arena marker at ${ARENA_HOME}/.arena-marker; refusing to touch hogman-front or pens that were not created by arena.sh"
  fi
  log "Tearing down arena containers and state (${ARENA_HOME})"
  local c p s
  for c in "${BOT_NAMES[@]}"; do
    docker rm -f "arena-bot-${c}" >/dev/null 2>&1 || true
  done
  for p in "${PEN_NAMES[@]}"; do
    docker rm -f "arena-canary-${p}" >/dev/null 2>&1 || true
  done
  for s in "${SANDBOX_NAMES[@]}"; do
    docker rm -f "hogman-arena-dns-${s}" >/dev/null 2>&1 || true
  done
  docker rm -f "$PEBBLE_CTR" "$CDNS_CTR" >/dev/null 2>&1 || true

  if [ -d "$ARENA_HOME/signup" ]; then
    (cd "$ARENA_HOME/signup" && docker compose down -v >/dev/null 2>&1) || true
  fi
  for p in "${PEN_NAMES[@]}"; do
    pen_net_disconnect_all "$p"
    if [ -d "$ARENA_HOME/pens/$p" ]; then
      (cd "$ARENA_HOME/pens/$p" && ./hogman down -v --remove-orphans >/dev/null 2>&1) || true
    fi
    docker network rm "pen-${p}-core" >/dev/null 2>&1 || true
  done
  if [ -d "$ARENA_HOME/front" ]; then
    (cd "$ARENA_HOME/front" && docker compose down -v >/dev/null 2>&1) || true
  fi
  for s in "${SANDBOX_NAMES[@]}"; do
    docker network rm "arena-iso-${s}" >/dev/null 2>&1 || true
  done
  docker network rm "$ACME_NET" >/dev/null 2>&1 || true
  docker network rm hogman-front >/dev/null 2>&1 || true
  rm -rf "$ARENA_HOME"
  log "Arena stopped and cleaned up."
}

cmd_up() {
  check_prereqs
  if [ -f "$ARENA_HOME/arena-state.json" ] || [ -f "$ARENA_HOME/.arena-marker" ]; then
    die "arena already appears initialized at ${ARENA_HOME}; run 'arena.sh reset' or 'arena.sh down' first"
  fi
  if [ -n "$(docker ps -aq --filter 'name=^/hogman-front-front-1$')" ]; then
    die "hogman-front-front-1 already exists outside this arena; refusing to touch an existing Hogman host"
  fi
  if docker network inspect hogman-front >/dev/null 2>&1; then
    die "Docker network hogman-front already exists outside this arena; refusing to reuse it"
  fi

  mkdir -p "$ARENA_HOME/src"
  : > "$ARENA_HOME/.arena-marker"
  chmod 0600 "$ARENA_HOME/.arena-marker"
  rsync -a --exclude data --exclude .env "$REPO/core/" "$ARENA_HOME/src/"

  log "Prebuilding registrar binary for arena pens"
  local goarch
  case "$(uname -m)" in
    x86_64|amd64)  goarch=amd64 ;;
    aarch64|arm64) goarch=arm64 ;;
    *)             die "unsupported architecture $(uname -m)" ;;
  esac
  mkdir -p "$ARENA_HOME/src/prebuilt/registrar"
  docker run --rm \
    -v "$REPO/core/registrar:/src:ro" \
    -v "$ARENA_HOME/src/prebuilt/registrar:/out" \
    -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
    golang:1.27-alpine go build -trimpath -ldflags="-s -w" -o "/out/registrar-linux-${goarch}" .

  log "Initializing Hogman front door (test mode)"
  "$HOST" init --test

  local acme="$ARENA_HOME/acme"
  mkdir -p "$acme/cdns" "$acme/sock" "$acme/ca-priv" "$acme/pebble-tls" "$acme/gate-tls"
  chmod 0700 "$acme/ca-priv"
  chgrp 65532 "$acme/sock" && chmod 0750 "$acme/sock"

  log "Creating --internal ACME network (${ACME_NET}) and starting challenge-dns (CDNS_WEEKLY_CAP=5)"
  docker network create --internal "$ACME_NET" >/dev/null

  docker run --rm \
    -v "$REPO/deploy/challenge-dns:/src:ro" \
    -v "$acme/cdns:/out" \
    -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
    golang:1.27-alpine go build -o /out/challenge-dns .

  docker run -d --name "$CDNS_CTR" \
    --network "$ACME_NET" \
    --read-only \
    --cap-drop ALL \
    --cap-add NET_BIND_SERVICE \
    --cap-add CHOWN \
    --security-opt no-new-privileges:true \
    --memory 128m \
    --memory-swap 128m \
    --pids-limit 64 \
    --cpus 0.5 \
    -v "$acme/cdns:/cdns" -v "$acme/sock:/run/hogman-acme" \
    -e CDNS_LISTEN=0.0.0.0:53 \
    -e CDNS_PENS_ZONE=pens.hogman.test \
    -e CDNS_GATE_NAME=_acme-challenge.gate.hogman.test \
    -e CDNS_WEEKLY_CAP=5 \
    -e CDNS_STATE=/cdns/state.json \
    -e CDNS_API_SOCK=/run/hogman-acme/api.sock \
    -e CDNS_ADMIN_SOCK=/cdns/admin.sock \
    alpine:3.22 /cdns/challenge-dns serve >/dev/null

  retry 20 env CDNS_ADMIN_SOCK="$acme/cdns/admin.sock" "$acme/cdns/challenge-dns" cred list \
    || die "challenge-dns admin socket did not come up"

  log "Starting Pebble test ACME CA (management loopback-only, zero internet egress)"
  # Keep CA private key strictly host-only (0600 inside 0700 dir); never mount into Pebble.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$acme/ca-priv/ca.key" -out "$acme/pebble-tls/ca.crt" \
    -days 7 -subj "/CN=hogman-arena-pebble-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" >/dev/null 2>&1
  chmod 0600 "$acme/ca-priv/ca.key"
  chmod 0644 "$acme/pebble-tls/ca.crt"

  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$acme/pebble-tls/server.key" -out "$acme/ca-priv/server.csr" \
    -subj "/CN=pebble.hogman.test" >/dev/null 2>&1
  printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pebble,DNS:pebble.hogman.test,IP:127.0.0.1\n' \
    > "$acme/ca-priv/ext.cnf"
  openssl x509 -req -in "$acme/ca-priv/server.csr" \
    -CA "$acme/pebble-tls/ca.crt" -CAkey "$acme/ca-priv/ca.key" -CAcreateserial \
    -out "$acme/pebble-tls/server.crt" -days 7 -extfile "$acme/ca-priv/ext.cnf" >/dev/null 2>&1
  chmod 0644 "$acme/pebble-tls/server.crt"
  chmod 0600 "$acme/pebble-tls/server.key"

  cat > "$acme/pebble.json" <<'JSON'
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "127.0.0.1:15000",
    "certificate": "/certs/server.crt",
    "privateKey": "/certs/server.key",
    "httpPort": 5002,
    "tlsPort": 5001,
    "externalAccountBindingRequired": false,
    "retryAfter": {"authz": 1, "order": 1},
    "keyAlgorithm": "ecdsa"
  }
}
JSON

  docker run -d --name "$PEBBLE_CTR" \
    --network "$ACME_NET" --network-alias pebble \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --memory 256m \
    --memory-swap 256m \
    --pids-limit 128 \
    --cpus 0.5 \
    -e PEBBLE_VA_NOSLEEP=1 \
    -v "$acme/pebble-tls:/certs:ro" -v "$acme/pebble.json:/pebble.json:ro" \
    ghcr.io/letsencrypt/pebble:2.10.3 \
    -config /pebble.json -dnsserver "${CDNS_CTR}:53" >/dev/null

  retry 30 docker run --rm --network "$ACME_NET" -v "$acme/pebble-tls/ca.crt:/ca.crt:ro" \
    nicolaka/netshoot:v0.14 curl -sf --cacert /ca.crt https://pebble:14000/dir \
    || die "Pebble directory did not come up"

  docker run --rm --network "container:${PEBBLE_CTR}" -v "$acme/pebble-tls/ca.crt:/ca.crt:ro" \
    nicolaka/netshoot:v0.14 curl -sf --cacert /ca.crt https://127.0.0.1:15000/roots/0 \
    > "$acme/issued-root.crt"
  grep -q 'BEGIN CERTIFICATE' "$acme/issued-root.crt" || die "failed to fetch Pebble issuing root"

  log "Signing *.gate.hogman.test wildcard certificate"
  local front_pki="$ARENA_HOME/front/data/caddy/pki/authorities/local"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$acme/gate-tls/gate.key" -out "$acme/ca-priv/gate.csr" \
    -subj "/CN=*.gate.hogman.test" >/dev/null 2>&1
  printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:*.gate.hogman.test\n' \
    > "$acme/ca-priv/gate.ext"
  openssl x509 -req -in "$acme/ca-priv/gate.csr" \
    -CA "$front_pki/root.crt" -CAkey "$front_pki/root.key" -CAcreateserial \
    -out "$acme/gate-tls/gate.crt" -days 7 -extfile "$acme/ca-priv/gate.ext" >/dev/null 2>&1
  local fuid
  fuid="$(grep -h '^FRONT_UID=' "$ARENA_HOME/host.env" | cut -d= -f2 | tr -d "'")"
  chown -R "${fuid:-0}" "$acme/gate-tls"
  chmod 0644 "$acme/gate-tls/gate.crt"
  chmod 0600 "$acme/gate-tls/gate.key"

  cat >> "$ARENA_HOME/host.env" <<EOF
GATE_TLS='$acme/gate-tls'
CDNS_BIN='$acme/cdns/challenge-dns'
CDNS_ADMIN='$acme/cdns/admin.sock'
HOGMAN_ACME_SOCK_DIR='$acme/sock'
ACME_CA_URL='https://pebble:14000/dir'
ACME_RESOLVERS='${CDNS_CTR}:53'
HOGMAN_TEST_ACME_ROOT='$acme/pebble-tls/ca.crt'
GATE_DOMAIN='gate.hogman.test'
EOF

  "$HOST" pens-zone pens.hogman.test

  log "Raising Pen A (pena) and Pen B (penb)"
  local p
  for p in "${PEN_NAMES[@]}"; do
    pen_net "$p"
    "$HOST" add "$p"
    # Detach Pebble from non-internal pen core networks as soon as home.<pen> has
    # its cert so Pebble stays strictly on --internal networks (zero internet egress).
    pen_net_disconnect_pebble "$p"
  done

  if [ "$ARENA_ENABLE_SIGNUP" = 1 ]; then
    log "ARENA_ENABLE_SIGNUP=1: enabling sign-up service at https://get.hogman.test"
    local agekey
    agekey="$(docker run --rm alpine:3.22 sh -c 'apk add -q age >/dev/null && age-keygen 2>/dev/null')"
    grep '^AGE-SECRET-KEY' <<<"$agekey" > "$ARENA_HOME/age-secret.txt"
    chmod 0600 "$ARENA_HOME/age-secret.txt"
    grep -o 'age1[0-9a-z]*' <<<"$agekey" | head -1 > "$ARENA_HOME/backup-recipient.txt"
    rsync -a --exclude hogman-signup.bin "$REPO/deploy/signup/" "$ARENA_HOME/signup-src/"
    "$HOST" signup-setup gate.hogman.test get.hogman.test 6
  else
    log "Skipping signup broker (disabled by default in v1 to avoid exposing docker.sock surface)"
  fi

  log "Building CA bundle, DNS image, and locked-down bot sandbox image"
  cat "$front_pki/root.crt" "$acme/pebble-tls/ca.crt" "$acme/issued-root.crt" > "$ARENA_HOME/ca-bundle.crt"
  chmod 0644 "$ARENA_HOME/ca-bundle.crt"

  docker build -q -t hogman-arena-dns:latest -f "$SCRIPT_DIR/Dockerfile.dns" "$SCRIPT_DIR" >/dev/null

  local arch join_bin join_sha256 build_ctx
  arch="$(uname -m)"
  join_bin="$ARENA_HOME/pens/pena/data/join-dl/hogman-join-Linux-${arch}"
  [ -x "$join_bin" ] || die "expected hogman-join binary at ${join_bin}"
  join_sha256="$(sha256sum "$join_bin" | awk '{print $1}')"

  build_ctx="$ARENA_HOME/bot-build"
  mkdir -p "$build_ctx"
  cp "$join_bin" "$build_ctx/hogman-join"
  cp "$SCRIPT_DIR/canary_server.py" "$build_ctx/canary_server.py"
  cp "$SCRIPT_DIR/Dockerfile.bot" "$build_ctx/Dockerfile.bot"
  docker build -q -t hogman-arena-bot:latest -f "$build_ctx/Dockerfile.bot" "$build_ctx" >/dev/null
  rm -rf "$build_ctx"

  local cdns_acme_ip
  cdns_acme_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${ACME_NET}\").IPAddress}}" "$CDNS_CTR")"
  [ -n "$cdns_acme_ip" ] || die "failed to inspect ${CDNS_CTR} IP on ${ACME_NET}"

  log "Creating per-sandbox --internal networks and DNS resolvers (zero bot-to-bot ICC)"
  declare -A dns_ips
  local s
  for s in "${SANDBOX_NAMES[@]}"; do
    dns_ips["$s"]="$(setup_isolated_sandbox_net "$s" "$cdns_acme_ip")"
  done

  log "Planting Pen A & Pen B canary secrets and starting canary vaults"
  local pena_canary penb_canary
  pena_canary="$(write_canary pena INITIAL)"
  penb_canary="$(write_canary penb SECRET)"
  start_canary pena "arena-iso-canary-pena" "${dns_ips[canary-pena]}"
  start_canary penb "arena-iso-canary-penb" "${dns_ips[canary-penb]}"

  log "Provisioning owner alice on pena and starting isolated bot containers"
  "$HOST" pen pena member add alice --role owner >/dev/null
  local alice_link
  alice_link="$("$HOST" pen pena device key alice personal | awk '/^link:/ {print $2}')"
  [ -n "$alice_link" ] || die "failed to issue owner device link for alice"

  local bot
  for bot in "${BOT_NAMES[@]}"; do
    run_sandbox_container "arena-bot-${bot}" "$bot" "arena-iso-${bot}" "${dns_ips[$bot]}"
  done

  local alice_front_ip
  alice_front_ip="$(docker inspect -f '{{(index .NetworkSettings.Networks "arena-iso-alice").IPAddress}}' hogman-front-front-1)"
  retry 15 sh -c "docker exec arena-bot-alice dig +short +time=3 pena.gate.hogman.test | grep -qx '$alice_front_ip'" \
    || die "arena DNS check failed for pena.gate.hogman.test"

  jq -n \
    --arg arena_home "$ARENA_HOME" \
    --arg acme_network "$ACME_NET" \
    --arg pebble_container "$PEBBLE_CTR" \
    --arg hogman_join_sha256 "$join_sha256" \
    --arg pena_zone "pena.pens.hogman.test" \
    --arg pena_gate "pena.gate.hogman.test" \
    --arg penb_zone "penb.pens.hogman.test" \
    --arg penb_gate "penb.gate.hogman.test" \
    --arg alice_join_link "$alice_link" \
    --arg pena_canary_file "$ARENA_HOME/canaries/pena/secret.txt" \
    --arg penb_canary_file "$ARENA_HOME/canaries/penb/secret.txt" \
    --arg pena_initial_canary "$pena_canary" \
    --arg dns_alice "${dns_ips[alice]}" \
    --arg dns_insider "${dns_ips[mallory-insider]}" \
    --arg dns_kicked "${dns_ips[mallory-kicked]}" \
    '{
      arena_home: $arena_home,
      acme_network: $acme_network,
      pebble_container: $pebble_container,
      hogman_join_sha256: $hogman_join_sha256,
      pen_a: {
        name: "pena",
        zone: $pena_zone,
        gate: $pena_gate,
        vault_url: ("https://vault." + $pena_zone + "/"),
        canary_container: "arena-canary-pena",
        canary_network: "arena-iso-canary-pena",
        canary_file: $pena_canary_file,
        initial_canary: $pena_initial_canary
      },
      pen_b: {
        name: "penb",
        zone: $penb_zone,
        gate: $penb_gate,
        vault_url: ("https://vault." + $penb_zone + "/"),
        canary_container: "arena-canary-penb",
        canary_network: "arena-iso-canary-penb",
        canary_file: $penb_canary_file
      },
      alice_join_link: $alice_join_link,
      bots: {
        "alice": "arena-bot-alice",
        "mallory-insider": "arena-bot-mallory-insider",
        "mallory-kicked": "arena-bot-mallory-kicked"
      },
      bot_networks: {
        "alice": "arena-iso-alice",
        "mallory-insider": "arena-iso-mallory-insider",
        "mallory-kicked": "arena-iso-mallory-kicked"
      },
      bot_dns_ips: {
        "alice": $dns_alice,
        "mallory-insider": $dns_insider,
        "mallory-kicked": $dns_kicked
      }
    }' > "$ARENA_HOME/arena-state.json"
  chmod 0600 "$ARENA_HOME/arena-state.json"

  log "Arena ready."
  log "  State:      $ARENA_HOME/arena-state.json"
  log "  Pen A:      https://vault.pena.pens.hogman.test (gate: pena.gate.hogman.test)"
  log "  Pen B:      https://vault.penb.pens.hogman.test (gate: penb.gate.hogman.test)"
  log "  Isolation:  per-sandbox --internal networks (zero bot-to-bot ICC, Pebble --internal only)"
  log "  Bots:       arena-bot-alice, arena-bot-mallory-insider, arena-bot-mallory-kicked"
}

cmd_rotate_canary() {
  check_not_production
  local pen="${1:-}"
  local phase="${2:-POSTKICK}"
  case "$pen" in
    pena|penb) ;;
    *) die "usage: arena.sh rotate-canary <pena|penb> [phase]" ;;
  esac
  [ -d "$ARENA_HOME/canaries/$pen" ] || die "arena is not initialized at ${ARENA_HOME}"
  write_canary "$pen" "$phase"
}

cmd_status() {
  [ -f "$ARENA_HOME/arena-state.json" ] || die "arena is not initialized at ${ARENA_HOME}"
  local s internal
  for s in "${SANDBOX_NAMES[@]}"; do
    internal="$(docker network inspect -f '{{.Internal}}' "arena-iso-${s}" 2>/dev/null || echo unknown)"
    printf 'Network arena-iso-%s: internal=%s\n' "$s" "$internal"
  done
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.RunningFor}}' \
    --filter 'name=^/(hogman-front-front-1|hogman-arena-|arena-|pen-pen[ab]-)'
}

case "${1:-}" in
  up)            cmd_up ;;
  down)          cmd_down ;;
  reset)         cmd_down; cmd_up ;;
  rotate-canary) shift; cmd_rotate_canary "$@" ;;
  status)        cmd_status ;;
  *)
    printf 'usage: %s <up|down|reset|rotate-canary|status>\n' "$0" >&2
    exit 2
    ;;
esac
