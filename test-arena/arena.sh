#!/usr/bin/env bash
# Manage the self-contained Hogman Bot Arena stack (Pebble + challenge-dns +
# hogman-front + Pen A / Pen B + canary vaults + locked-down bot sandboxes).
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

BOT_NET="hogman-arena-bots"
CDNS_CTR="hogman-arena-cdns"
PEBBLE_CTR="hogman-arena-pebble"
DNS_CTR="hogman-arena-dns"
BOT_NAMES=(alice mallory-insider mallory-kicked)
PEN_NAMES=(pena penb)

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

check_not_production() {
  if command -v tailscale >/dev/null 2>&1 || [ -S /var/run/tailscale/tailscaled.sock ]; then
    die "Tailscale detected on this host; refusing to run Bot Arena outside a disposable sandbox droplet"
  fi
  if [ -d /opt/hogman ]; then
    die "/opt/hogman detected; refusing to run Bot Arena on a Hogman host"
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

pen_net_disconnect() {
  local pen="$1"
  docker network disconnect -f "pen-${pen}-core" "$CDNS_CTR" >/dev/null 2>&1 || true
  docker network disconnect -f "pen-${pen}-core" "$PEBBLE_CTR" >/dev/null 2>&1 || true
}

run_sandbox_container() {
  local name="$1"
  local hostname="$2"
  local dns_ip="$3"
  shift 3
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d \
    --name "$name" \
    --hostname "$hostname" \
    --network "$BOT_NET" \
    --dns "$dns_ip" \
    --user 1000:1000 \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --tmpfs /home/bot:rw,nosuid,size=128m,uid=1000,gid=1000 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit "$ARENA_BOT_PIDS" \
    --memory "$ARENA_BOT_MEM" \
    --memory-swap "$ARENA_BOT_MEM" \
    --cpus "$ARENA_BOT_CPUS" \
    -e HOME=/home/bot \
    -e XDG_CONFIG_HOME=/home/bot/.config \
    -e HOGMAN_ACME_CA_URL="https://pebble.hogman.test:14000/dir" \
    -e HOGMAN_ACME_FALLBACK_CA_URL="" \
    -e HOGMAN_ACME_CA_ROOT="/etc/hogman-arena/ca-bundle.crt" \
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
  local dns_ip="$2"
  local ctr="arena-canary-${pen}"
  local zone="${pen}.pens.hogman.test"
  local handle="canary-${pen}"
  local link proxy

  log "Provisioning canary vault for ${pen} (https://vault.${zone})"
  "$HOST" pen "$pen" member add "$handle" --role member >/dev/null
  link="$("$HOST" pen "$pen" device key "$handle" personal | awk '/^link:/ {print $2}')"
  [ -n "$link" ] || die "failed to issue device link for ${handle} on ${pen}"

  run_sandbox_container "$ctr" "$handle" "$dns_ip" \
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
  local c p
  for c in "${BOT_NAMES[@]}"; do
    docker rm -f "arena-bot-${c}" >/dev/null 2>&1 || true
  done
  for p in "${PEN_NAMES[@]}"; do
    docker rm -f "arena-canary-${p}" >/dev/null 2>&1 || true
  done
  docker rm -f "$DNS_CTR" "$PEBBLE_CTR" "$CDNS_CTR" >/dev/null 2>&1 || true

  if [ -d "$ARENA_HOME/signup" ]; then
    (cd "$ARENA_HOME/signup" && docker compose down -v >/dev/null 2>&1) || true
  fi
  for p in "${PEN_NAMES[@]}"; do
    pen_net_disconnect "$p"
    if [ -d "$ARENA_HOME/pens/$p" ]; then
      (cd "$ARENA_HOME/pens/$p" && ./hogman down -v --remove-orphans >/dev/null 2>&1) || true
    fi
    docker network rm "pen-${p}-core" >/dev/null 2>&1 || true
  done
  if [ -d "$ARENA_HOME/front" ]; then
    (cd "$ARENA_HOME/front" && docker compose down -v >/dev/null 2>&1) || true
  fi
  docker network rm "$BOT_NET" >/dev/null 2>&1 || true
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

  log "Initializing Hogman front door (test mode)"
  "$HOST" init --test

  local acme="$ARENA_HOME/acme"
  mkdir -p "$acme/cdns" "$acme/sock" "$acme/certs" "$acme/gate-tls"
  chgrp 65532 "$acme/sock" && chmod 0750 "$acme/sock"

  log "Building and starting challenge-dns (CDNS_WEEKLY_CAP=5)"
  docker run --rm \
    -v "$REPO/deploy/challenge-dns:/src:ro" \
    -v "$acme/cdns:/out" \
    -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
    golang:1.27-alpine go build -o /out/challenge-dns .

  docker run -d --name "$CDNS_CTR" --network hogman-front \
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

  log "Starting Pebble test ACME CA"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$acme/certs/ca.key" -out "$acme/certs/ca.crt" \
    -days 7 -subj "/CN=hogman-arena-pebble-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" >/dev/null 2>&1
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$acme/certs/server.key" -out "$acme/certs/server.csr" \
    -subj "/CN=pebble.hogman.test" >/dev/null 2>&1
  # Bind Pebble's management API strictly to loopback (127.0.0.1:15000) so
  # bots on hogman-arena-bots can never reach /intermediate-keys/0 and mint
  # arbitrary certificates trusted by the arena CA bundle.
  printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pebble,DNS:pebble.hogman.test,IP:127.0.0.1\n' \
    > "$acme/certs/ext.cnf"
  openssl x509 -req -in "$acme/certs/server.csr" \
    -CA "$acme/certs/ca.crt" -CAkey "$acme/certs/ca.key" -CAcreateserial \
    -out "$acme/certs/server.crt" -days 7 -extfile "$acme/certs/ext.cnf" >/dev/null 2>&1
  chmod 0644 "$acme/certs/"*

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

  docker run -d --name "$PEBBLE_CTR" --network hogman-front --network-alias pebble \
    -e PEBBLE_VA_NOSLEEP=1 \
    -v "$acme/certs:/certs:ro" -v "$acme/pebble.json:/pebble.json:ro" \
    ghcr.io/letsencrypt/pebble:2.10.3 \
    -config /pebble.json -dnsserver "${CDNS_CTR}:53" >/dev/null

  retry 30 docker run --rm --network hogman-front -v "$acme/certs:/c:ro" \
    nicolaka/netshoot:v0.14 curl -sf --cacert /c/ca.crt https://pebble:14000/dir \
    || die "Pebble directory did not come up"

  docker run --rm --network "container:${PEBBLE_CTR}" -v "$acme/certs:/c:ro" \
    nicolaka/netshoot:v0.14 curl -sf --cacert /c/ca.crt https://127.0.0.1:15000/roots/0 \
    > "$acme/issued-root.crt"
  grep -q 'BEGIN CERTIFICATE' "$acme/issued-root.crt" || die "failed to fetch Pebble issuing root"

  log "Signing *.gate.hogman.test wildcard certificate"
  local front_pki="$ARENA_HOME/front/data/caddy/pki/authorities/local"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$acme/gate-tls/gate.key" -out "$acme/gate.csr" \
    -subj "/CN=*.gate.hogman.test" >/dev/null 2>&1
  printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:*.gate.hogman.test\n' \
    > "$acme/gate.ext"
  openssl x509 -req -in "$acme/gate.csr" \
    -CA "$front_pki/root.crt" -CAkey "$front_pki/root.key" -CAcreateserial \
    -out "$acme/gate-tls/gate.crt" -days 7 -extfile "$acme/gate.ext" >/dev/null 2>&1
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
HOGMAN_TEST_ACME_ROOT='$acme/certs/ca.crt'
GATE_DOMAIN='gate.hogman.test'
EOF

  "$HOST" pens-zone pens.hogman.test

  log "Raising Pen A (pena) and Pen B (penb)"
  local p
  for p in "${PEN_NAMES[@]}"; do
    pen_net "$p"
    "$HOST" add "$p"
  done

  log "Enabling arena sign-up service at https://get.hogman.test"
  local agekey
  agekey="$(docker run --rm alpine:3.22 sh -c 'apk add -q age >/dev/null && age-keygen 2>/dev/null')"
  grep '^AGE-SECRET-KEY' <<<"$agekey" > "$ARENA_HOME/age-secret.txt"
  chmod 0600 "$ARENA_HOME/age-secret.txt"
  grep -o 'age1[0-9a-z]*' <<<"$agekey" | head -1 > "$ARENA_HOME/backup-recipient.txt"
  rsync -a --exclude hogman-signup.bin "$REPO/deploy/signup/" "$ARENA_HOME/signup-src/"
  "$HOST" signup-setup gate.hogman.test get.hogman.test 6

  log "Creating --internal bot network (${BOT_NET}) and arena DNS resolver"
  docker network create --internal "$BOT_NET" >/dev/null
  docker network connect "$BOT_NET" hogman-front-front-1
  docker network connect "$BOT_NET" "$PEBBLE_CTR"

  local front_bot_ip pebble_bot_ip cdns_front_ip
  front_bot_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${BOT_NET}\").IPAddress}}" hogman-front-front-1)"
  pebble_bot_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${BOT_NET}\").IPAddress}}" "$PEBBLE_CTR")"
  cdns_front_ip="$(docker inspect -f '{{(index .NetworkSettings.Networks "hogman-front").IPAddress}}' "$CDNS_CTR")"
  [ -n "$front_bot_ip" ] && [ -n "$pebble_bot_ip" ] && [ -n "$cdns_front_ip" ] \
    || die "failed to resolve arena container IPs"

  docker build -q -t hogman-arena-dns:latest -f "$SCRIPT_DIR/Dockerfile.dns" "$SCRIPT_DIR" >/dev/null

  mkdir -p "$ARENA_HOME/dns"
  cat > "$ARENA_HOME/dns/dnsmasq.conf" <<EOF
no-resolv
no-hosts
cache-size=0
no-negcache
port=53
bind-dynamic
log-facility=-
address=/.gate.hogman.test/${front_bot_ip}
address=/get.hogman.test/${front_bot_ip}
address=/pebble.hogman.test/${pebble_bot_ip}
address=/pebble/${pebble_bot_ip}
server=/pens.hogman.test/${cdns_front_ip}
EOF
  chmod 0644 "$ARENA_HOME/dns/dnsmasq.conf"

  docker create --name "$DNS_CTR" \
    --network hogman-front \
    --read-only \
    --cap-drop ALL \
    --cap-add NET_BIND_SERVICE \
    --cap-add SETUID \
    --cap-add SETGID \
    --security-opt no-new-privileges:true \
    -v "$ARENA_HOME/dns/dnsmasq.conf:/etc/dnsmasq.conf:ro" \
    hogman-arena-dns:latest --conf-file=/etc/dnsmasq.conf >/dev/null
  docker network connect "$BOT_NET" "$DNS_CTR"
  docker start "$DNS_CTR" >/dev/null

  local arena_dns_ip
  arena_dns_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${BOT_NET}\").IPAddress}}" "$DNS_CTR")"
  [ -n "$arena_dns_ip" ] || die "failed to resolve ${DNS_CTR} IP on ${BOT_NET}"

  log "Building CA bundle and locked-down bot sandbox image"
  cat "$front_pki/root.crt" "$acme/certs/ca.crt" "$acme/issued-root.crt" > "$ARENA_HOME/ca-bundle.crt"
  chmod 0644 "$ARENA_HOME/ca-bundle.crt"

  local arch join_bin build_ctx
  arch="$(uname -m)"
  join_bin="$ARENA_HOME/pens/pena/data/join-dl/hogman-join-Linux-${arch}"
  [ -x "$join_bin" ] || die "expected hogman-join binary at ${join_bin}"

  build_ctx="$ARENA_HOME/bot-build"
  mkdir -p "$build_ctx"
  cp "$join_bin" "$build_ctx/hogman-join"
  cp "$SCRIPT_DIR/canary_server.py" "$build_ctx/canary_server.py"
  cp "$SCRIPT_DIR/Dockerfile.bot" "$build_ctx/Dockerfile.bot"
  docker build -q -t hogman-arena-bot:latest -f "$build_ctx/Dockerfile.bot" "$build_ctx" >/dev/null
  rm -rf "$build_ctx"

  log "Planting Pen A & Pen B canary secrets and starting canary vaults"
  local pena_canary penb_canary
  pena_canary="$(write_canary pena INITIAL)"
  penb_canary="$(write_canary penb SECRET)"
  start_canary pena "$arena_dns_ip"
  start_canary penb "$arena_dns_ip"

  log "Provisioning owner alice on pena and starting bot containers"
  "$HOST" pen pena member add alice --role owner >/dev/null
  local alice_link
  alice_link="$("$HOST" pen pena device key alice personal | awk '/^link:/ {print $2}')"
  [ -n "$alice_link" ] || die "failed to issue owner device link for alice"

  local bot
  for bot in "${BOT_NAMES[@]}"; do
    run_sandbox_container "arena-bot-${bot}" "$bot" "$arena_dns_ip"
  done

  # Verify DNS pinning and zero-egress behavior inside a bot container.
  retry 15 sh -c "docker exec arena-bot-alice dig +short +time=3 pena.gate.hogman.test | grep -qx '$front_bot_ip'" \
    || die "arena DNS check failed for pena.gate.hogman.test"

  jq -n \
    --arg arena_home "$ARENA_HOME" \
    --arg bot_network "$BOT_NET" \
    --arg arena_dns_ip "$arena_dns_ip" \
    --arg front_bot_ip "$front_bot_ip" \
    --arg pebble_bot_ip "$pebble_bot_ip" \
    --arg pena_zone "pena.pens.hogman.test" \
    --arg pena_gate "pena.gate.hogman.test" \
    --arg penb_zone "penb.pens.hogman.test" \
    --arg penb_gate "penb.gate.hogman.test" \
    --arg alice_join_link "$alice_link" \
    --arg pena_canary_file "$ARENA_HOME/canaries/pena/secret.txt" \
    --arg penb_canary_file "$ARENA_HOME/canaries/penb/secret.txt" \
    --arg pena_initial_canary "$pena_canary" \
    '{
      arena_home: $arena_home,
      bot_network: $bot_network,
      arena_dns_ip: $arena_dns_ip,
      front_bot_ip: $front_bot_ip,
      pebble_bot_ip: $pebble_bot_ip,
      pen_a: {
        name: "pena",
        zone: $pena_zone,
        gate: $pena_gate,
        vault_url: ("https://vault." + $pena_zone + "/"),
        canary_container: "arena-canary-pena",
        canary_file: $pena_canary_file,
        initial_canary: $pena_initial_canary
      },
      pen_b: {
        name: "penb",
        zone: $penb_zone,
        gate: $penb_gate,
        vault_url: ("https://vault." + $penb_zone + "/"),
        canary_container: "arena-canary-penb",
        canary_file: $penb_canary_file
      },
      alice_join_link: $alice_join_link,
      bots: {
        "alice": "arena-bot-alice",
        "mallory-insider": "arena-bot-mallory-insider",
        "mallory-kicked": "arena-bot-mallory-kicked"
      }
    }' > "$ARENA_HOME/arena-state.json"
  chmod 0600 "$ARENA_HOME/arena-state.json"

  log "Arena ready."
  log "  State:      $ARENA_HOME/arena-state.json"
  log "  Pen A:      https://vault.pena.pens.hogman.test (gate: pena.gate.hogman.test)"
  log "  Pen B:      https://vault.penb.pens.hogman.test (gate: penb.gate.hogman.test)"
  log "  Bot net:    ${BOT_NET} (internal=true, dns=${arena_dns_ip})"
  log "  Bots:       arena-bot-alice, arena-bot-mallory-insider, arena-bot-mallory-kicked"
}

cmd_rotate_canary() {
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
  local internal
  internal="$(docker network inspect -f '{{.Internal}}' "$BOT_NET" 2>/dev/null || echo unknown)"
  printf 'Bot network: %s (internal=%s)\n' "$BOT_NET" "$internal"
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
