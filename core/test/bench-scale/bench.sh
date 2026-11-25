#!/usr/bin/env bash
# Repeatable I-30 single-pen scale & capacity benchmark.
#
# Raises one isolated benchmark pen (headscale + registrar) using the exact
# production container limits from core/compose.yaml (headscale: 0.5 CPU / 256m;
# registrar: 0.25 CPU / 128m), binds NO public host ports, makes NO ACME calls,
# and ramps enrolled + live tsnet devices across configurable stages.
#
# Usage:
#   STAGES="10 50 100 250 500" LIVE_MAX=40 core/test/bench-scale/bench.sh
#
# Optional env:
#   STAGES          Space-separated total device counts (default: "10 50 100 250 500")
#   LIVE_MAX        Max simultaneously online tsnet clients kept alive (default: 40)
#   ENROLL_CONC     Parallel tsnet enrollment workers (default: 8)
#   TRAFFIC_REQS    HTTPS requests per traffic probe (default: 100)
#   TRAFFIC_CONC    Concurrent HTTPS workers (default: 10)
#   REGISTRAR_IMAGE Prebuilt registrar image to use (default: hogman/registrar:dev)
#   DRIVER_BIN      Prebuilt linux bench-driver binary (if empty, built with Docker)
#   KEEP_WORKDIR    If 1, leave workdir and containers up on exit for inspection
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

STAGES="${STAGES:-10 50 100 250 500}"
LIVE_MAX="${LIVE_MAX:-40}"
ENROLL_CONC="${ENROLL_CONC:-8}"
TRAFFIC_REQS="${TRAFFIC_REQS:-100}"
TRAFFIC_CONC="${TRAFFIC_CONC:-10}"
REGISTRAR_IMAGE="${REGISTRAR_IMAGE:-hogman/registrar:dev}"
HEADSCALE_IMAGE="${HEADSCALE_IMAGE:-headscale/headscale:0.29.7@sha256:11f81665e842809db9fe3006a38c56a66e968baa5abd4bac498e86445572b970}"
ZONE="bench.hogman.test"
PROJ="bench-i30-$$"

WORK="$(mktemp -d /tmp/hogman-bench-i30.XXXXXX)"
cleanup() {
  if [ "${KEEP_WORKDIR:-0}" = "1" ]; then
    echo "KEEP_WORKDIR=1: leaving $WORK and project $PROJ running" >&2
    return
  fi
  docker rm -f "${PROJ}-driver" >/dev/null 2>&1 || true
  if [ -f "$WORK/compose.yaml" ]; then
    docker compose -p "$PROJ" -f "$WORK/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> I-30 benchmark workdir: $WORK (project: $PROJ)"
echo "==> Host: $(uname -s)/$(uname -m) CPUs=$(nproc 2>/dev/null || sysctl -n hw.ncpu) STAGES=[$STAGES] LIVE_MAX=$LIVE_MAX"

# 1. Prepare bench-driver binary for linux/<arch>
DRIVER_BIN="${DRIVER_BIN:-}"
if [ -z "$DRIVER_BIN" ] || [ ! -x "$DRIVER_BIN" ]; then
  ARCH="$(uname -m)"
  case "$ARCH" in x86_64|amd64) GOARCH=amd64 ;; aarch64|arm64) GOARCH=arm64 ;; *) GOARCH=amd64 ;; esac
  echo "==> Building bench-driver (linux/$GOARCH, -tags ts_omit_peerapiserver)..."
  mkdir -p "$WORK/build"
  cp "$REPO_ROOT/core/join/go.mod" "$REPO_ROOT/core/join/go.sum" "$WORK/build/"
  cp "$SCRIPT_DIR/driver.go" "$WORK/build/main.go"
  docker run --rm -v "$WORK/build:/src" -w /src \
    -v hogman-gomod:/go/pkg/mod -v hogman-gocache:/root/.cache/go-build \
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH="$GOARCH" -e GOFLAGS=-tags=ts_omit_peerapiserver \
    golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 \
    go build -trimpath -ldflags="-s -w" -o /src/bench-driver .
  DRIVER_BIN="$WORK/build/bench-driver"
else
  cp "$DRIVER_BIN" "$WORK/bench-driver"
  chmod +x "$WORK/bench-driver"
  DRIVER_BIN="$WORK/bench-driver"
fi

# 2. Ensure registrar image exists
if ! docker image inspect "$REGISTRAR_IMAGE" >/dev/null 2>&1; then
  echo "==> Building $REGISTRAR_IMAGE from core/registrar..."
  docker build -t "$REGISTRAR_IMAGE" "$REPO_ROOT/core/registrar"
fi

# 3. Create isolated pen directories, self-signed home TLS cert, and Headscale config
mkdir -p "$WORK/data/headscale/config" "$WORK/data/headscale/lib" \
         "$WORK/data/registrar/tsnet" "$WORK/data/home-tls" "$WORK/data/secrets/registrar" \
         "$WORK/portal" "$WORK/driver"
printf '<html><body>bench portal</body></html>\n' > "$WORK/portal/index.html"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/data/home-tls/home.key" -out "$WORK/data/home-tls/home.crt" \
  -days 90 -subj "/CN=home.$ZONE" -addext "subjectAltName=DNS:home.$ZONE" >/dev/null 2>&1
cp "$WORK/data/home-tls/home.crt" "$WORK/driver/home.crt"

cat > "$WORK/data/headscale/config/config.yaml" <<EOF
server_url: http://headscale:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: random
derp:
  server:
    enabled: true
    region_id: 999
    region_code: hogman
    region_name: "bench relay"
    verify_clients: true
    stun_listen_addr: 0.0.0.0:3478
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
node:
  expiry: 0
  ephemeral:
    inactivity_timeout: 30m
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
log:
  level: warn
  format: text
policy:
  mode: database
dns:
  magic_dns: true
  base_domain: nodes.$ZONE
  override_local_dns: false
  nameservers:
    global: []
    split:
      $ZONE:
        - 100.64.0.1
unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"
logtail:
  enabled: false
EOF

cat > "$WORK/data/headscale/config/policy.hujson" <<'EOF'
{
  "tagOwners": { "tag:infra": [], "tag:server": [] },
  "grants": [
    { "src": ["tag:infra"], "dst": ["tag:infra"], "ip": ["53", "443"] }
  ]
}
EOF

chmod -R a+rX "$WORK/data/headscale/config" "$WORK/data/home-tls" "$WORK/portal"
chown -R 1000:1000 "$WORK/data/headscale/lib" "$WORK/data/registrar" "$WORK/data/secrets" "$WORK/data/home-tls" 2>/dev/null || chmod -R 0777 "$WORK/data/headscale/lib" "$WORK/data/registrar" "$WORK/data/secrets" "$WORK/data/home-tls"

# Exact production resource limits from core/compose.yaml (no public host ports!).
cat > "$WORK/compose.yaml" <<EOF
services:
  headscale:
    image: ${HEADSCALE_IMAGE}
    user: "1000:1000"
    command: serve
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    cpus: 0.5
    cpu_shares: 256
    mem_limit: 256m
    pids_limit: 128
    environment:
      GOGC: "25"
      GOMEMLIMIT: 180MiB
    tmpfs:
      - /var/run/headscale:uid=1000,gid=1000,mode=0700
      - /tmp:uid=1000,gid=1000,mode=0700
    volumes:
      - ./data/headscale/config:/etc/headscale:ro
      - ./data/headscale/lib:/var/lib/headscale
    networks: [core]
    healthcheck:
      test: ["CMD", "headscale", "health"]
      interval: 5s
      timeout: 3s
      retries: 20

  registrar:
    image: ${REGISTRAR_IMAGE}
    user: "1000:1000"
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    cpus: 0.25
    cpu_shares: 256
    mem_limit: 128m
    pids_limit: 128
    networks: [core]
    environment:
      ZONE: ${ZONE}
      PUBLIC_HOST: bench.gate.hogman.test
      TEST_MODE: "true"
      TSNET_STATE_DIR: /var/lib/registrar/tsnet
      TSNET_CONTROL_URL: http://headscale:8080
      TSNET_HOSTNAME: core
      TSNET_AUTH_KEY_FILE: /var/lib/registrar/tsnet/.authkey
      TSNET_UP_TIMEOUT: 2m
      PORTAL_DIR: /srv/portal
      HOME_TLS_DIR: /home-tls
      ACME_STORAGE_DIR: /var/lib/registrar/acme
      ACME_CA_URL: https://127.0.0.1:1/dir
      CHALLENGE_DNS_URL: http://127.0.0.1:1
      CHALLENGE_DNS_TOKEN_FILE: /secrets/challenge_dns_token
      SYNC_INTERVAL: ${SYNC_INTERVAL:-3s}
      GOGC: "25"
      GOMEMLIMIT: 96MiB
    volumes:
      - ./data/registrar:/var/lib/registrar
      - ./portal:/srv/portal:ro
      - ./data/home-tls:/home-tls
      - ./data/secrets/registrar:/secrets:ro
    healthcheck:
      test: ["CMD", "registrar", "health"]
      interval: 5s
      timeout: 5s
      retries: 60
    depends_on:
      headscale: { condition: service_healthy }

networks:
  core: {}
EOF

dc() { docker compose -p "$PROJ" -f "$WORK/compose.yaml" "$@"; }
hs() { dc exec -T headscale headscale "$@"; }
reg() { dc exec -T registrar registrar "$@"; }

# 4. Bootstrap Headscale + registrar embedded tsnet core node
echo "==> Starting Headscale..."
dc up -d --wait headscale
HS_API_KEY="$(hs apikeys create --expiration 24h | tail -1 | tr -d '\r\n')"
printf '%s\n' "$HS_API_KEY" > "$WORK/data/secrets/registrar/headscale_api_key"
printf 'bench-dummy-token\n' > "$WORK/data/secrets/registrar/challenge_dns_token"
chmod 644 "$WORK/data/secrets/registrar/headscale_api_key" "$WORK/data/secrets/registrar/challenge_dns_token"

hs policy set --file /etc/headscale/policy.hujson >/dev/null
CORE_KEY="$(hs preauthkeys create --tags tag:infra --expiration 1h --output json | jq -r .key)"
printf '%s\n' "$CORE_KEY" > "$WORK/data/registrar/tsnet/.authkey"
chown 1000:1000 "$WORK/data/registrar/tsnet/.authkey" 2>/dev/null || chmod 666 "$WORK/data/registrar/tsnet/.authkey"

echo "==> Starting Registrar (embedded tsnet core)..."
if ! dc up -d --wait registrar; then
  dc logs --tail=60 registrar >&2 || true
  exit 1
fi
CORE_IP="$(cat "$WORK/data/registrar/tsnet/mesh-ip" 2>/dev/null || true)"
if [ -z "$CORE_IP" ]; then
  CORE_IP="$(hs nodes list -o json | jq -r '.[] | select(.tags | index("tag:infra")) | .ip_addresses[0]' | head -n1)"
fi
echo "==> Core node online at $CORE_IP"

# 5. Bootstrap probe members & start bench-driver container on bench network
reg member add bench-owner --role owner >/dev/null
reg member add probe-kick >/dev/null
OWNER_KEY="$(reg device key bench-owner personal | awk '/^key:/ {print $2}' | tr -d '\r')"
KICK_KEY="$(reg device key probe-kick personal | awk '/^key:/ {print $2}' | tr -d '\r')"
ECHO_KEY="$(reg device key bench-owner server | awk '/^key:/ {print $2}' | tr -d '\r')"

docker run -d --name "${PROJ}-driver" --network "${PROJ}_core" \
  -v "$WORK/driver:/work" -v "$DRIVER_BIN:/usr/local/bin/bench-driver:ro" \
  -e GOGC=25 \
  alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf \
  /usr/local/bin/bench-driver -sock /work/driver.sock -control-url http://headscale:8080 -zone "$ZONE" -home-ca /work/home.crt >/dev/null

for i in $(seq 1 40); do
  if docker exec "${PROJ}-driver" /usr/local/bin/bench-driver -sock /work/driver.sock -call GET /health >/dev/null 2>&1; then break; fi
  sleep 0.25
done
drv() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    printf '%s' "$body" | docker exec -i "${PROJ}-driver" /usr/local/bin/bench-driver -sock /work/driver.sock -call "$method" "$path"
  else
    docker exec "${PROJ}-driver" /usr/local/bin/bench-driver -sock /work/driver.sock -call "$method" "$path"
  fi
}

echo "==> Connecting probe nodes (owner, kick-probe, echo-server)..."
INIT_JSON="$(drv POST /init "{\"owner_key\":\"$OWNER_KEY\",\"kick_probe_key\":\"$KICK_KEY\",\"echo_server_key\":\"$ECHO_KEY\",\"core_ip\":\"$CORE_IP\"}")"
echo "    $INIT_JSON"
reg sync >/dev/null

# Helper to measure container stats + OOM + sync timing
HS_CID="$(dc ps -q headscale)"
REG_CID="$(dc ps -q registrar)"

now_ms() {
  local v
  v="$(date +%s%3N 2>/dev/null || true)"
  case "$v" in
    ''|*[!0-9]*) python3 -c 'import time; print(int(time.time()*1000))' ;;
    *) printf '%s\n' "$v" ;;
  esac
}

measure_stage() {
  local n="$1"
  # Sample true steady-state idle CPU/RAM after sync settles (before forced syncs).
  sleep 6
  local hs_mem hs_cpu hs_pids hs_oom reg_mem reg_cpu reg_pids reg_oom
  read -r hs_cpu hs_mem hs_pids <<<"$(docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}} {{.PIDs}}' "$HS_CID" 2>/dev/null | awk '{print $1, $2, $NF}' || echo '0% 0B 0')"
  read -r reg_cpu reg_mem reg_pids <<<"$(docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}} {{.PIDs}}' "$REG_CID" 2>/dev/null | awk '{print $1, $2, $NF}' || echo '0% 0B 0')"
  hs_oom="$(docker inspect -f '{{.State.OOMKilled}}/{{.State.Status}}' "$HS_CID" 2>/dev/null || echo '?')"
  reg_oom="$(docker inspect -f '{{.State.OOMKilled}}/{{.State.Status}}' "$REG_CID" 2>/dev/null || echo '?')"

  # 3x registrar sync timing (median in ms)
  local times=()
  local sync_ok=1
  for k in 1 2 3; do
    local t0 t1
    t0="$(now_ms)"
    if ! reg sync >/dev/null 2>&1; then
      sync_ok=0
      times+=(-1)
    else
      t1="$(now_ms)"
      times+=("$((t1 - t0))")
    fi
  done
  local sync_ms
  sync_ms="$(printf '%s\n' "${times[@]}" | sort -n | sed -n '2p')"
  if [ "$sync_ok" -eq 0 ]; then
    echo >&2 "    WARNING stage=$n reg sync failed (hs=$hs_oom reg=$reg_oom)"
  fi

  local pol_bytes nodes_bytes
  pol_bytes="$(hs policy get 2>/dev/null | wc -c | tr -d ' ')"
  nodes_bytes="$(hs nodes list -o json 2>/dev/null | wc -c | tr -d ' ')"

  local prop_json traf_echo traf_portal drv_stats
  prop_json="$(drv POST /propagation "{\"core_ip\":\"$CORE_IP\",\"handle\":\"probe-kick\"}" 2>&1 || echo '{"suspend_ms":-1,"resume_ms":-1}')"
  traf_echo="$(drv POST /traffic "{\"target\":\"echo\",\"core_ip\":\"$CORE_IP\",\"requests\":$TRAFFIC_REQS,\"concurrency\":$TRAFFIC_CONC}" 2>&1 || echo '{"rps":"0","p50_ms":-1,"p95_ms":-1,"errors":-1}')"
  traf_portal="$(drv POST /traffic "{\"target\":\"portal\",\"core_ip\":\"$CORE_IP\",\"requests\":$TRAFFIC_REQS,\"concurrency\":$TRAFFIC_CONC}" 2>&1 || echo '{"rps":"0","p50_ms":-1,"p95_ms":-1,"errors":-1}')"
  drv_stats="$(drv GET /stats)"

  local sus_ms res_ms echo_rps echo_p95 echo_err port_rps port_p95 port_err live_on peers srv_peers per_node_mb
  sus_ms="$(jq -r '.suspend_ms // -1' <<<"$prop_json" 2>/dev/null || echo -1)"
  res_ms="$(jq -r '.resume_ms // -1' <<<"$prop_json" 2>/dev/null || echo -1)"
  echo_rps="$(jq -r '.rps // "0"' <<<"$traf_echo" 2>/dev/null || echo 0)"
  echo_p95="$(jq -r '.p95_ms // -1' <<<"$traf_echo" 2>/dev/null || echo -1)"
  echo_err="$(jq -r '.errors // -1' <<<"$traf_echo" 2>/dev/null || echo -1)"
  port_rps="$(jq -r '.rps // "0"' <<<"$traf_portal" 2>/dev/null || echo 0)"
  port_p95="$(jq -r '.p95_ms // -1' <<<"$traf_portal" 2>/dev/null || echo -1)"
  port_err="$(jq -r '.errors // -1' <<<"$traf_portal" 2>/dev/null || echo -1)"
  live_on="$(jq -r '.live_online' <<<"$drv_stats")"
  peers="$(jq -r '.owner_netmap_peers' <<<"$drv_stats")"
  srv_peers="$(jq -r '.server_netmap_peers' <<<"$drv_stats")"
  per_node_mb="$(jq -r '.driver_per_node_mb' <<<"$drv_stats")"
  if [ "$echo_err" != "0" ] || [ "$port_err" != "0" ] || [ "$sus_ms" = "-1" ]; then
    echo >&2 "    diag stage=$n prop=$prop_json echo=$traf_echo portal=$traf_portal"
  fi

  printf '| %4d | %4d | %s (%s, oom=%s) | %s (%s, oom=%s) | %5dms | %5dKB | %6dKB | %5dms / %5dms | %s rps (p95=%dms, err=%s) | %s rps (p95=%dms, err=%s) | %sMB/node (p=%d, s=%d) |\n' \
    "$n" "$live_on" "$hs_mem" "$hs_cpu" "$hs_oom" "$reg_mem" "$reg_cpu" "$reg_oom" \
    "$sync_ms" "$((pol_bytes/1024))" "$((nodes_bytes/1024))" "$sus_ms" "$res_ms" \
    "$echo_rps" "$echo_p95" "$echo_err" "$port_rps" "$port_p95" "$port_err" "$per_node_mb" "$peers" "$srv_peers"
}

echo ""
echo "| Devices | Live | Headscale (256m/0.5c) | Registrar (128m/0.25c) | Sync(med) | Policy | NodesJSON | Suspend / Resume | Share HTTPS | Portal HTTPS | Client Heap |"
echo "|---:|---:|---|---|---:|---:|---:|---|---|---|---|"

CURRENT=3
LIVE_CUR=3
NEXT_ID=1

for TARGET in $STAGES; do
  if [ "$TARGET" -gt "$CURRENT" ]; then
    NEED=$((TARGET - CURRENT))
    END_ID=$((NEXT_ID + NEED - 1))
    echo >&2 "==> Issuing $NEED device keys (ids $NEXT_ID..$END_ID, target=$TARGET, live_cap=$LIVE_MAX)..."
    KEYS_OUT="$(docker exec -i "$REG_CID" sh -e <<EOF
i=$NEXT_ID
while [ "\$i" -le "$END_ID" ]; do
  if [ \$((i % 5)) -eq 0 ]; then
    kind="server"
    owner="u\$((i - 1))"
  else
    kind="personal"
    owner="u\${i}"
    registrar member add "\$owner" >/dev/null 2>&1 || true
  fi
  key="\$(registrar device key "\$owner" "\$kind" | awk '/^key:/ {print \$2}' | tr -d '\r')"
  printf '%d %s %s\n' "\$i" "\$kind" "\$key"
  i=\$((i + 1))
done
EOF
)"
    ITEMS_FILE="$WORK/items.json"
    printf '[' > "$ITEMS_FILE"
    FIRST=1
    while read -r idx kind key; do
      [ -n "$idx" ] || continue
      keep="false"
      if [ "$LIVE_CUR" -lt "$LIVE_MAX" ]; then
        keep="true"
        LIVE_CUR=$((LIVE_CUR + 1))
      fi
      if [ "$FIRST" -eq 0 ]; then printf ',' >> "$ITEMS_FILE"; fi
      FIRST=0
      printf '{"hostname":"dev-%d","auth_key":"%s","kind":"%s","keep_live":%s}' "$idx" "$key" "$kind" "$keep" >> "$ITEMS_FILE"
    done <<<"$KEYS_OUT"
    printf ']' >> "$ITEMS_FILE"
    NEXT_ID=$((END_ID + 1))

    PAYLOAD="$(jq -nc --slurpfile items "$ITEMS_FILE" --argjson conc "$ENROLL_CONC" '{items: $items[0], concurrency: $conc}')"
    echo >&2 "==> Enrolling $NEED tsnet nodes (conc=$ENROLL_CONC)..."
    RES="$(drv POST /enroll "$PAYLOAD" || echo '{"error":"enroll_failed"}')"
    echo >&2 "    enroll result: $RES"
    reg sync >/dev/null 2>&1 || true
    sleep 2
    CURRENT="$TARGET"
  fi
  measure_stage "$CURRENT"
done
