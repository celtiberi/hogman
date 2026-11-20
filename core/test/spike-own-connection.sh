#!/usr/bin/env bash
# Linux end-to-end spike test for Decision D-10 Option (D):
# own TUN (hogman0 on 198.19.0.0/16) + local split-DNS stub (~<zone>) + tsnet,
# running on the same host as stock tailscaled (netfilter=on) joined to another tailnet.
#
# Intended for Ubuntu 24.04 CI runners (sudo / root, Docker, systemd-resolved, tailscaled).
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/hogman-spike-e2e.XXXXXX")"
export HOGMAN_HOME="$WORK/host"
HOST="$REPO/deploy/hogman-host"
FRONT_CA="$HOGMAN_HOME/front/data/caddy/pki/authorities/local/root.crt"

pass=0; fail=0
SPIKE_PID=""
SBS_PID=""

step()  { echo; echo "== $*"; }
check() {
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS  $d"
    pass=$((pass + 1))
  else
    echo "  FAIL  $d"
    fail=$((fail + 1))
  fi
}
fails() { ! "$@" >/dev/null 2>&1; }
retry() {
  local n="$1"; shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

add_hosts_line() {
  echo "$* # hogman-spike-test" >> /etc/hosts
}

remove_hosts_lines() {
  if grep -q '# hogman-spike-test' /etc/hosts 2>/dev/null; then
    sed -i.bak '/# hogman-spike-test$/d' /etc/hosts && rm -f /etc/hosts.bak
  fi
}

cleanup() {
  set +e
  if [ -n "$SPIKE_PID" ]; then
    kill -TERM "$SPIKE_PID" >/dev/null 2>&1 || true
    wait "$SPIKE_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "$SBS_PID" ]; then
    kill -TERM "$SBS_PID" >/dev/null 2>&1 || true
    wait "$SBS_PID" >/dev/null 2>&1 || true
  fi
  tailscale down >/dev/null 2>&1 || true
  systemctl stop tailscaled >/dev/null 2>&1 || true
  for c in bobo-srv-app bobo-srv work-peer-web work-peer headscale-work; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker network rm spike-work >/dev/null 2>&1 || true
  for n in bobo zebra; do
    (cd "$HOGMAN_HOME/pens/$n" 2>/dev/null && ./hogman down -v --remove-orphans >/dev/null 2>&1) || true
    docker network rm "pen-$n-core" >/dev/null 2>&1 || true
  done
  (cd "$HOGMAN_HOME/front" 2>/dev/null && docker compose down -v >/dev/null 2>&1) || true
  docker network rm hogman-front >/dev/null 2>&1 || true
  rm -f /usr/local/share/ca-certificates/hogman-bobo.hogman.crt /usr/local/share/ca-certificates/hogman-zebra.hogman.crt
  update-ca-certificates --fresh >/dev/null 2>&1 || true
  remove_hosts_lines
  rm -rf "$WORK"
}
trap cleanup EXIT

step "Build hogman-join binary natively"
(cd "$REPO/core/join" && CGO_ENABLED=0 go build -o "$WORK/hogman-join" .) || exit 1
echo "  built $WORK/hogman-join"

step "Start shared front door and two real pens (bobo, zebra)"
mkdir -p "$HOGMAN_HOME/src"
rsync -a --exclude data --exclude .env "$REPO/core/" "$HOGMAN_HOME/src/"
"$HOST" init --test || exit 1
"$HOST" add bobo control.bobo.example || exit 1
"$HOST" add zebra control.zebra.example || exit 1
add_hosts_line "127.0.0.1 control.bobo.example control.zebra.example"

BOBO_INVITE="$("$HOST" pen bobo member add bobo-owner --role owner >/dev/null && "$HOST" pen bobo invite create --note spike | awk '/^link:/ {print $2}')"
ZEBRA_INVITE="$("$HOST" pen zebra member add zebra-owner --role owner >/dev/null && "$HOST" pen zebra invite create --note spike | awk '/^link:/ {print $2}')"
[ -n "$BOBO_INVITE" ] && [ -n "$ZEBRA_INVITE" ] || { echo "failed to mint pen invites" >&2; exit 1; }

step "Start bobo pen server (srv.bobo.hogman) serving TCP, UDP, and 50 MiB HTTP"
BOBO_SRV_KEY="$("$HOST" pen bobo device key bobo-owner server | awk '/^key:/ {print $2}')"
[ -n "$BOBO_SRV_KEY" ] || { echo "failed to mint bobo server key" >&2; exit 1; }
FRONT_IP="$(docker inspect -f '{{(index .NetworkSettings.Networks "hogman-front").IPAddress}}' hogman-front-front-1)"
docker run -d --name bobo-srv --hostname bobo-srv \
  --network hogman-front --add-host "control.bobo.example:$FRONT_IP" \
  --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun:/dev/net/tun \
  -v "$FRONT_CA:/edge-trust/root.crt:ro" \
  -e TS_AUTHKEY="$BOBO_SRV_KEY" -e TS_HOSTNAME=bobo-srv \
  -e TS_STATE_DIR=/var/lib/tailscale -e TS_USERSPACE=false -e TS_ACCEPT_DNS=false \
  -e TS_EXTRA_ARGS="--login-server=https://control.bobo.example" \
  -e SSL_CERT_FILE=/edge-trust/root.crt \
  tailscale/tailscale:v1.104.7 >/dev/null || exit 1

has_bobo_srv_ip() { [ -n "$(docker exec bobo-srv tailscale ip -4 2>/dev/null | head -1 | tr -d '\r')" ]; }
retry 90 has_bobo_srv_ip || { echo "bobo-srv never got mesh IP" >&2; exit 1; }
srv_enrolled() { "$HOST" pen bobo device list | grep -q 'bobo-owner.*server.*bobo-srv'; }
retry 30 srv_enrolled || { echo "registrar did not enroll bobo-srv" >&2; exit 1; }
SRV_DEV_ID="$("$HOST" pen bobo device list | awk '$2 == "bobo-owner" && $3 == "server" && $4 == "bobo-srv" {print $1; exit}')"
"$HOST" pen bobo name claim bobo-owner srv "$SRV_DEV_ID" >/dev/null || exit 1
BOBO_SRV_IP="$(docker exec bobo-srv tailscale ip -4 | head -1 | tr -d '\r')"
echo "  srv.bobo.hogman -> device #$SRV_DEV_ID ($BOBO_SRV_IP)"

docker run -d --name bobo-srv-app --network container:bobo-srv \
  python:3.12-alpine python3 -u -c '
import http.server, socket, threading

def tcp_srv():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 2222))
    s.listen(32)
    while True:
        c, _ = s.accept()
        def handle(conn):
            try:
                chunks = []
                while True:
                    d = conn.recv(65536)
                    if not d:
                        break
                    chunks.append(d)
                conn.sendall(b"tcp:" + b"".join(chunks))
            finally:
                conn.close()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

def udp_srv():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 9999))
    while True:
        d, addr = s.recvfrom(65536)
        s.sendto(b"udp:" + d, addr)

TOTAL = 52428800
CHUNK = b"hogman-throughput-check-01234567" * (65536 // 32)
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        if self.path == "/50m.bin":
            self.send_response(200)
            self.send_header("Content-Length", str(TOTAL))
            self.end_headers()
            rem = TOTAL
            while rem > 0:
                n = min(len(CHUNK), rem)
                self.wfile.write(CHUNK[:n])
                rem -= n
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"srv ok\n")

threading.Thread(target=tcp_srv, daemon=True).start()
threading.Thread(target=udp_srv, daemon=True).start()
http.server.ThreadingHTTPServer(("0.0.0.0", 8088), H).serve_forever()
' >/dev/null || exit 1
retry 30 docker exec bobo-srv sh -c 'nc -z -w2 127.0.0.1 8088 && nc -z -w2 127.0.0.1 2222' || { echo "bobo-srv-app did not listen" >&2; exit 1; }

step "Start separate work tailnet + stock host tailscaled (netfilter=on)"
mkdir -p "$WORK/work-hs/cfg" "$WORK/work-hs/lib" "$WORK/work-hs/run"
cat > "$WORK/work-hs/cfg/policy.hujson" <<'EOF'
{
  "acls": [
    {"action": "accept", "src": ["*"], "dst": ["*:*"]}
  ]
}
EOF
cat > "$WORK/work-hs/cfg/config.yaml" <<'EOF'
server_url: http://work.example:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: true
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: random
derp:
  server:
    enabled: true
    region_id: 998
    region_code: work
    region_name: "work relay"
    verify_clients: true
    stun_listen_addr: 0.0.0.0:3490
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
policy:
  mode: database
dns:
  magic_dns: true
  base_domain: work.ts.internal
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
unix_socket: /var/run/headscale/headscale.sock
logtail:
  enabled: false
EOF

docker network create spike-work >/dev/null || exit 1
docker run -d --name headscale-work --network spike-work \
  -v "$WORK/work-hs/cfg:/etc/headscale:ro" -v "$WORK/work-hs/lib:/var/lib/headscale" -v "$WORK/work-hs/run:/var/run/headscale" \
  headscale/headscale:0.29.7 serve >/dev/null || exit 1
hs_work_ok() { docker exec headscale-work headscale health >/dev/null 2>&1; }
retry 60 hs_work_ok || { echo "headscale-work failed health" >&2; docker logs headscale-work; exit 1; }
HS_WORK_IP="$(docker inspect -f '{{(index .NetworkSettings.Networks "spike-work").IPAddress}}' headscale-work)"
add_hosts_line "$HS_WORK_IP work.example"
docker exec headscale-work headscale policy set --file /etc/headscale/policy.hujson >/dev/null || exit 1
docker exec headscale-work headscale users create workuser >/dev/null || exit 1
WORK_UID="$(docker exec headscale-work headscale users list -o json | jq -r '.[0].id')"
WORK_KEY="$(docker exec headscale-work headscale preauthkeys create --user "$WORK_UID" --reusable --expiration 1h -o json | jq -r .key)"
[ -n "$WORK_KEY" ] && [ "$WORK_KEY" != null ] || { echo "failed work preauthkey" >&2; exit 1; }

docker run -d --name work-peer --hostname work-peer \
  --network spike-work --add-host "work.example:$HS_WORK_IP" \
  --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun:/dev/net/tun \
  -e TS_AUTHKEY="$WORK_KEY" -e TS_HOSTNAME=work-peer \
  -e TS_STATE_DIR=/var/lib/tailscale -e TS_USERSPACE=false -e TS_ACCEPT_DNS=false \
  -e TS_EXTRA_ARGS="--login-server=http://work.example:8080" \
  tailscale/tailscale:v1.104.7 >/dev/null || exit 1
has_work_peer_ip() { [ -n "$(docker exec work-peer tailscale ip -4 2>/dev/null | head -1 | tr -d '\r')" ]; }
retry 90 has_work_peer_ip || { echo "work-peer failed to get IP" >&2; exit 1; }
WORK_PEER_IP="$(docker exec work-peer tailscale ip -4 | head -1 | tr -d '\r')"
docker run -d --name work-peer-web --network container:work-peer \
  python:3.12-alpine python3 -u -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello from work tailnet\n")
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
' >/dev/null || exit 1

# Host stock tailscaled on work tailnet with netfilter enabled (default on Linux).
mkdir -p /etc/default
rm -f /etc/default/tailscaled || true
systemctl restart tailscaled
retry 30 tailscale status >/dev/null 2>&1 || true
tailscale up --login-server="http://work.example:8080" --auth-key="$WORK_KEY" --hostname=runner-host --accept-dns=true || {
  echo "host tailscale up failed" >&2; tailscale status || true; exit 1;
}

cgnat_drop_active() {
  iptables -S ts-input 2>/dev/null | grep -q '100\.64\.0\.0/10' ||
    nft list ruleset 2>/dev/null | grep -q '100\.64\.0\.0/10'
}
work_ip_ok() { curl -sf --max-time 5 "http://$WORK_PEER_IP:8080/" | grep -q "hello from work tailnet"; }
work_dns_ok() { curl -sf --max-time 5 "http://work-peer.work.ts.internal:8080/" | grep -q "hello from work tailnet"; }
check "host stock tailscaled CGNAT drop rule (netfilter=on) is active" retry 15 cgnat_drop_active
check "host tailscaled reaches work-peer IP before spike" retry 30 work_ip_ok
check "host tailscaled resolves & reaches work-peer MagicDNS before spike" retry 30 work_dns_ok

step "Initialize and start Option (D) spike TUN for bobo.hogman + zebra.hogman"
"$WORK/hogman-join" spike-init "$WORK/pen-bobo" "$BOBO_INVITE" --control-ca "$FRONT_CA" --handle spikeuser --hostname runner-spike || exit 1
"$WORK/hogman-join" spike-init "$WORK/pen-zebra" "$ZEBRA_INVITE" --control-ca "$FRONT_CA" --handle spikeuser --hostname runner-spike || exit 1

"$WORK/hogman-join" spike-tun --status-addr 127.0.0.1:19819 "$WORK/pen-bobo" "$WORK/pen-zebra" > "$WORK/spike-tun.log" 2>&1 &
SPIKE_PID=$!

spike_ready() { curl -sf http://127.0.0.1:19819/status | jq -e '.ready == true'; }
if ! retry 90 spike_ready; then
  echo "spike-tun failed to become ready" >&2
  cat "$WORK/spike-tun.log" >&2
  curl -s http://127.0.0.1:19819/status || true
  exit 1
fi
echo "  spike-tun status: $(curl -s http://127.0.0.1:19819/status)"

step "Pass/fail checks with BOTH Option (D) spike AND stock tailscaled active"
no_proxy_fetch() {
  env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    curl -sf --max-time 15 "$1" | grep -q "$2"
}
check "1a. home.bobo.hogman loads over HTTPS without proxy" retry 30 no_proxy_fetch "https://home.bobo.hogman/" "You're in"
check "1b. home.zebra.hogman loads over HTTPS without proxy" retry 30 no_proxy_fetch "https://home.zebra.hogman/" "You're in"
check "1c. home.bobo.hogman resolves into 198.19.x.x (not 100.64.0.0/10)" bash -c 'getent ahostsv4 home.bobo.hogman | awk "{print \$1}" | grep -q "^198\.19\."'

raw_tcp_ok() {
  python3 - <<'PY'
import socket
s = socket.create_connection(("srv.bobo.hogman", 2222), timeout=10)
s.sendall(b"hello-spike-tcp")
s.shutdown(socket.SHUT_WR)
chunks = []
while True:
    d = s.recv(4096)
    if not d:
        break
    chunks.append(d)
s.close()
assert b"".join(chunks) == b"tcp:hello-spike-tcp", chunks
PY
}
raw_udp_ok() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b"hello-spike-udp", ("srv.bobo.hogman", 9999))
data, _ = s.recvfrom(4096)
s.close()
assert data == b"udp:hello-spike-udp", data
PY
}
check "2a. raw non-HTTP TCP to srv.bobo.hogman:2222" retry 30 raw_tcp_ok
check "2b. raw UDP datagram to srv.bobo.hogman:9999" retry 20 raw_udp_ok

check "3a. work-peer IP STILL works simultaneously" retry 10 work_ip_ok
check "3b. work-peer MagicDNS STILL works simultaneously" retry 10 work_dns_ok

dns_isolation_ok() {
  local st_hog st_ts before_q after_q
  st_hog="$(resolvectl status hogman0 2>&1)" || return 1
  grep -q '198\.19\.0\.53' <<<"$st_hog" || return 1
  grep -q '~bobo\.hogman' <<<"$st_hog" || return 1
  grep -q '~zebra\.hogman' <<<"$st_hog" || return 1
  grep -qiE 'Default Route:\s*no|\-DefaultRoute' <<<"$st_hog" || return 1
  st_ts="$(resolvectl status tailscale0 2>&1)" || return 1
  grep -q '100\.100\.100\.100' <<<"$st_ts" || return 1

  before_q="$(curl -sf http://127.0.0.1:19819/status | jq -r .dns_queries)"
  resolvectl query example.com >/dev/null 2>&1 || getent hosts example.com >/dev/null 2>&1 || return 1
  after_q="$(curl -sf http://127.0.0.1:19819/status | jq -r .dns_queries)"
  [ "$before_q" = "$after_q" ]
}
check "4a. DNS isolation: resolvectl scopes ~pen only, tailscale0 100.100.100.100 & public DNS untouched" dns_isolation_ok

routing_isolation_ok() {
  ip route show dev hogman0 | grep -q '^198\.19\.0\.0/16' || return 1
  ! ip route show table 52 2>/dev/null | grep -qE 'hogman0|198\.19\.' || return 1
  cgnat_drop_active
}
check "4b. routing/netfilter isolation: table 52 and CGNAT drop untouched" routing_isolation_ok

step "Throughput & CPU benchmark: Option (D) spike-tun vs side-by-side proxy (50 MiB)"
read_proc_ticks() {
  awk '{
    idx = index($0, ") ");
    rest = substr($0, idx + 2);
    split(rest, a, " ");
    print a[12] + a[13];
  }' "/proc/$1/stat"
}
CLK_TCK="$(getconf CLK_TCK)"

t0_ticks="$(read_proc_ticks "$SPIKE_PID")"
t0_ns="$(date +%s%N)"
curl -sf --max-time 60 -o "$WORK/50m-tun.bin" "http://srv.bobo.hogman:8088/50m.bin"
rc_tun=$?
t1_ns="$(date +%s%N)"
t1_ticks="$(read_proc_ticks "$SPIKE_PID")"
check "5a. 50 MiB HTTP download via spike-tun (52428800 bytes)" test "$rc_tun" = 0 -a "$(wc -c < "$WORK/50m-tun.bin" | tr -d ' ')" = 52428800
TUN_METRICS="$(python3 -c "
dt = ($t1_ns - $t0_ns) / 1e9
cpu = ($t1_ticks - $t0_ticks) / $CLK_TCK
mbps = (52428800 / (1024*1024)) / dt
print(f'spike-tun: {dt:.3f}s  {mbps:.2f} MiB/s  cpu={cpu:.3f}s')
")"
echo "  BENCH $TUN_METRICS"

step "Clean teardown check (SIGTERM)"
kill -TERM "$SPIKE_PID"
wait "$SPIKE_PID" >/dev/null 2>&1 || true
SPIKE_PID=""
check "6a. hogman0 interface gone after leave/SIGTERM" fails ip link show hogman0
check "6b. 198.19.0.0/16 route gone after teardown" bash -c "! ip route show | grep -q '198\.19\.'"
check "6c. resolvectl has no hogman0 after teardown" fails resolvectl status hogman0
check "6d. work-peer MagicDNS STILL works after spike teardown" work_dns_ok

step "Side-by-side baseline throughput & CPU benchmark (50 MiB)"
mkdir -p "$WORK/pen-bobo-sbs"
cp -a "$WORK/pen-bobo/." "$WORK/pen-bobo-sbs/"
python3 - <<PY
import json
p = "$WORK/pen-bobo-sbs/config.json"
d = json.load(open(p))
d["proxy_addr"] = "127.0.0.1:18999"
json.dump(d, open(p, "w"))
PY
"$WORK/hogman-join" agent "$WORK/pen-bobo-sbs" > "$WORK/sbs.log" 2>&1 &
SBS_PID=$!
sbs_up() { curl -sf http://127.0.0.1:18999/status | jq -e '.up == true'; }
if retry 90 sbs_up; then
  s0_ticks="$(read_proc_ticks "$SBS_PID")"
  s0_ns="$(date +%s%N)"
  http_proxy="http://127.0.0.1:18999" curl -sf --max-time 60 -o "$WORK/50m-sbs.bin" "http://srv.bobo.hogman:8088/50m.bin"
  rc_sbs=$?
  s1_ns="$(date +%s%N)"
  s1_ticks="$(read_proc_ticks "$SBS_PID")"
  check "5b. 50 MiB HTTP download via side-by-side proxy (52428800 bytes)" test "$rc_sbs" = 0 -a "$(wc -c < "$WORK/50m-sbs.bin" | tr -d ' ')" = 52428800
  SBS_METRICS="$(python3 -c "
dt = ($s1_ns - $s0_ns) / 1e9
cpu = ($s1_ticks - $s0_ticks) / $CLK_TCK
mbps = (52428800 / (1024*1024)) / dt
print(f'side-by-side: {dt:.3f}s  {mbps:.2f} MiB/s  cpu={cpu:.3f}s')
")"
  echo "  BENCH $SBS_METRICS"
else
  echo "  FAIL  side-by-side agent failed to start for benchmark"
  fail=$((fail + 1))
fi

echo
echo "=== SPIKE DIAGNOSTICS ==="
echo "  $TUN_METRICS"
echo "  ${SBS_METRICS:-side-by-side: N/A}"
echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
