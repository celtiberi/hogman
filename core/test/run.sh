#!/usr/bin/env bash
# End-to-end test of the core stack and registrar on one machine.
# Needs Docker and jq.
#
# Deploys a throwaway network "bobo" in a temporary copy of core/, then plays
# out the life of a small network: the owner invites alice (admin) and bob,
# they redeem the invites from "the internet", alice adds a server and claims
# names for it, someone sneaks a device in around the registrar, bob gets
# suspended and resumed, and alice gets kicked.
#
# usage: test/run.sh [--keep]     --keep leaves the stack running afterwards
set -uo pipefail
# shellcheck source=/dev/null
. "$(dirname "$0")/e2e-lock.sh"
e2e_lock

SRC="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$SRC/.." && pwd)"
KEEP=false; [ "${1:-}" = --keep ] && KEEP=true
WORK="$(mktemp -d "${TMPDIR:-/tmp}/hogman-test.XXXXXX")"
export COMPOSE_PROJECT_NAME=hogman-test
ACME="$WORK/acme"
export ACME_DIR="$ACME"
ROOT=/acme/issued-root.crt
ZONE=bobo.pens.hogman.test
PUBLIC_HOST=bobo.gate.hogman.test

pass=0; fail=0
step()  { echo; echo "== $*"; }
check() {   # check <description> <command...>
  local d="$1" log="$WORK/.check.out"; shift
  if "$@" >"$log" 2>&1; then echo "  PASS  $d"; pass=$((pass + 1))
  else
    echo "  FAIL  $d"; fail=$((fail + 1))
    [ -s "$log" ] && tail -n 5 "$log" | sed 's/^/        | /'
  fi
}
retry() {   # retry <seconds> <command...>
  local n="$1"; shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
timed() {   # timed <var> <seconds> <command...>: retry, store elapsed seconds in <var>
  local var="$1" n="$2" t0 rc; shift 2
  t0="$(date +%s)"; retry "$n" "$@"; rc=$?
  printf -v "$var" '%s' "$(( $(date +%s) - t0 ))"
  return $rc
}
not() { ! "$@"; }
# Capture command stdout before grepping: under pipefail, piping docker exec /
# curl directly into `grep -q` closes the pipe on the first match and makes the
# producer exit 255/141 (EPIPE/SIGPIPE).
match() {    # match <grep-pattern> <command...>
  local pat="$1" out; shift
  out="$("$@")" || return 1
  grep -q -- "$pat" <<<"$out"
}
no_match() { # no_match <grep-pattern> <command...>: command succeeds and stdout does not match
  local pat="$1" out; shift
  out="$("$@")" || return 1
  ! grep -q -- "$pat" <<<"$out"
}

cleanup() {
  if [ "$KEEP" = true ]; then
    echo; echo "Stack left running in $WORK"
    echo "  cd there, export COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME ACME_DIR=$ACME, then ./hogman <command>; ./hogman down -v to stop"
  else
    docker rm -f hogman-run-cdns hogman-run-pebble \
      "hogman-e2e-sidecar-$$" "hogman-e2e-bridge-$$" "hogman-e2e-app-$$" >/dev/null 2>&1 || true
    docker volume rm -f "hogman-e2e-state-$$" "hogman-e2e-in-$$" >/dev/null 2>&1 || true
    docker rmi -f "hogman-sidecar-e2e:$$" >/dev/null 2>&1 || true
    dc down -v -t 1 --remove-orphans >/dev/null 2>&1
    docker network rm "${COMPOSE_PROJECT_NAME}_core" hogman-test-acme >/dev/null 2>&1 || true
    rm -rf "$WORK"
  fi
}
trap 'cleanup; e2e_unlock' EXIT

step "Challenge DNS and test public CA (Pebble)"
if [ "$(uname -s)" != Linux ]; then
  echo "  SKIP  Linux required (Unix socket bind mounts for challenge-dns); CI runs this suite"
  exit 0
fi

mkdir -p "$ACME/cdns" "$ACME/sock" "$ACME/certs"
if [ "$(id -u)" = 0 ]; then chgrp 65532 "$ACME/sock"; fi
chmod 0750 "$ACME/sock"

case "$(uname -m)" in x86_64|amd64) HOST_GOARCH=amd64 ;; aarch64|arm64) HOST_GOARCH=arm64 ;; *) HOST_GOARCH="" ;; esac
if [ -n "$HOST_GOARCH" ] && [ -f "$SRC/prebuilt/challenge-dns/challenge-dns-linux-$HOST_GOARCH" ]; then
  install -m 0755 "$SRC/prebuilt/challenge-dns/challenge-dns-linux-$HOST_GOARCH" "$ACME/cdns/challenge-dns"
else
  docker run --rm -v "$REPO/deploy/challenge-dns:/src:ro" -v "$ACME/cdns:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false golang:1.27-alpine go build -o /out/challenge-dns . || exit 1
fi
docker network inspect hogman-test-acme >/dev/null 2>&1 || docker network create hogman-test-acme >/dev/null
docker rm -f hogman-run-cdns hogman-run-pebble >/dev/null 2>&1 || true
docker run -d --name hogman-run-cdns --network hogman-test-acme \
  -v "$ACME/cdns:/cdns" -v "$ACME/sock:/run/hogman-acme" \
  -e CDNS_LISTEN=0.0.0.0:53 -e CDNS_PENS_ZONE=pens.hogman.test -e CDNS_GATE_NAME=_acme-challenge.gate.hogman.test \
  -e CDNS_STATE=/cdns/state.json -e CDNS_API_SOCK=/run/hogman-acme/api.sock -e CDNS_ADMIN_SOCK=/cdns/admin.sock \
  -e CDNS_HOURLY_CAP=10 \
  alpine:3.22 /cdns/challenge-dns serve >/dev/null
retry 20 env CDNS_ADMIN_SOCK="$ACME/cdns/admin.sock" "$ACME/cdns/challenge-dns" cred list || exit 1

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$ACME/certs/ca.key" -out "$ACME/certs/ca.crt" \
  -days 2 -subj "/CN=hogman-test-ca" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$ACME/certs/server.key" -out "$ACME/certs/server.csr" -subj "/CN=pebble" >/dev/null 2>&1
printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pebble\n' > "$ACME/certs/ext.cnf"
openssl x509 -req -in "$ACME/certs/server.csr" -CA "$ACME/certs/ca.crt" -CAkey "$ACME/certs/ca.key" -CAcreateserial \
  -out "$ACME/certs/server.crt" -days 2 -extfile "$ACME/certs/ext.cnf" >/dev/null 2>&1
chmod 644 "$ACME/certs/"*
cat > "$ACME/pebble.json" <<'JSON'
{"pebble": {"listenAddress": "0.0.0.0:14000", "managementListenAddress": "0.0.0.0:15000",
  "certificate": "/certs/server.crt", "privateKey": "/certs/server.key", "httpPort": 5002, "tlsPort": 5001,
  "externalAccountBindingRequired": false, "retryAfter": {"authz": 1, "order": 1}, "keyAlgorithm": "ecdsa"}}
JSON
docker run -d --name hogman-run-pebble --network hogman-test-acme --network-alias pebble -e PEBBLE_VA_NOSLEEP=1 \
  -v "$ACME/certs:/certs:ro" -v "$ACME/pebble.json:/pebble.json:ro" \
  ghcr.io/letsencrypt/pebble:2.10.3 -config /pebble.json -dnsserver hogman-run-cdns:53 >/dev/null
# Connect Pebble and challenge-dns to the pen's single core network so registrar
# stays single-homed (matching production) while still reaching the test CA/DNS.
docker network inspect "${COMPOSE_PROJECT_NAME}_core" >/dev/null 2>&1 || docker network create "${COMPOSE_PROJECT_NAME}_core" >/dev/null
docker network connect "${COMPOSE_PROJECT_NAME}_core" hogman-run-cdns >/dev/null 2>&1 || true
docker network connect --alias pebble "${COMPOSE_PROJECT_NAME}_core" hogman-run-pebble >/dev/null 2>&1 || true
retry 30 docker run --rm --network hogman-test-acme -v "$ACME/certs:/c:ro" nicolaka/netshoot:v0.14 \
  curl -sf --cacert /c/ca.crt https://pebble:14000/dir || exit 1
docker run --rm --network hogman-test-acme -v "$ACME/certs:/c:ro" nicolaka/netshoot:v0.14 \
  curl -sf --cacert /c/ca.crt https://pebble:15000/roots/0 > "$ACME/issued-root.crt" || exit 1
cat "$ACME/certs/ca.crt" "$ACME/issued-root.crt" > "$ACME/bundle.crt"
chmod 644 "$ACME/issued-root.crt" "$ACME/bundle.crt"

rsync -a --exclude data --exclude .env "$SRC/" "$WORK/"
cd "$WORK"
cat > .env <<EOF
NETWORK=bobo
ZONE=$ZONE
PUBLIC_HOST=$PUBLIC_HOST
PUBLIC_IPV4=
TEST_MODE=true
HOGMAN_ACME_SOCK_DIR=$ACME/sock
ACME_CA_URL=https://pebble:14000/dir
ACME_RESOLVERS=hogman-run-cdns:53
HOGMAN_TEST_ACME_ROOT=$ACME/certs/ca.crt
EOF
export HOGMAN_TEST_ACME_ROOT="$ACME/certs/ca.crt"

H=./hogman
dc() {
  local envs=(--env-file .env)
  [ -f data/state.env ] && envs+=(--env-file data/state.env)
  ZONE=$ZONE EDGE_TLS_MODE=local_certs ACME_DIR="$ACME" HOGMAN_TEST_ACME_ROOT="$ACME/certs/ca.crt" \
    docker compose "${envs[@]}" -f compose.yaml -f test/compose.test.yaml -f test/compose.acme-root.yaml --profile clients "$@"
}
run()   { local c="$1"; shift; dc exec -T "$c" "$@"; }
ip_of() {
  local out line
  out="$(run "$1" tailscale ip -4 2>/dev/null)" || return 1
  IFS= read -r line <<<"${out//$'\r'/}"
  printf '%s\n' "$line"
}
has_ip(){ [ -n "$(ip_of "$1")" ]; }

# --- from "the internet": a machine that can reach only the public edge ---
redeem() {  # redeem <token> <handle>  -> prints "<http status> <json>"
  docker run --rm --network "${COMPOSE_PROJECT_NAME}_outside" \
    -v "$WORK/data/edge-trust:/t:ro" nicolaka/netshoot:v0.14 \
    curl -s -w ' %{http_code}' --cacert /t/root.crt -X POST "https://$PUBLIC_HOST/hogman/v1/redeem" \
      -H 'content-type: application/json' -d "{\"token\":\"$1\",\"handle\":\"$2\"}"
}

# --- the portal API, called from a device on the mesh ----------------------
api() {     # api <tools-container> <METHOD> <path> [json]  -> body; fails on non-2xx
  run "$1" curl -sf -m5 --cacert $ROOT -X "$2" "https://home.$ZONE$3" \
    -H 'content-type: application/json' ${4:+-d "$4"}
}
api_blocked() {  # expected-blocked probe with shorter timeout (packets are dropped by ACL)
  run "$1" curl -sf -m2 --cacert $ROOT -X "$2" "https://home.$ZONE$3" \
    -H 'content-type: application/json' ${4:+-d "$4"}
}
api_status() {  # api_status <tools-container> <METHOD> <path> [json] -> HTTP status
  run "$1" curl -s -m5 -o /dev/null -w '%{http_code}' --cacert $ROOT -X "$2" "https://home.$ZONE$3" \
    -H 'content-type: application/json' ${4:+-d "$4"}
}
api_raw_status() {  # api_raw_status <tools-container> <METHOD> <path> <curl args...> -> HTTP status
  local c="$1" m="$2" p="$3"; shift 3
  run "$c" curl -s -m5 -o /dev/null -w '%{http_code}' --cacert $ROOT -X "$m" "https://home.$ZONE$p" "$@" \
    | tr -d '\r' | tail -c 3
}
status_is() { [ "$(api_status "$@" 2>/dev/null | tail -c 3)" = "$EXPECT" ]; }
expect() { EXPECT="$1"; shift; status_is "$@"; }

resolves_to() {
  local out
  out="$(run bob-tools dig +short "$1")" || return 1
  grep -qx -- "$2" <<<"${out//$'\r'/}"
}
resolves_none(){ [ -z "$(run bob-tools dig +short "$1" | tr -d '\r')" ]; }
resolves_any() { match . run bob-tools dig +short "$1"; }
refused()      { match REFUSED run bob-tools dig "@$CORE_MESH_IP" "$1"; }
fetch() {
  local body
  body="$(run "${FROM:-bob-tools}" curl -sf -m3 --cacert $ROOT "https://$1")" || return 1
  grep -q "$2" <<<"$body"
}
can_ping()     { run "$1" ping -c2 -W2 "$2"; }
port_open()    { run "$1" nc -z -w3 "$2" "$3"; }
has_device()   { match "$1" $H device list; }
no_device_of() {
  local out
  out="$($H device list)" || return 1
  ! awk -v u="$1" '$2 == u { found=1 } END { exit !found }' <<<"$out"
}
cert_verifies() {
  run bob-tools sh -c "echo | openssl s_client -connect $1:443 -servername $1 -CAfile $ROOT -verify_return_error >/dev/null 2>&1"
}

# ===========================================================================

step "Deploy"
$H init || exit 1
cdns_out="$(CDNS_ADMIN_SOCK="$ACME/cdns/admin.sock" "$ACME/cdns/challenge-dns" cred add pen bobo)" || exit 1
cdns_tok="$(awk '/^token:/ {print $2}' <<<"$cdns_out")"
[ -n "$cdns_tok" ] || exit 1
install -d -m 0700 "$WORK/data/secrets/registrar"
( umask 077; printf '%s' "$cdns_tok" > "$WORK/data/secrets/registrar/challenge_dns_token" )
$H up   || exit 1
. ./data/state.env
check "the registrar is up and in sync" $H sync
check "the owner is created" $H member add root --role owner

step "Invites, redeemed from the internet"
token_of() { awk '/^token:/ {print $2}'; }
ALICE_TOKEN="$($H invite create --role admin --note "alice, colleague" | token_of)"
BOB_TOKEN="$($H invite create --note "bob" | token_of)"
check "owner minted two invites" test -n "$ALICE_TOKEN" -a -n "$BOB_TOKEN"

r="$(redeem "$ALICE_TOKEN" alice)"; alice_json="${r% *}"
check "alice redeems her invite (HTTP ${r##* })" test "${r##* }" = 201
ALICE_LAPTOP_KEY="$(jq -r .auth_key <<<"$alice_json")"
check "the enrolment carries the public zone without root fingerprint" \
  jq -e --arg z "$ZONE" '.zone == $z and (.root_fingerprint // "") == "" and (.root_ca // "") == ""' <<<"$alice_json"
check "the enrolment carries the control server" test "$(jq -r .login_server <<<"$alice_json")" = "https://$PUBLIC_HOST"
r="$(redeem "$ALICE_TOKEN" mallory)"
check "an invite works only once (HTTP ${r##* })" test "${r##* }" = 403
r="$(redeem "hmi_notarealtoken" mallory)"
check "a made-up invite is refused (HTTP ${r##* })" test "${r##* }" = 403
r="$(redeem "$BOB_TOKEN" alice)"
check "a taken handle is refused (HTTP ${r##* })" test "${r##* }" = 409
r="$(redeem "$BOB_TOKEN" bob)"; BOB_LAPTOP_KEY="$(jq -r .auth_key <<<"${r% *}")"
check "bob redeems his invite (HTTP ${r##* })" test "${r##* }" = 201
check "both invites now show as redeemed" test "$($H invite list | grep -c redeemed)" = 2

step "Devices join; the registrar recognises them"
# A device added straight through Headscale, around the registrar.
STRAY_KEY="$($H headscale preauthkeys create --tags tag:server --expiration 1h --output json | jq -r .key)"
export ALICE_LAPTOP_KEY BOB_LAPTOP_KEY STRAY_KEY
dc up -d alice-laptop bob-laptop stray-device alice-laptop-tools bob-tools stray-tools
for d in alice-laptop bob-laptop stray-device; do retry 90 has_ip $d; done
ALICE_LAPTOP_IP="$(ip_of alice-laptop)"; BOB_LAPTOP_IP="$(ip_of bob-laptop)"; STRAY_IP="$(ip_of stray-device)"
both_laptops() {
  local out
  out="$($H device list)" || return 1
  grep -q 'alice.*personal' <<<"$out" && grep -q 'bob.*personal' <<<"$out"
}
check "alice's and bob's laptops are recorded as theirs" retry 20 both_laptops
retry 30 api alice-laptop-tools GET /api/me
me="$(api alice-laptop-tools GET /api/me)"
check "the portal knows alice from her mesh address (alice, admin)" \
  test "$(jq -r '.member.handle + "/" + .member.role' <<<"$me")" = alice/admin
me="$(api bob-tools GET /api/me)"
check "... and bob from his (bob, member)" test "$(jq -r '.member.handle + "/" + .member.role' <<<"$me")" = bob/member

# D-35 grace-period banner + in-pen signed renewal token (owners/admins only).
printf '{"pen":"bobo","state":"grace","grace_until":"2027-12-24T00:00:00Z","renew_url":"https://get.example.com"}\n' \
  > "$WORK/data/registrar/billing-status.json"
chmod 0644 "$WORK/data/registrar/billing-status.json"
me_grace_alice="$(api alice-laptop-tools GET /api/me)"
me_grace_bob="$(api bob-tools GET /api/me)"
check "alice (admin) sees grace status with can_renew=true in /api/me" \
  jq -e '.billing.state == "grace" and .billing.can_renew == true' <<<"$me_grace_alice"
check "bob (non-admin member) sees grace status without can_renew in /api/me" \
  jq -e '.billing.state == "grace" and (.billing.can_renew // false) == false' <<<"$me_grace_bob"
check "bob (non-admin) cannot mint a renewal token (403)" \
  expect 403 bob-tools POST /api/billing/renew-token '{}'
renew_tok="$(api alice-laptop-tools POST /api/billing/renew-token '{}')"
check "alice (admin) mints a signed fragment renewal URL" \
  jq -e '.url | startswith("https://get.example.com/#renew=")' <<<"$renew_tok"
# Verify registrar created a 0600 renew.key and that the minted token's HMAC matches it (host/broker compatibility).
renew_verify_hmac() {
  local tok payload sig key_hex expected
  [ "$(stat -c '%a' "$WORK/data/registrar/renew.key")" = "600" ] || return 1
  tok="$(jq -r '.url | split("#renew=")[1]' <<<"$renew_tok")"
  payload="${tok%%.*}"; sig="${tok#*.}"
  key_hex="$(tr -d ' \r\n' < "$WORK/data/registrar/renew.key")"
  expected="$(printf 'hogman-renew-v1:%s' "$payload" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  [ -n "$expected" ] && [ "$sig" = "$expected" ]
}
check "registrar wrote 0600 renew.key and minted token HMAC verifies against it" renew_verify_hmac
rm -f "$WORK/data/registrar/billing-status.json" "$WORK/data/registrar/renew.key"
me_clear="$(api bob-tools GET /api/me)"
check "removing billing-status.json clears /api/me billing field" \
  jq -e '.billing == null' <<<"$me_clear"

step "Alice adds a server and shares a site"
srv="$(api alice-laptop-tools POST /api/devices '{"kind":"server"}')"
ALICE_SERVER_KEY="$(jq -r .auth_key <<<"$srv")"
check "alice gets a server key from the portal" test -n "$ALICE_SERVER_KEY" -a "$ALICE_SERVER_KEY" != null
check "the device link carries no fingerprint" bash -c '! grep -q "fp=" <<<"$1"' _ "$(jq -r .join_link <<<"$srv")"
check "the device link comes with a QR code drawn inside the pen" grep -q '^<svg ' <<<"$(jq -r .join_qr_svg <<<"$srv")"
portal_has_ui() {
  local body
  body="$(run alice-laptop-tools curl -sf -m5 --cacert $ROOT "https://home.$ZONE/")" || return 1
  grep -q 'id="add-personal"' <<<"$body"
}
check "the portal offers 'Add a device'" portal_has_ui
portal_hdrs="$(run alice-laptop-tools curl -sI -m5 --cacert $ROOT "https://home.$ZONE/" | tr -d '\r')"
check "the portal sets anti-framing headers" bash -c "grep -iq '^x-frame-options: DENY' <<<\"\$1\" && grep -iq \"^content-security-policy:.*frame-ancestors 'none'\" <<<\"\$1\"" _ "$portal_hdrs"
portal_assets_ok() {
  run alice-laptop-tools curl -sf -m5 --cacert $ROOT "https://home.$ZONE/portal.js" >/dev/null &&
    run alice-laptop-tools curl -sf -m5 --cacert $ROOT "https://home.$ZONE/portal.css" >/dev/null
}
check "portal external JS/CSS load" portal_assets_ok
export ALICE_SERVER_KEY
dc up -d alice-server alice-tools
retry 90 has_ip alice-server; ALICE_SERVER_IP="$(ip_of alice-server)"
docker exec -d "$(dc ps -q alice-tools)" sh -c 'while true; do nc -l -p 443 >/dev/null 2>&1 || nc -l 443 >/dev/null 2>&1; done'
docker exec -d "$(dc ps -q alice-tools)" sh -c 'while true; do nc -l -p 2222 >/dev/null 2>&1 || nc -l 2222 >/dev/null 2>&1; done'
check "her server is recorded as hers" retry 20 match 'alice.*server' $H device list
SERVER_ID="$(api alice-laptop-tools GET /api/me | jq -r '.devices[] | select(.kind=="server") | .id')"
echo "  core=$CORE_MESH_IP alice-laptop=$ALICE_LAPTOP_IP bob-laptop=$BOB_LAPTOP_IP alice-server=$ALICE_SERVER_IP (#$SERVER_ID) stray=$STRAY_IP"
LAPTOP_ID="$(api alice-laptop-tools GET /api/me | jq -r '.devices[] | select(.kind=="personal") | .id')"
check "a name can't point at a personal device"  expect 400 alice-laptop-tools POST /api/names "{\"name\":\"srv\",\"device_id\":$LAPTOP_ID}"
check "a sub-name needs its parent claimed first" expect 403 alice-laptop-tools POST /api/names "{\"name\":\"sub.srv\",\"device_id\":$SERVER_ID}"
check "alice claims srv.$ZONE"      expect 201 alice-laptop-tools POST /api/names "{\"name\":\"srv\",\"device_id\":$SERVER_ID}"
check "alice claims sub.srv.$ZONE" expect 201 alice-laptop-tools POST /api/names "{\"name\":\"sub.srv\",\"device_id\":$SERVER_ID}"
check "reserved names are refused"    expect 403 alice-laptop-tools POST /api/names "{\"name\":\"home\",\"device_id\":$SERVER_ID}"
check "bob can't take srv"          expect 409 bob-tools POST /api/names "{\"name\":\"srv\",\"device_id\":$SERVER_ID}"
check "bob can't point a name at alice's server" expect 400 bob-tools POST /api/names "{\"name\":\"bobsite\",\"device_id\":$SERVER_ID}"

srv_share="$(api alice-laptop-tools POST /api/devices '{"kind":"server"}')"
ALICE_SHARE_LINK="$(jq -r .join_link <<<"$srv_share")"
dc up -d alice-share
retry 20 run alice-share test -s /etc/ssl/certs/ca-certificates.crt
run alice-share sh -c 'mkdir -p /tmp/www && echo "hello from alice.'"$ZONE"'" > /tmp/www/index.html'
out="$(run alice-share sh -c '"/dl/hogman-$(uname -s)-$(uname -m)" --no-open share alice /tmp/www "$1" --background' _ "$ALICE_SHARE_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "alice shares https://alice.$ZONE with hogman share (exit $rc)" grep -q "https://alice.$ZONE is up" <<<"$out"

step "Naming"
check "bob resolves srv.$ZONE to alice's server" retry 30 resolves_to srv.$ZONE "$ALICE_SERVER_IP"
check "bob resolves alice.$ZONE to alice's share" retry 30 resolves_any alice.$ZONE
check "bob resolves home.$ZONE to the core node"   resolves_to home.$ZONE "$CORE_MESH_IP"
check "ca.$ZONE has no DNS record"                 resolves_none ca.$ZONE
dns_aaaa_nodata() {
  local name="$1" out
  out="$(run bob-tools dig "@$CORE_MESH_IP" AAAA "$name" | tr -d '\r')" || return 1
  grep -q 'status: NOERROR' <<<"$out" &&
    grep -q 'flags:.*aa' <<<"$out" &&
    grep -q 'ANSWER: 0,' <<<"$out" &&
    grep -q 'AUTHORITY: 1,' <<<"$out"
}
check "IPv4-only DNS: AAAA for home.$ZONE returns NOERROR NODATA" dns_aaaa_nodata "home.$ZONE"
check "IPv4-only DNS: AAAA for srv.$ZONE returns NOERROR NODATA"  dns_aaaa_nodata "srv.$ZONE"
check "IPv4-only DNS: AAAA for alice.$ZONE returns NOERROR NODATA" dns_aaaa_nodata "alice.$ZONE"
split_dns_v4_only() {
  local ns
  ns="$(awk '/split:/{flag=1; next} flag && /^  [^ ]/{exit} flag && /- /{print $2}' "$WORK/data/headscale/config/config.yaml")"
  [ "$ns" = "$CORE_MESH_IP" ] && ! grep -q ':' <<<"$ns"
}
check "Headscale split-DNS hands clients only core's IPv4 resolver" split_dns_v4_only
check "device names work (alice-server.nodes.$ZONE)" resolves_to alice-server.nodes.$ZONE "$ALICE_SERVER_IP"
check "ordinary names still resolve (example.com)" resolves_any example.com
check "the network's DNS refuses outside names (not an open resolver)" refused example.com
in_directory() { match "$1" api bob-tools GET /api/directory; }
check "the directory lists alice's server sub-name" in_directory "sub.srv.$ZONE"
check "the directory lists alice's shared site"     in_directory "alice.$ZONE"

step "Public HTTPS certificates (ACME DNS-01)"
check "there is no step-ca container"            not docker inspect "$COMPOSE_PROJECT_NAME-step-ca-1"
check "there is no private PKI directory"        test ! -e "$WORK/data/pki"
check "portal https://home.$ZONE answers"        retry 60 fetch home.$ZONE "You're in"
check "portal certificate verifies against test public CA" cert_verifies "home.$ZONE"
check "alice's site https://alice.$ZONE answers" retry 150 fetch alice.$ZONE "hello from alice.$ZONE"
check "alice's site certificate verifies against test public CA" cert_verifies "alice.$ZONE"

step "Default-deny access policy"
# HTTPS only (D-11): members reach servers on 443 and nothing else.
check "bob's laptop can reach alice's server on 443"     retry 20 port_open bob-tools "$ALICE_SERVER_IP" 443
# Run independent read-only negative connectivity probes in parallel so we keep
# full 3s nc timeouts without burning 18s serially.
_pd="$WORK/.probes"; rm -rf "$_pd"; mkdir -p "$_pd"
CORE_MESH_IPV6="$($H headscale nodes list --output json | jq -r --arg ip "$CORE_MESH_IP" '.[] | (.ip_addresses // .ipAddresses // []) | select(index($ip) != null) | .[] | select(contains(":"))' | tr -d '\r' | head -n1)"
ALICE_SHARE_IP=""
for _ in $(seq 10); do
  ALICE_SHARE_IP="$(run bob-tools dig +short "alice.$ZONE" | tr -d '\r' | grep -E '^[0-9.]+$' | head -n1)"
  [ -n "$ALICE_SHARE_IP" ] && break
  sleep 1
done
ALICE_SHARE_IPV6="$($H headscale nodes list --output json | jq -r --arg ip "$ALICE_SHARE_IP" '.[] | (.ip_addresses // .ipAddresses // []) | select(index($ip) != null) | .[] | select(contains(":"))' | tr -d '\r' | head -n1)"
port_blocked_v6() {
  local c="$1" ip="$2" port="$3" route out rc
  if [ -z "$ip" ]; then
    echo "missing target IPv6 address"
    return 1
  fi
  route="$(run "$c" ip -6 route get "$ip" 2>&1)" || { echo "no IPv6 route to $ip: $route"; return 1; }
  if ! grep -q 'tailscale0' <<<"$route"; then
    echo "IPv6 route for $ip does not use tailscale0: $route"
    return 1
  fi
  out="$(run "$c" nc -6 -v -z -w3 "$ip" "$port" 2>&1)"; rc=$?
  if [ "$rc" = 0 ]; then
    echo "unexpected IPv6 connection succeeded to [$ip]:$port: $out"
    return 1
  fi
  if grep -iqE 'unreachable|not supported|cannot assign|invalid' <<<"$out"; then
    echo "IPv6 probe failed before WireGuard ACLs: $out"
    return 1
  fi
  return 0
}
( not port_open bob-tools "$ALICE_SERVER_IP" 80   >"$_pd/p1.out" 2>&1; echo $? >"$_pd/p1.rc" ) &
( not port_open bob-tools "$ALICE_SERVER_IP" 2222 >"$_pd/p2.out" 2>&1; echo $? >"$_pd/p2.rc" ) &
( not port_open bob-tools "$CORE_MESH_IP" 9000    >"$_pd/p3.out" 2>&1; echo $? >"$_pd/p3.rc" ) &
( not port_open bob-tools "$ALICE_LAPTOP_IP" 443  >"$_pd/p4.out" 2>&1; echo $? >"$_pd/p4.rc" ) &
( not port_open alice-tools "$BOB_LAPTOP_IP" 443  >"$_pd/p5.out" 2>&1; echo $? >"$_pd/p5.rc" ) &
( not port_open bob-tools "$CORE_MESH_IP" 22      >"$_pd/p6.out" 2>&1; echo $? >"$_pd/p6.rc" ) &
( port_blocked_v6 bob-tools "$CORE_MESH_IPV6" 443   >"$_pd/p7.out" 2>&1; echo $? >"$_pd/p7.rc" ) &
( port_blocked_v6 bob-tools "$ALICE_SHARE_IPV6" 443 >"$_pd/p8.out" 2>&1; echo $? >"$_pd/p8.rc" ) &
wait
probe_ok() { local rc; rc="$(cat "$_pd/$1.rc" 2>/dev/null || echo 1)"; [ "$rc" = 0 ] || { cat "$_pd/$1.out" 2>/dev/null; return 1; }; }
check "... but not on 80"                                 probe_ok p1
check "... but on no other port (2222 is open there)"    probe_ok p2
# (Ping still answers: Tailscale's filter lets ICMP through between devices
# allowed any port. It can't carry data, so it isn't a way in.)
check "the server itself has 2222 open (so the above means something)" run alice-tools nc -z -w3 127.0.0.1 2222
check "bob's laptop cannot reach retired CA port 9000"     probe_ok p3
check "bob's laptop cannot reach alice's laptop"         probe_ok p4
check "alice's server cannot reach bob's laptop"         probe_ok p5
check "members cannot reach other ports on the core (22)" probe_ok p6
check "active Headscale policy contains no IPv6 addresses" no_match 'fd7a:' $H headscale policy get
check "mesh IPv6 is default-deny: bob cannot reach core over IPv6 :443"         probe_ok p7
check "mesh IPv6 is default-deny: bob cannot reach alice's share over IPv6 :443" probe_ok p8
check "bob can't use the admin API"   expect 403 bob-tools GET /api/admin/members
check "alice (admin) can"             expect 200 alice-laptop-tools GET /api/admin/members
page_invite() {  # an invite made from the home page comes with its link and QR code
  api alice-laptop-tools POST /api/invites '{"note":"from the page"}' \
    | jq -e --arg h "$PUBLIC_HOST" '(.url | startswith("https://\($h)/join#t=")) and (.qr_svg | startswith("<svg"))'
}
check "alice (admin) makes an invite from the home page" page_invite
invite_open()  { match 'open.*from the page' $H invite list; }
offers_keeper(){ api "$1" GET /api/me | jq -e '.can_invite and .is_admin'; }
offers_none()  { api "$1" GET /api/me | jq -e '(.can_invite or .is_admin) | not'; }
check "the ledger lists it as open"   invite_open
check "the home page offers alice the keeper controls" offers_keeper alice-laptop-tools
check "and offers bob neither"        offers_none bob-tools
check "the home page has the herd"    fetch "home.$ZONE" 'The herd'
check "the home page has the pen directory" fetch "home.$ZONE" 'Sites in this pen'
herd_finds_bob() {  # searched on the registrar, with his devices counted
  api alice-laptop-tools GET '/api/admin/herd?q=bo' | jq -e '.total >= 1 and any(.members[]; .handle == "bob" and .devices >= 1)'
}
check "alice finds bob in the herd, devices counted" herd_finds_bob
check "bob can't list the herd"       expect 403 bob-tools GET /api/admin/herd
check "alice's server can read /api/me"        expect 200 alice-tools GET /api/me
check "alice's server can read /api/directory" expect 200 alice-tools GET /api/directory
check "alice's server cannot use the admin API"   expect 403 alice-tools GET /api/admin/members
check "alice's server cannot issue device keys"   expect 403 alice-tools POST /api/devices '{"kind":"personal"}'
check "alice's server cannot claim names"         expect 403 alice-tools POST /api/names '{"name":"x","device_id":1}'
check "mesh API rejects text/plain CSRF attempts (415)" \
  test "$(api_raw_status alice-laptop-tools POST /api/devices -H 'Content-Type: text/plain' -d '{"kind":"personal"}')" = 415
check "mesh API rejects cross-origin requests (403)" \
  test "$(api_raw_status alice-laptop-tools POST /api/devices -H 'Content-Type: application/json' -H "Origin: https://alice.$ZONE" -d '{"kind":"personal"}')" = 403
check "mesh API rejects same-site browser requests (403)" \
  test "$(api_raw_status alice-laptop-tools POST /api/devices -H 'Content-Type: application/json' -H 'Sec-Fetch-Site: same-site' -d '{"kind":"personal"}')" = 403

step "A device that bypassed the registrar gets nothing"
check "it is not recorded as anyone's device" no_match stray-device $H device list
rm -rf "$_pd"; mkdir -p "$_pd"
( not port_open stray-tools "$CORE_MESH_IP" 443   >"$_pd/s1.out" 2>&1; echo $? >"$_pd/s1.rc" ) &
( not port_open stray-tools "$CORE_MESH_IP" 9000  >"$_pd/s2.out" 2>&1; echo $? >"$_pd/s2.rc" ) &
( not port_open stray-tools "$ALICE_SERVER_IP" 443 >"$_pd/s3.out" 2>&1; echo $? >"$_pd/s3.rc" ) &
( not can_ping bob-tools "$STRAY_IP"              >"$_pd/s4.out" 2>&1; echo $? >"$_pd/s4.rc" ) &
wait
check "it cannot reach the portal"     probe_ok s1
check "it cannot reach retired CA port 9000" probe_ok s2
check "it cannot reach alice's server" probe_ok s3
check "bob cannot reach it"            probe_ok s4

step "Relay"
relay="$(run bob-laptop tailscale ping -c 3 "$CORE_MESH_IP" 2>&1 | tr -d '\r')"
echo "$relay" | head -1 | sed 's/^/        /'
check "traffic with no direct path is carried by the network's own relay" grep -q 'DERP(hogman)' <<<"$relay"
regions="$(run bob-laptop tailscale debug derp-map 2>/dev/null | grep '"RegionCode"' | sort -u | tr -d ' \t\r')"
check "only our relay region is offered, none of Tailscale's" test "$regions" = '"RegionCode":"hogman",'

step "The join page and downloads"
from_internet() {  # from_internet <curl args...>
  docker run --rm --network "${COMPOSE_PROJECT_NAME}_outside" -v "$WORK/data/edge-trust:/t:ro" \
    nicolaka/netshoot:v0.14 curl -sf --cacert /t/root.crt "$@"
}
from_internet_status() {
  docker run --rm --network "${COMPOSE_PROJECT_NAME}_outside" -v "$WORK/data/edge-trust:/t:ro" \
    nicolaka/netshoot:v0.14 curl -s -o /dev/null -w '%{http_code}' --cacert /t/root.crt "$1" \
    | tr -d '\r' | tail -c 3
}
page_ok() {
  local html
  html="$(from_internet "https://$PUBLIC_HOST/join")" || return 1
  grep -q 'hogman' <<<"$html"
}
net_ok()   { from_internet "https://$PUBLIC_HOST/hogman/v1/network" | jq -e --arg z "$ZONE" '.zone == $z and .cert_mode == "public" and (.root_ca // "") == "" and (.root_fingerprint // "") == ""'; }
check "https://<host>/join serves the join page" page_ok
check "edge runs non-root ($HOGMAN_UID:$HOGMAN_GID)" bash -c 'test "$1" != 0 && test "$2" = "$1:$3"' _ "$HOGMAN_UID" "$(docker inspect -f '{{.Config.User}}' "$(dc ps -q edge)")" "$HOGMAN_GID"
check "registrar (portal + DNS + core mesh) runs non-root ($HOGMAN_UID:$HOGMAN_GID)" bash -c 'test "$1" != 0 && test "$2" = "$1:$3"' _ "$HOGMAN_UID" "$(docker inspect -f '{{.Config.User}}' "$(dc ps -q registrar)")" "$HOGMAN_GID"
check "core-mesh and portal containers are gone (I-15)" bash -c 'test -z "$1" && test -z "$2"' _ "$(dc ps -q core-mesh 2>/dev/null || true)" "$(dc ps -q portal 2>/dev/null || true)"
tcp_dns_ok() {
  local out
  out="$(run bob-tools dig +tcp +short "@$CORE_MESH_IP" "home.$ZONE" | tr -d '\r')" || return 1
  grep -qx -- "$CORE_MESH_IP" <<<"$out"
}
check "TCP :53 DNS resolves home.$ZONE over tsnet" tcp_dns_ok
xff_spoof_refused() {
  local code
  code="$(run bob-tools curl -s -m5 -o /dev/null -w '%{http_code}' --cacert "$ROOT" -H "X-Forwarded-For: $ALICE_LAPTOP_IP" "https://home.$ZONE/api/admin/members" | tr -d '\r')" || return 1
  test "$code" = 403
}
check "direct tsnet identity ignores spoofed X-Forwarded-For on /api/admin/members" xff_spoof_refused
join_hdrs="$(from_internet -sI "https://$PUBLIC_HOST/join" | tr -d '\r')"
check "the join page sets anti-framing headers and Origin-Agent-Cluster" bash -c "grep -iq '^x-frame-options: DENY' <<<\"\$1\" && grep -iq \"^content-security-policy:.*frame-ancestors 'none'\" <<<\"\$1\" && grep -iq '^origin-agent-cluster: ?1' <<<\"\$1\"" _ "$join_hdrs"
portal_hdrs="$(run bob-tools curl -sfI --cacert $ROOT "https://home.$ZONE/" | tr -d '\r')"
check "the portal page sets Origin-Agent-Cluster" grep -iq '^origin-agent-cluster: ?1' <<<"$portal_hdrs"
join_assets_ok() {
  from_internet "https://$PUBLIC_HOST/join/assets/join.js" >/dev/null &&
    from_internet "https://$PUBLIC_HOST/join/assets/join.css" >/dev/null
}
check "join page external JS/CSS load" join_assets_ok
dl_hdrs="$(from_internet -sI "https://$PUBLIC_HOST/join/dl/SHA256SUMS" | tr -d '\r')"
check "/join/dl/ sets nosniff" grep -iq '^x-content-type-options: nosniff' <<<"$dl_hdrs"
check "edge allows Headscale /health" match '"pass"' from_internet "https://$PUBLIC_HOST/health"
check "edge allows Tailscale /key" match '"publicKey"' from_internet "https://$PUBLIC_HOST/key?v=138"
check "edge allows /generate_204" test "$(from_internet_status "https://$PUBLIC_HOST/generate_204")" = 204
check "edge blocks Headscale admin API (/api/v1/user -> 404)" test "$(from_internet_status "https://$PUBLIC_HOST/api/v1/user")" = 404
check "edge blocks Headscale Swagger UI (/swagger -> 404)" test "$(from_internet_status "https://$PUBLIC_HOST/swagger")" = 404
edge_blocked_routes_ok() {
  local p
  for p in / /version /apple /windows /register/test /auth/test /robots.txt; do
    [ "$(from_internet_status "https://$PUBLIC_HOST$p")" = 404 ] || return 1
  done
}
check "edge blocks Headscale root, register, auth, apple, windows, version (-> 404)" edge_blocked_routes_ok
sums="$(from_internet "https://$PUBLIC_HOST/join/dl/SHA256SUMS")"
check "the join tool is downloadable for 5 platforms" test "$(grep -c hogman <<<"$sums")" = 5
check "the network info endpoint is public" net_ok

step "The join tool, on a fresh computer"
dc up -d carol-laptop carol-desktop
retry 30 run carol-laptop tailscale status --json
join_tool() {  # join_tool <container> <args...>
  local c="$1"; shift
  run "$c" sh -c '"/dl/hogman-$(uname -s)-$(uname -m)" --no-open "$@"' _ "$@"
}
CAROL_LINK="$($H invite create --note carol | awk '/^link:/ {print $2}')"
check "the invite link carries no fingerprint" bash -c '! grep -q "fp=" <<<"$1"' _ "$CAROL_LINK"
BAD_LINK="${CAROL_LINK}&fp=$(printf '%064d' 0)"
out="$(join_tool carol-laptop --handle carol "$BAD_LINK" 2>&1)"
check "a legacy link with fp= is refused" grep -q 'older release' <<<"$out"
check "... before the invite is used" match 'open.*carol' $H invite list
out="$(join_tool carol-laptop --handle carol --hostname carol-laptop "$CAROL_LINK" 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "the join tool succeeds (exit $rc)" test $rc = 0
check "it reports carol is in" grep -q "You're in. You are carol on $ZONE" <<<"$out"
check "with Tailscale installed, it still joins the usual HTTPS-only way" grep -q "own small connection" <<<"$out"
ts_untouched() { [ "$(run carol-laptop tailscale status --json | jq -r .BackendState)" != Running ]; }
check "... and leaves this computer's Tailscale alone" ts_untouched
check "nothing was added to the system trust store" \
  no_match hogman run carol-laptop ls /usr/local/share/ca-certificates
check "the registrar recorded carol's laptop" retry 10 match 'carol.*carol-laptop' $H device list
check "no account recovery: the server won't make a device link for carol, who has joined" not $H device key carol personal
check "a new member can still be given a first device link from the server" $H member add erin
DEVICE_LINK="$($H device key erin personal | awk '/^link:/ {print $2}')"
out="$(join_tool carol-desktop --tailscale --hostname carol-desktop "$DEVICE_LINK" 2>&1)"; rc=$?
check "joining through the Tailscale app is no longer offered (--tailscale refused)" test $rc != 0
check "... and the device link is still unused" no_match 'erin.*carol-desktop' $H device list
out="$(join_tool carol-desktop --hostname carol-desktop "$DEVICE_LINK" 2>&1)"; rc=$?
check "a device link joins that member (exit $rc)" grep -q "You're in. You are erin" <<<"$out"
check "the registrar recorded it as erin's" retry 10 match 'erin.*carol-desktop' $H device list
out="$(join_tool carol-desktop leave "$DEVICE_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "leave works (exit $rc)" grep -q "Left $ZONE" <<<"$out"
conn_gone() { ! run carol-desktop test -e "/root/.config/hogman/$ZONE"; }
check "leave removed the pen's connection and its settings" conn_gone

step "The join page's own command, pasted into a terminal (zsh and bash)"
# Run the exact text join.js shows people, the way they paste it: zsh is the
# default shell in macOS Terminal, bash on most Linux. (Before #191, zsh
# stopped at an unquoted --proto =https and nothing here noticed.) The only
# additions are the flags a terminal without a keyboard needs.
dc up -d zsh-laptop bash-laptop
for c in zsh-laptop bash-laptop; do retry 20 run "$c" test -s /etc/ssl/certs/ca-certificates.crt; done
paste_join() {  # paste_join <container> <shell> <handle>
  local c="$1" shell="$2" handle="$3" link cmd
  link="$($H invite create --note "$handle (pasted join command)" | awk '/^link:/ {print $2}')"
  cmd="$("$SRC/test/render-join-cmd.sh" "$PUBLIC_HOST" "$link") --no-open --handle $handle --hostname $c"
  run "$c" "$shell" -c "$cmd" 2>&1
}
pasted_portal_ok() {  # pasted_portal_ok <container> <handle>
  run "$1" sh -c 'p="$(jq -r .proxy_addr "$HOME/.config/hogman/$1/config.json")" &&
    curl -sf -m 10 --cacert "$2" -x "http://$p" "https://home.$1/api/me"' _ "$ZONE" "$ROOT" | jq -e --arg h "$2" '.member.handle == $h' >/dev/null
}
for pair in "zsh-laptop zsh zara" "bash-laptop bash bart"; do
  set -- $pair
  out="$(paste_join "$1" "$2" "$3")"; rc=$?
  [ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
  check "pasted join command works under $2 (exit $rc)" grep -q "You're in. You are $3 on $ZONE" <<<"$out"
  check "... with no shell error (e.g. zsh's 'https not found')" bash -c '! grep -qE "not found|parse error|no matches found" <<<"$1"' _ "$out"
  check "... installed ~/hogman from the front door" run "$1" sh -c 'test -x "$HOME/hogman" && "$HOME/hogman" --version'
  check "... and $3 reaches the portal through the local proxy" retry 15 pasted_portal_ok "$1" "$3"
done
dc kill zsh-laptop bash-laptop >/dev/null 2>&1 || true
dc rm -f zsh-laptop bash-laptop >/dev/null 2>&1 || true

step "Side by side: a computer with no Tailscale at all"
dc up -d dave-laptop
retry 20 run dave-laptop test -s /etc/ssl/certs/ca-certificates.crt
DAVE_LINK="$($H invite create --note dave | awk '/^link:/ {print $2}')"
out="$(join_tool dave-laptop --handle dave --hostname dave-laptop "$DAVE_LINK" 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "the join tool succeeds without Tailscale installed (exit $rc)" test $rc = 0
check "it joined the usual way (side by side)" grep -q "joining side by side" <<<"$out"
check "it reports dave is in" grep -q "You're in. You are dave on $ZONE" <<<"$out"
check "nothing was added to dave's system trust store" \
  no_match hogman run dave-laptop ls /usr/local/share/ca-certificates
check "the registrar recorded dave's laptop" retry 10 match 'dave.*dave-laptop' $H device list
PROXY="$(run dave-laptop sh -c 'grep -o "127.0.0.1:[0-9]*" "/root/.config/hogman/'"$ZONE"'/config.json" | head -1' | tr -d '\r')"
via_pen()   { run dave-laptop curl -sf -m10 --cacert $ROOT --proxy "http://$PROXY" "$1"; }
alice_via() { match "hello from alice.$ZONE" via_pen "https://alice.$ZONE"; }
check "dave loads alice's site through the pen, trusted by the system store" retry 20 alice_via
outside_code() { run dave-laptop curl -s -m10 -o /dev/null -w '%{http_code}' --proxy "http://$PROXY" http://example.com | tr -d '\r'; }
check "the pen's proxy refuses anything outside the pen (HTTP $(outside_code))" test "$(outside_code)" = 403
pac_ok() { match "dnsDomainIs(host, \".$ZONE\")" run dave-laptop curl -sf "http://$PROXY/proxy.pac"; }
check "its rules file sends only pen names through the pen" pac_ok
no_tun() {
  local out
  out="$(run dave-laptop ip -o link)" || return 1
  ! grep -qi tailscale <<<"$out"
}
check "no network interface was added to the computer" no_tun
direct_ok() { run dave-laptop curl -sf -m10 -o /dev/null https://example.com; }
check "dave's ordinary internet is untouched" direct_ok

# One command puts a folder on the pen, from a laptop that only joined side by side.
run dave-laptop sh -c 'mkdir -p /tmp/notes && echo "notes from dave" > /tmp/notes/index.html'
out="$(join_tool dave-laptop share notes /tmp/notes --note "Dave's test notes" --background 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "share puts a folder on the pen in one command (exit $rc)" grep -q "https://notes.$ZONE is up" <<<"$out"
notes_via() { match "notes from dave" via_pen "https://notes.$ZONE"; }
check "dave's laptop loads https://notes.$ZONE" retry 20 notes_via
check "bob loads it too (with Tailscale)" retry 30 fetch notes.$ZONE "notes from dave"
check "the name is dave's" match 'notes.*dave' $H name list
share_dir_note() { api bob-tools GET /api/directory | jq -e --arg n "notes.$ZONE" --arg desc "Dave's test notes" 'any(.[]; .name == $n and .member == "dave" and .note == $desc)'; }
check "the directory shows the share's note" share_dir_note
notes_listed() { match "notes.*running" join_tool dave-laptop share list; }
check "share list shows it running" notes_listed
only_proxy_tcp_listen() {
  # I-27: with ts_omit_peerapiserver, hogman agent + share must ONLY listen on
  # the agent's 127.0.0.1:<proxyPort> socket — zero wildcard or extra TCP listeners.
  # Ignore Docker's built-in container DNS listener on 127.0.0.11 (0B00007F).
  local want_hex
  want_hex="$(printf '0100007F:%04X' "${PROXY##*:}")"
  run dave-laptop sh -c '
    want="'"$want_hex"'"
    v4="$(awk "NR>1 && \$4==\"0A\" && \$2 !~ /^0B00007F:/ { print \$2 }" /proc/net/tcp 2>/dev/null || true)"
    v6="$(awk "NR>1 && \$4==\"0A\" { print \$2 }" /proc/net/tcp6 2>/dev/null || true)"
    if [ "$v4" != "$want" ] || [ -n "$v6" ]; then
      echo "unexpected TCP listeners on dave-laptop: want v4=[$want] v6=[], got v4=[$v4] v6=[$v6]" >&2
      exit 1
    fi
  '
}
check "hogman agent and share only open 127.0.0.1:<proxy> TCP listener (I-27)" only_proxy_tcp_listen
DAVE_LAPTOP_IP="$(ip_of dave-laptop)"
check "bob's laptop cannot reach dave's tsnet laptop over the mesh (443)" not port_open bob-tools "$DAVE_LAPTOP_IP" 443
NOTES_IP="$(ip_of notes)"
check "alice's server cannot reach dave's notes share on 443 (server isolation)" not port_open alice-tools "$NOTES_IP" 443
notes_device() {
  local out
  out="$($H device list)" || return 1
  awk '$2 == "dave" && $4 == "notes" { found=1 } END { exit !found }' <<<"$out"
}
check "it is a server of dave's, called notes" notes_device
out="$(join_tool dave-laptop share notes /tmp/notes 2>&1)"
check "sharing the same name twice is refused while it runs" grep -q "already being shared" <<<"$out"
out="$(join_tool dave-laptop share stop notes 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "share stop takes it down (exit $rc)" grep -q "notes.$ZONE is down" <<<"$out"
check "... and gives the name back" no_match notes $H name list
check "... and removes its server" retry 10 not notes_device
check "bob can't load it any more" retry 15 not fetch notes.$ZONE "notes from dave"

# Server links only put something in the pen with share (D-11): joining a
# whole computer with one is refused before the link is used, and the same
# link then works with share.
dc up -d dave-server dave-server-tools
retry 20 run dave-server test -s /etc/ssl/certs/ca-certificates.crt

# Second-device link minted from an existing member's portal (I-21): verifies
# device-link enrollment survives the transient ACL sync window, actually
# reaches https://home.$ZONE/api/me through its own local proxy, and loses
# access cleanly when removed via DELETE /api/devices/:id.
DAVE_DEV_LINK="$(run dave-laptop curl -sf -m10 --cacert "$ROOT" --proxy "http://$PROXY" \
  -H "Origin: https://home.$ZONE" -H 'Content-Type: application/json' \
  -d '{"kind":"personal"}' "https://home.$ZONE/api/devices" | jq -r '.join_link')"
check "dave mints a second-device link from his portal" bash -c '[[ "$1" == https://*/join#k=* ]]' _ "$DAVE_DEV_LINK"
out="$(join_tool dave-server --hostname dave-second "$DAVE_DEV_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "second device joins via portal device link (exit $rc)" grep -q "You're in. You are dave on $ZONE" <<<"$out"
DAVE2_PROXY="$(run dave-server sh -c 'cat "${XDG_CONFIG_HOME:-$HOME/.config}/hogman/'"$ZONE"'/config.json"' | jq -r '.proxy_addr' | tr -d '\r')"
dave2_me() {
  run dave-server-tools curl -sf -m10 --cacert "$ROOT" --proxy "http://$DAVE2_PROXY" "https://home.$ZONE/api/me" \
    | jq -e '.member.handle == "dave"' >/dev/null
}
check "... second device reaches /api/me through its proxy" retry 10 dave2_me
DAVE2_ID="$(run dave-server-tools curl -sf -m10 --cacert "$ROOT" --proxy "http://$DAVE2_PROXY" "https://home.$ZONE/api/me" | jq -r '.this_device.id')"
check "... dave removes his second device via DELETE /api/devices/$DAVE2_ID" run dave-laptop curl -sf -m10 --cacert "$ROOT" --proxy "http://$PROXY" \
  -X DELETE -H "Origin: https://home.$ZONE" "https://home.$ZONE/api/devices/$DAVE2_ID"
dave2_blocked() {
  ! run dave-server-tools curl -sf -m5 --cacert "$ROOT" --proxy "http://$DAVE2_PROXY" "https://home.$ZONE/api/me"
}
check "... removed second device loses access to home.$ZONE" retry 15 dave2_blocked
check "... while dave's first laptop still reaches home.$ZONE" run dave-laptop curl -sf -m10 --cacert "$ROOT" --proxy "http://$PROXY" "https://home.$ZONE/api/me"
join_tool dave-server leave --force "$ZONE" >/dev/null 2>&1 || true

SHARE_LINK="$($H device key dave server | awk '/^link:/ {print $2}')"
check "a server link is marked for share" grep -q 'for=share' <<<"$SHARE_LINK"
check "the server link carries no fingerprint" bash -c '! grep -q "fp=" <<<"$1"' _ "$SHARE_LINK"
out="$(join_tool dave-server --hostname dave-server "$SHARE_LINK" 2>&1)"; rc=$?
check "joining a whole computer with a server link is refused (exit $rc)" test $rc != 0
check "... and says to use it with share" grep -q "hogman share" <<<"$out"
no_dave_server() { local out; out="$($H device list)" || return 1; [ -z "$(awk '$2 == "dave" && $4 == "dave-server"' <<<"$out")" ]; }
check "... and adds no device" no_dave_server

# A computer that isn't on the pen at all: one server link, one command.
docker exec -d "$(dc ps -q dave-server)" sh -c 'mkdir -p /tmp/www && echo "app from a server link" > /tmp/www/index.html && caddy file-server --listen 127.0.0.1:8080 --root /tmp/www >/tmp/fs.log 2>&1'
out="$(join_tool dave-server share app 8080 "$SHARE_LINK" 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "a server link plus one command shares a port (exit $rc)" grep -q "https://app.$ZONE is up" <<<"$out"
check "members load https://app.$ZONE" retry 30 fetch app.$ZONE "app from a server link"
out="$(join_tool dave-server share stop app 2>&1)"; rc=$?
check "and it stops cleanly (exit $rc)" grep -q "app.$ZONE is down" <<<"$out"

# Opt-in private site name (I-17 Part 2): random 12-char hostname in DNS/cert,
# friendly --note stays inside the pen, discoverable via /api/directory both
# through a local hogman proxy (no browser) and from a tag:server device, and
# permanently retired on stop (D-21).
step "Private site names (--private-name) and headless /api/directory discovery"
PRIV_LINK="$($H device key dave server | awk '/^link:/ {print $2}')"
out="$(join_tool dave-server share --private-name 8080 "$PRIV_LINK" --note "Cooler 3 - North Bay" --background 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
PRIV_FQDN="$(grep -oE "https://[a-z][a-z0-9]{11}\.${ZONE}" <<<"$out" | head -n 1 | sed 's|^https://||')"
PRIV_LABEL="${PRIV_FQDN%.$ZONE}"
check "share --private-name brings up a random 12-char hostname (exit $rc, label=$PRIV_LABEL)" \
  bash -c 'test "$1" = 0 && [[ "$2" =~ ^[a-z][a-z0-9]{11}$ ]]' _ "$rc" "$PRIV_LABEL"
check "private-name output prints honest certificate-log notice" grep -q "only this random name appears in certificate logs" <<<"$out"
DAVE_STATUS_PORT="$(join_tool dave-laptop status --json | jq -r --arg z "$ZONE" '.pens[] | select(.zone == $z) | .port')"
check "hogman status --json reports the local proxy port ($DAVE_STATUS_PORT)" test "127.0.0.1:$DAVE_STATUS_PORT" = "$PROXY"
priv_dir_via_proxy() {
  run dave-laptop curl -sf -m10 --cacert $ROOT --proxy "http://127.0.0.1:$DAVE_STATUS_PORT" "https://home.$ZONE/api/directory" \
    | jq -e --arg n "$PRIV_FQDN" 'any(.[]; .name == $n and .member == "dave" and .note == "Cooler 3 - North Bay" and .private == true and .online == true)'
}
check "headless client discovers private site via /api/directory through local proxy" retry 20 priv_dir_via_proxy
priv_dir_via_server() {
  api alice-tools GET /api/directory \
    | jq -e --arg n "$PRIV_FQDN" 'any(.[]; .name == $n and .member == "dave" and .note == "Cooler 3 - North Bay" and .private == true)'
}
check "tag:server device discovers private site via /api/directory without a browser" retry 20 priv_dir_via_server
priv_via_proxy() { match "app from a server link" via_pen "https://$PRIV_FQDN"; }
check "members load the private-name site over HTTPS" retry 30 priv_via_proxy
priv_listed() {
  join_tool dave-server share list --json \
    | jq -e --arg n "$PRIV_LABEL" 'any(.[]; .name == $n and .private == true and .note == "Cooler 3 - North Bay" and .running == true)'
}
check "share list --json shows private=true and note" priv_listed
out="$(join_tool dave-server share stop "$PRIV_LABEL" 2>&1)"; rc=$?
check "share stop retires the private name (exit $rc)" grep -q "private name is retired" <<<"$out"
check "retired private label stays retired in registrar (D-21)" match "${PRIV_LABEL}.*retired" $H name list

# Sealed sidecar E2E: real scratch hogman-sidecar container -> --enroll-only --link-stdin
# -> serve over mesh via :ro UDS -> network_mode: none bridge -> app -> docker kill PID 1
# -> restart on the exact same state volume and serve again.
step "Sealed server sidecar (enroll, serve, kill PID 1, restart)"
SIDECAR_IMG="hogman-sidecar-e2e:$$"
SIDECAR_STATE="hogman-e2e-state-$$"
SIDECAR_IN="hogman-e2e-in-$$"
SIDECAR_CTR="hogman-e2e-sidecar-$$"
BRIDGE_CTR="hogman-e2e-bridge-$$"
APP_CTR="hogman-e2e-app-$$"
OUTSIDE_NET="$(docker inspect "$(dc ps -q dave-server)" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' | tr ' ' '\n' | grep -v '^hogman-test-acme$' | grep -v '^$' | head -n 1)"
mkdir -p "$WORK/sidecar-ca"
cp "$WORK/data/edge-trust/root.crt" "$WORK/sidecar-ca/root.crt"
cp "$ACME/bundle.crt" "$WORK/sidecar-ca/bundle.crt"
cat "$WORK/data/edge-trust/root.crt" "$ACME/bundle.crt" > "$WORK/sidecar-ca/combined.crt"
chmod 755 "$WORK/sidecar-ca" && chmod 644 "$WORK/sidecar-ca"/*.crt

if [ -f "$SRC/prebuilt/join/hogman-$(uname -s)-$(uname -m)" ] && [ -f "$REPO/core/join/Dockerfile.sidecar.prebuilt" ]; then
  mkdir -p "$WORK/sidecar-ctx"
  install -m 0755 "$SRC/prebuilt/join/hogman-$(uname -s)-$(uname -m)" "$WORK/sidecar-ctx/hogman.bin"
  docker build -q -f "$REPO/core/join/Dockerfile.sidecar.prebuilt" -t "$SIDECAR_IMG" "$WORK/sidecar-ctx" >/dev/null
else
  docker build -q -f "$REPO/core/join/Dockerfile.sidecar" -t "$SIDECAR_IMG" "$REPO/core/join" >/dev/null
fi
docker volume create "$SIDECAR_STATE" >/dev/null
docker volume create "$SIDECAR_IN" >/dev/null
SEALED_LINK="$($H device key dave server | awk '/^link:/ {print $2}')"

ENROLL_CTR="$(docker create -i \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
  --network "$OUTSIDE_NET" \
  -v "$SIDECAR_STATE:/var/lib/hogman" \
  -v "$WORK/sidecar-ca:/sidecar-ca:ro" \
  -e SSL_CERT_FILE=/sidecar-ca/combined.crt \
  -e HOGMAN_ACME_CA_ROOT=/sidecar-ca/bundle.crt \
  -e HOGMAN_ACME_CA_URL=https://pebble:14000/dir \
  -e HOGMAN_ACME_RESOLVERS=hogman-run-cdns:53 \
  -e HOGMAN_ACME_PROPAGATION_DELAY=100ms \
  -e HOGMAN_ACME_PROPAGATION_TIMEOUT=30s \
  "$SIDECAR_IMG" share sealed unix:///run/hogman-in/app.sock \
    --state-dir=/var/lib/hogman --control-ca=/sidecar-ca/root.crt --enroll-only --link-stdin)"
docker network connect hogman-test-acme "$ENROLL_CTR"
out="$(printf '%s\n' "$SEALED_LINK" | docker start -a -i "$ENROLL_CTR" 2>&1)"; rc=$?
docker rm -f "$ENROLL_CTR" >/dev/null 2>&1 || true
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "sidecar --enroll-only --link-stdin enrolls cleanly (exit $rc)" bash -c 'test "$1" = 0 && grep -q "Enrolled https://sealed.'"$ZONE"'" <<<"$2"' _ "$rc" "$out"

docker run -d --name "$BRIDGE_CTR" \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=4m,noexec,nosuid,nodev \
  -v "$SIDECAR_IN:/run/hogman-in" \
  "$SIDECAR_IMG" bridge --listen-unix=/run/hogman-in/app.sock --forward-tcp=127.0.0.1:8080 >/dev/null
retry 15 docker exec "$BRIDGE_CTR" /hogman bridge --check /run/hogman-in/app.sock

docker run -d --name "$APP_CTR" \
  --network "container:$BRIDGE_CTR" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
  caddy:2.11.9@sha256:4851e54a46b206517c574821bb5cc67f170d2156041e9fbc4c9193b45e84a75b \
  sh -c 'mkdir -p /tmp/www && printf "sealed sidecar ok" > /tmp/www/index.html && exec caddy file-server --listen 127.0.0.1:8080 --root /tmp/www' >/dev/null

start_live_sidecar() {
  docker rm -f "$SIDECAR_CTR" >/dev/null 2>&1 || true
  docker create --name "$SIDECAR_CTR" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
    --network "$OUTSIDE_NET" \
    -v "$SIDECAR_STATE:/var/lib/hogman" \
    -v "$SIDECAR_IN:/run/hogman-in:ro" \
    -v "$WORK/sidecar-ca:/sidecar-ca:ro" \
    -e SSL_CERT_FILE=/sidecar-ca/combined.crt \
    -e HOGMAN_ACME_CA_ROOT=/sidecar-ca/bundle.crt \
    -e HOGMAN_ACME_CA_URL=https://pebble:14000/dir \
    -e HOGMAN_ACME_RESOLVERS=hogman-run-cdns:53 \
    -e HOGMAN_ACME_PROPAGATION_DELAY=100ms \
    -e HOGMAN_ACME_PROPAGATION_TIMEOUT=30s \
    "$SIDECAR_IMG" share sealed unix:///run/hogman-in/app.sock \
      --state-dir=/var/lib/hogman --control-ca=/sidecar-ca/root.crt >/dev/null
  docker network connect hogman-test-acme "$SIDECAR_CTR"
  docker start "$SIDECAR_CTR" >/dev/null
}

start_live_sidecar
check "members load https://sealed.$ZONE through scratch sidecar -> :ro UDS -> bridge -> app" retry 45 fetch sealed.$ZONE "sealed sidecar ok"

docker kill "$SIDECAR_CTR" >/dev/null 2>&1 || true
start_live_sidecar
check "... and after docker kill (stale PID 1), sidecar restarts on same state volume" retry 45 fetch sealed.$ZONE "sealed sidecar ok"
docker rm -f "$SIDECAR_CTR" "$APP_CTR" "$BRIDGE_CTR" >/dev/null 2>&1 || true
docker volume rm -f "$SIDECAR_STATE" "$SIDECAR_IN" >/dev/null 2>&1 || true
docker rmi -f "$SIDECAR_IMG" >/dev/null 2>&1 || true

out="$(join_tool dave-laptop update --pen "$ZONE" --dry-run 2>&1)"; rc=$?
check "hogman update --dry-run checks SHA256SUMS cleanly (exit $rc)" bash -c 'test "$1" = 0 && grep -q "already up to date" <<<"$2"' _ "$rc" "$out"
BEFORE_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
# Simulate an existing hogman-join install layout (stale canonical binary,
# legacy per-pen hogman-join copy, and a regular-file native-host copy).
run dave-laptop sh -c '
  cp "/dl/hogman-$(uname -s)-$(uname -m)" "/root/.config/hogman/'"$ZONE"'/hogman-join"
  cp "/dl/hogman-$(uname -s)-$(uname -m)" "/root/.config/hogman/bin/hogman-native-host"
  printf "#!/bin/sh\nexit 1\n" > "/root/.config/hogman/bin/.stale-join" && chmod 755 "/root/.config/hogman/bin/.stale-join" && mv "/root/.config/hogman/bin/.stale-join" "/root/.config/hogman/bin/hogman"
'
out="$(join_tool dave-laptop update --pen "$ZONE" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "hogman update consolidates legacy hogman-join layout and restarts agent (exit $rc)" bash -c 'test "$1" = 0 && grep -q "Updated " <<<"$2"' _ "$rc" "$out"
AFTER_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
check "... restarted agent with a new process" test -n "$BEFORE_PID" -a -n "$AFTER_PID" -a "$BEFORE_PID" != "$AFTER_PID"
check "... and installed binary matches /join/dl exactly" run dave-laptop sh -c 'cmp -s "/root/.config/hogman/bin/hogman" "/dl/hogman-$(uname -s)-$(uname -m)"'
check "... and removed legacy per-pen hogman-join copy" run dave-laptop sh -c 'test ! -e "/root/.config/hogman/'"$ZONE"'/hogman-join"'
check "... and converted hogman-native-host into a symlink to hogman" run dave-laptop sh -c 'test -L "/root/.config/hogman/bin/hogman-native-host"'
check "... and restarted agent still loads alice.$ZONE" retry 20 alice_via

# I-10 E2E (1): a running legacy hogman-join agent holding the proxy port must
# be stopped cleanly when the new hogman client runs on the same pen (e.g. via /start).
run dave-laptop sh -c '
  pid="$(cat "/root/.config/hogman/'"$ZONE"'/agent.pid" 2>/dev/null || true)"
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  sleep 1
  cp "/dl/hogman-$(uname -s)-$(uname -m)" "/root/.config/hogman/'"$ZONE"'/hogman-join"
  rm -f "/root/.config/hogman/'"$ZONE"'/status.token"
  nohup "/root/.config/hogman/'"$ZONE"'/hogman-join" agent "/root/.config/hogman/'"$ZONE"'" >/root/.config/hogman/'"$ZONE"'/agent.log 2>&1 </dev/null &
'
retry 20 run dave-laptop sh -c 'test -s "/root/.config/hogman/'"$ZONE"'/agent.pid" && kill -0 "$(cat "/root/.config/hogman/'"$ZONE"'/agent.pid")" 2>/dev/null'
LEGACY_AGENT_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
out="$(join_tool dave-laptop --no-system-proxy "$DAVE_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "re-running hogman replaces a running legacy hogman-join agent on the same port (exit $rc)" bash -c 'test "$1" = 0 && grep -q "You'\''re in." <<<"$2"' _ "$rc" "$out"
NEW_AGENT_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
check "... replaced legacy agent PID ($LEGACY_AGENT_PID -> $NEW_AGENT_PID)" test -n "$LEGACY_AGENT_PID" -a -n "$NEW_AGENT_PID" -a "$LEGACY_AGENT_PID" != "$NEW_AGENT_PID"
check "... cleaned up legacy hogman-join copy after restart" run dave-laptop sh -c 'test ! -e "/root/.config/hogman/'"$ZONE"'/hogman-join"'
check "... and new agent loads alice.$ZONE" retry 20 alice_via

# I-10 E2E (2): two legacy pens where the first pen's server is unreachable and
# the second pen is healthy: `hogman update` must not stop at the dead pen, must
# skip the 60s online wait for it, and must still migrate the healthy pen.
docker exec -d "$(dc ps -q dave-server)" sh -c '
  set -e
  mkdir -p /tmp/rel/latest/download /tmp/rel/download/v2026.11.24
  printf "2026.11.24\n" > /tmp/rel/latest/download/latest
  cp /dl/SHA256SUMS /tmp/rel/download/v2026.11.24/hogman-SHA256SUMS
  cp /dl/hogman-* /tmp/rel/download/v2026.11.24/
  cat > /tmp/rel/Caddyfile <<EOF
{
  auto_https disable_redirects
}
dave-server:8443 {
  tls internal
  root * /tmp/rel
  file_server
}
EOF
  caddy run --config /tmp/rel/Caddyfile >/tmp/rel/caddy.log 2>&1
'
retry 20 run dave-server test -s /data/caddy/pki/authorities/local/root.crt
run dave-server cat /data/caddy/pki/authorities/local/root.crt | docker exec -i "$(dc ps -q dave-laptop)" sh -c 'cat > /usr/local/share/ca-certificates/rel-ca.crt && update-ca-certificates >/dev/null 2>&1'
BEFORE_MULTI_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
run dave-laptop sh -c '
  mkdir -p /root/.config/hogman/aaa-dead.example.test
  printf "{\"zone\":\"aaa-dead.example.test\",\"login_server\":\"https://127.0.0.1:1\",\"dns_server\":\"100.64.0.1\",\"hostname\":\"dead\",\"proxy_addr\":\"127.0.0.1:19999\"}\n" > /root/.config/hogman/aaa-dead.example.test/config.json
  cp "/dl/hogman-$(uname -s)-$(uname -m)" /root/.config/hogman/aaa-dead.example.test/hogman-join
  nohup sleep 300 >/dev/null 2>&1 </dev/null & echo $! > /root/.config/hogman/aaa-dead.example.test/agent.pid
  cp "/dl/hogman-$(uname -s)-$(uname -m)" "/root/.config/hogman/'"$ZONE"'/hogman-join"
'
DEAD_OLD_PID="$(run dave-laptop cat /root/.config/hogman/aaa-dead.example.test/agent.pid 2>/dev/null | tr -d '\r')"
t0="$(date +%s)"
out="$(run dave-laptop sh -c 'HOGMAN_RELEASE_BASE="https://dave-server:8443" "/dl/hogman-$(uname -s)-$(uname -m)" --no-open update' 2>&1)"; rc=$?
t_multi=$(( $(date +%s) - t0 ))
check "hogman update with one dead pen + one live pen reports failure (exit $rc, ${t_multi}s)" bash -c 'test "$1" != 0 && grep -q "hogman leave aaa-dead.example.test" <<<"$2"' _ "$rc" "$out"
check "... skipped the 60s wait on the unreachable pen (${t_multi}s < 45s)" test "$t_multi" -lt 45
check "... replaced dead pen old agent ($DEAD_OLD_PID) with live canonical hogman agent without waiting (B1)" retry 10 run dave-laptop sh -c 'pid="$(cat /root/.config/hogman/aaa-dead.example.test/agent.pid 2>/dev/null || true)"; test -n "$pid" && test "$pid" != "$1" && kill -0 "$pid" 2>/dev/null && test "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" = "/root/.config/hogman/bin/hogman"' _ "$DEAD_OLD_PID"
AFTER_MULTI_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
check "... still migrated and restarted the healthy pen ($BEFORE_MULTI_PID -> $AFTER_MULTI_PID)" test -n "$BEFORE_MULTI_PID" -a -n "$AFTER_MULTI_PID" -a "$BEFORE_MULTI_PID" != "$AFTER_MULTI_PID"
check "... removed legacy hogman-join copy on BOTH pens" run dave-laptop sh -c 'test ! -e /root/.config/hogman/aaa-dead.example.test/hogman-join && test ! -e "/root/.config/hogman/'"$ZONE"'/hogman-join"'
check "... and healthy pen still loads alice.$ZONE" retry 20 alice_via
run dave-laptop sh -c 'pid="$(cat /root/.config/hogman/aaa-dead.example.test/agent.pid 2>/dev/null || true)"; [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; rm -rf /root/.config/hogman/aaa-dead.example.test'

# Downgrade guard E2E (I-8 follow-up) + I-20 stale running-agent self-heal E2E.
DAVE_ARCH="$(run dave-laptop uname -m | tr -d '\r')"
case "$DAVE_ARCH" in x86_64|amd64) DAVE_GOARCH=amd64 ;; aarch64|arm64) DAVE_GOARCH=arm64 ;; *) DAVE_GOARCH=amd64 ;; esac
mkdir -p "$WORK/ver-bins"
if [ -f "$SRC/prebuilt/test-bins/hogman-old" ] && [ -f "$SRC/prebuilt/test-bins/hogman-new" ]; then
  install -m 0755 "$SRC/prebuilt/test-bins/hogman-old" "$WORK/ver-bins/hogman-old"
  install -m 0755 "$SRC/prebuilt/test-bins/hogman-new" "$WORK/ver-bins/hogman-new"
else
  docker run --rm -v "$REPO/core/join:/src:ro" -v "$WORK/ver-bins:/out" -w /src \
    -v hogman-gomod:/go/pkg/mod -v hogman-gocache:/root/.cache/go-build \
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH="$DAVE_GOARCH" -e GOFLAGS="-buildvcs=false -tags=ts_omit_peerapiserver" \
    golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 sh -c '
      set -e
      go build -trimpath -ldflags="-s -w -X main.version=2025.01.01-aaaaaaa" -o /out/hogman-old .
      go build -trimpath -ldflags="-s -w -X main.version=2099.01.01-bbbbbbb" -o /out/hogman-new .
    ' >/dev/null
fi
DAVE_CID="$(dc ps -q dave-laptop)"
docker cp "$WORK/ver-bins/hogman-old" "$DAVE_CID:/tmp/hogman-old"
docker cp "$WORK/ver-bins/hogman-new" "$DAVE_CID:/tmp/hogman-new"
run dave-laptop chmod 0755 /tmp/hogman-old /tmp/hogman-new

# I-20 E2E: on-disk binaries already match the release, a deleted pen returns
# HTTP 404 from the front door, and the live pen's running agent is still on an
# older (then-deleted) binary. `hogman update` must NOT say "already up to date";
# it must skip the 404 pen's 60s wait and restart the live pen onto bin/hogman.
run dave-laptop sh -c '
  cp /tmp/hogman-old /tmp/hogman-stale-deleted && chmod 0755 /tmp/hogman-stale-deleted
  pid="$(cat "/root/.config/hogman/'"$ZONE"'/agent.pid" 2>/dev/null || true)"
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  sleep 1
  nohup /tmp/hogman-stale-deleted agent "/root/.config/hogman/'"$ZONE"'" >/root/.config/hogman/'"$ZONE"'/agent.log 2>&1 </dev/null &
  mkdir -p /root/.config/hogman/aaa-gone.example.test
  printf "{\"zone\":\"aaa-gone.example.test\",\"login_server\":\"https://dave-server:8443/gone\",\"dns_server\":\"100.64.0.1\",\"hostname\":\"gone\",\"proxy_addr\":\"127.0.0.1:19998\"}\n" > /root/.config/hogman/aaa-gone.example.test/config.json
  printf "0\n" > /root/.config/hogman/aaa-gone.example.test/.updating
  nohup sleep 300 >/dev/null 2>&1 </dev/null & echo $! > /root/.config/hogman/aaa-gone.example.test/agent.pid
'
retry 20 alice_via
run dave-laptop rm -f /tmp/hogman-stale-deleted
STALE_LIVE_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
t0="$(date +%s)"
out="$(run dave-laptop sh -c 'HOGMAN_RELEASE_BASE="https://dave-server:8443" "/dl/hogman-$(uname -s)-$(uname -m)" --no-open update' 2>&1)"; rc=$?
t_i20=$(( $(date +%s) - t0 ))
check "I-20: update with 404 deleted pen + stale live agent does not say already up to date (exit $rc, ${t_i20}s)" bash -c 'test "$1" != 0 && ! grep -q "already up to date" <<<"$2" && grep -q "aaa-gone.example.test" <<<"$2"' _ "$rc" "$out"
check "... skipped 60s wait on HTTP 404 deleted pen (${t_i20}s < 45s)" test "$t_i20" -lt 45
HEALED_LIVE_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
check "... restarted live pen off deleted old binary onto canonical bin/hogman ($STALE_LIVE_PID -> $HEALED_LIVE_PID)" bash -c \
  'test -n "$1" && test -n "$2" && test "$1" != "$2"' _ "$STALE_LIVE_PID" "$HEALED_LIVE_PID"
check "... live pen agent now runs /root/.config/hogman/bin/hogman" run dave-laptop sh -c 'test "$(readlink -f "/proc/$1/exe" 2>/dev/null)" = "/root/.config/hogman/bin/hogman"' _ "$HEALED_LIVE_PID"
check "... and healed live pen still loads alice.$ZONE" retry 20 alice_via
run dave-laptop sh -c 'pid="$(cat /root/.config/hogman/aaa-gone.example.test/agent.pid 2>/dev/null || true)"; [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; rm -rf /root/.config/hogman/aaa-gone.example.test'
out="$(run dave-laptop sh -c 'HOGMAN_RELEASE_BASE="https://dave-server:8443" "/dl/hogman-$(uname -s)-$(uname -m)" --no-open update' 2>&1)"; rc=$?
check "... follow-up update with healthy current agent reports already up to date (exit $rc)" bash -c 'test "$1" = 0 && grep -q "already up to date" <<<"$2"' _ "$rc" "$out"
run dave-laptop sh -c 'rm -f /usr/local/share/ca-certificates/rel-ca.crt && update-ca-certificates --fresh >/dev/null 2>&1'

run dave-laptop sh -c 'cp /tmp/hogman-old /root/.config/hogman/bin/hogman.tmp && mv -f /root/.config/hogman/bin/hogman.tmp /root/.config/hogman/bin/hogman'
out="$(run dave-laptop /tmp/hogman-new --no-open "$DAVE_LINK" 2>&1)"; rc=$?
check "newer-dated client upgrades older shared binary (exit $rc)" test "$rc" = 0
check "... shared binary now reports 2099.01.01-bbbbbbb" match '2099\.01\.01-bbbbbbb' run dave-laptop /root/.config/hogman/bin/hogman --version
NEW_BIN_SUM="$(run dave-laptop sha256sum /root/.config/hogman/bin/hogman | awk '{print $1}')"
out="$(run dave-laptop /tmp/hogman-old --no-open "$DAVE_LINK" 2>&1)"; rc=$?
check "older-dated client does not downgrade newer shared binary (exit $rc)" bash -c 'test "$1" = 0 && grep -q "keeping newer shared binary" <<<"$2"' _ "$rc" "$out"
check "... shared binary version stays 2099.01.01-bbbbbbb" match '2099\.01\.01-bbbbbbb' run dave-laptop /root/.config/hogman/bin/hogman --version
check "... shared binary hash is unchanged" test "$(run dave-laptop sha256sum /root/.config/hogman/bin/hogman | awk '{print $1}')" = "$NEW_BIN_SUM"
run dave-laptop sh -c 'cp "/dl/hogman-$(uname -s)-$(uname -m)" /root/.config/hogman/bin/hogman.tmp && mv -f /root/.config/hogman/bin/hogman.tmp /root/.config/hogman/bin/hogman && rm -f /tmp/hogman-old /tmp/hogman-new'

out="$(join_tool dave-laptop leave "$DAVE_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "leave works (exit $rc)" grep -q "Left $ZONE" <<<"$out"
check "... and removed dave's laptop from his devices" grep -q "removed this computer from your devices" <<<"$out"
dave_laptop_gone() { local out; out="$($H device list)" || return 1; [ -z "$(awk '$2 == "dave" && $4 == "dave-laptop"' <<<"$out")" ]; }
check "... so it's no longer listed" retry 10 dave_laptop_gone
gone() { ! run dave-laptop test -e "/root/.config/hogman/$ZONE"; }
check "leave removed the connection and its settings" gone
proxy_closed() { ! run dave-laptop curl -s -m3 -o /dev/null "http://$PROXY/status"; }
check "the proxy is no longer running" retry 10 proxy_closed

step "Suspend and resume"
check "alice (admin) cannot suspend the owner" expect 403 alice-laptop-tools POST /api/admin/members/root/suspend
$H member suspend bob "testing" >/dev/null
timed t 30 not fetch alice.$ZONE "hello"
check "suspended bob loses access (${t}s)" not fetch alice.$ZONE "hello"
check "suspended bob can't reach the portal" not api_blocked bob-tools GET /api/me
check "his device is still registered" has_device bob-laptop
$H member resume bob >/dev/null
timed t 30 fetch alice.$ZONE "hello"
check "resumed bob has access again (${t}s)" fetch alice.$ZONE "hello"

step "Renew-only wake (I-7 Part 2)"
check "headscale template disables node key expiry for sleeping pens" awk '/^node:[[:space:]]*$/{f=1;next} f && /^  expiry: 0[[:space:]]*$/{ok=1;exit} f && /^[^[:space:]]/{f=0} END{exit !ok}' "$SRC/templates/headscale.yaml"
check "rendered headscale config disables node key expiry for sleeping pens" awk '/^node:[[:space:]]*$/{f=1;next} f && /^  expiry: 0[[:space:]]*$/{ok=1;exit} f && /^[^[:space:]]/{f=0} END{exit !ok}' "$WORK/data/headscale/config/config.yaml"
printf 'renew_only\n' > "$WORK/data/registrar/.renew-only"
cat > "$WORK/data/registrar/billing-status.json" <<'EOF'
{"pen":"bobo","state":"renew_only","wake_until":"2030-01-01T00:10:00Z","renew_url":"https://get.example.com"}
EOF
chmod 0644 "$WORK/data/registrar/.renew-only" "$WORK/data/registrar/billing-status.json"
$H sync >/dev/null
timed t 30 not fetch alice.$ZONE "hello"
check "during renew_only, regular member bob cannot reach alice's share (${t}s)" not fetch alice.$ZONE "hello"
check "during renew_only, regular member bob cannot reach the portal" not api_blocked bob-tools GET /api/me
check "during renew_only, admin alice still reaches /api/me with renew_only state" match '"state":"renew_only"' api alice-laptop-tools GET /api/me
check "during renew_only, admin alice can mint a renewal token" match 'https://get.example.com/#renew=' api alice-laptop-tools POST /api/billing/renew-token '{}'
check "during renew_only, admin alice gets 403 on /api/directory" expect 403 alice-laptop-tools GET /api/directory
r="$(redeem bad x)"
check "during renew_only, public /hogman/v1/redeem returns 403 (HTTP ${r##* })" test "${r##* }" = 403
# Simulate payment completion: clear .renew-only and billing-status.json and reconcile with ZERO container restarts.
rm -f "$WORK/data/registrar/.renew-only" "$WORK/data/registrar/billing-status.json" "$WORK/data/registrar/renew.key"
$H sync >/dev/null
timed t 30 fetch alice.$ZONE "hello"
check "after payment clears renew_only (no restart), bob reaches alice's share again (${t}s)" fetch alice.$ZONE "hello"
check "... and admin alice reaches /api/directory again" api alice-laptop-tools GET /api/directory

step "Kick"
check "nobody can kick the owner" not $H member kick root
check "bob can load alice's site before the kick" fetch alice.$ZONE "hello"
t0="$(date +%s)"
kick_out="$($H member kick alice "test kick")"
echo "        $kick_out"
timed t 60 not fetch alice.$ZONE "hello"
check "bob can no longer reach alice's site (${t}s after the kick)" not fetch alice.$ZONE "hello"
check "alice.$ZONE no longer resolves" retry 20 resolves_none alice.$ZONE
check "all of alice's devices are gone from the mesh" no_device_of alice
check "alice's laptop can no longer reach the portal" retry 30 not port_open alice-laptop-tools "$CORE_MESH_IP" 443
check "alice's server can no longer reach anyone" retry 30 not port_open alice-tools "$CORE_MESH_IP" 443
check "her name is held: bob can't claim alice" expect 409 bob-tools POST /api/names '{"name":"alice","device_id":1}'
check "the kick is in the audit log" match 'member.kick.*alice' $H audit
match 'member.kick.*alice' $H audit || { $H audit | tail -8; dc logs --tail 20 registrar 2>&1 | grep -i audit; } | sed 's/^/        audit| /'
check "bob is unaffected" fetch home.$ZONE "You're in"

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
