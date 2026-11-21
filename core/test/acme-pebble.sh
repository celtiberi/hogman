#!/usr/bin/env bash
# Offline end-to-end test suite for registrar ACME DNS-01 (Step 2):
#   1. Initial home.<zone> cert issuance from Pebble1, registrar healthcheck,
#      and TLS verification through portal Caddy.
#   2. Forced renewal via SIGHUP hot-reloads portal over Caddy's admin Unix
#      socket (new cert serial, unchanged portal container StartedAt).
#   3. Mesh API /api/acme/txt and /api/acme/eab auth, live TXT verification
#      in pebble-challtestsrv via dig, reserved names, and 10-FQDN cap.
#   4. Failover discipline:
#      (a) Broken DNS TXT fails primary WITHOUT triggering fallback or EAB mint.
#      (b) Primary HTTP 429 rateLimited fails over to Pebble2 with lazy EAB
#          mint, reloads portal, and supports SIGHUP renewal on fallback.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/core/test/e2e-lock.sh"
e2e_lock

export ACME_PEN_NAME="${ACME_PEN_NAME:-bobo}"
export ACME_PENS_ZONE="${ACME_PENS_ZONE:-pens.hogman.network}"
export ACME_ZONE="${ACME_ZONE:-${ACME_PEN_NAME}.${ACME_PENS_ZONE}}"
export ACME_PUBLIC_HOST="${ACME_PUBLIC_HOST:-gate.hogman.test}"
export ACME_CHALLENGE_TOKEN="${ACME_CHALLENGE_TOKEN:-test-challenge-token}"
export ACME_EAB_KID="${ACME_EAB_KID:-test-eab-kid}"
export ACME_EAB_HMAC="${ACME_EAB_HMAC:-$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n')}"

export ACME_PEBBLE1_DIR_PORT="${ACME_PEBBLE1_DIR_PORT:-14001}"
export ACME_PEBBLE1_MGMT_PORT="${ACME_PEBBLE1_MGMT_PORT:-15001}"
export ACME_PEBBLE2_DIR_PORT="${ACME_PEBBLE2_DIR_PORT:-14002}"
export ACME_PEBBLE2_MGMT_PORT="${ACME_PEBBLE2_MGMT_PORT:-15002}"
export ACME_CHALLENGE_API_PORT="${ACME_CHALLENGE_API_PORT:-18080}"
export ACME_DNS_PORT="${ACME_DNS_PORT:-18054}"
export ACME_HS_PORT="${ACME_HS_PORT:-18085}"
export ACME_PORTAL_PORT="${ACME_PORTAL_PORT:-18443}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/hogman-acme-e2e.XXXXXX")"
export ACME_WORKDIR="$WORKDIR"
PROJECT="hogman-acme-$$"
FAILED=1

dc() {
  docker compose -p "$PROJECT" -f "$ROOT_DIR/core/test/compose.acme.yaml" "$@"
}

cleanup() {
  local rc=$?
  set +e
  if [ "$FAILED" -ne 0 ] || [ "$rc" -ne 0 ]; then
    echo "--- ACME e2e failed; container logs ---" >&2
    dc ps >&2 || true
    dc logs --tail=80 >&2 || true
  fi
  dc --profile join-e2e down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
  e2e_unlock
  exit "$rc"
}
trap cleanup EXIT

step() { printf "\n=== %s ===\n" "$*"; }
pass() { printf "  ok: %s\n" "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

retry() {
  local tries="$1" delay="$2"; shift 2
  local i=0
  while [ "$i" -lt "$tries" ]; do
    if "$@"; then return 0; fi
    i=$((i + 1))
    sleep "$delay"
  done
  return 1
}

init_data_dirs() {
  rm -rf "$WORKDIR/data"
  mkdir -p "$WORKDIR/data/registrar/acme" \
           "$WORKDIR/data/home-tls" \
           "$WORKDIR/data/caddy-admin" \
           "$WORKDIR/data/api" \
           "$WORKDIR/data/portal"
  chmod 755 "$WORKDIR/data" "$WORKDIR/data/home-tls" "$WORKDIR/data/api"
  chown -R 65532:65532 "$WORKDIR/data"
}

stats_json() {
  curl -sf "http://127.0.0.1:${ACME_CHALLENGE_API_PORT}/test/stats"
}

portal_http_ok() {
  local ca_file="$1"
  local body
  body="$(curl -sf -m 3 \
    --connect-to "home.${ACME_ZONE}:443:127.0.0.1:${ACME_PORTAL_PORT}" \
    --cacert "$ca_file" \
    "https://home.${ACME_ZONE}/")" || return 1
  [ "$body" = "portal ok" ]
}

portal_cert_serial() {
  local ca_file="$1"
  local out
  out="$(openssl s_client \
    -connect "127.0.0.1:${ACME_PORTAL_PORT}" \
    -servername "home.${ACME_ZONE}" \
    -CAfile "$ca_file" \
    -verify_hostname "home.${ACME_ZONE}" \
    -verify_return_error \
    </dev/null 2>/dev/null | openssl x509 -noout -serial)" || return 1
  printf "%s\n" "${out#serial=}"
}

mesh_req() {
  local ip="$1" method="$2" path="$3" body="${4:-}"
  shift 4 || true
  if [ -n "$body" ]; then
    curl -s -m 5 --unix-socket "$WORKDIR/data/api/mesh.sock" \
      -w '\n%{http_code}' -X "$method" \
      -H "X-Forwarded-For: ${ip}" \
      -H "Content-Type: application/json" \
      "$@" \
      -d "$body" \
      "http://localhost${path}"
  else
    curl -s -m 5 --unix-socket "$WORKDIR/data/api/mesh.sock" \
      -w '\n%{http_code}' -X "$method" \
      -H "X-Forwarded-For: ${ip}" \
      -H "Content-Type: application/json" \
      "$@" \
      "http://localhost${path}"
  fi
}

assert_mesh_status() {
  local desc="$1" want="$2" ip="$3" method="$4" path="$5" body="${6:-}"
  shift 6 || true
  local raw code payload
  raw="$(mesh_req "$ip" "$method" "$path" "$body" "$@")"
  code="${raw##*$'\n'}"
  payload="${raw%$'\n'*}"
  if [ "$code" != "$want" ]; then
    fail "$desc: got HTTP $code want $want (body=$payload)"
  fi
  pass "$desc ($code)"
}

step "Preparing ACME test certificates, configs, and secrets in $WORKDIR"
mkdir -p "$WORKDIR/certs" "$WORKDIR/config" "$WORKDIR/secrets"
chmod 755 "$WORKDIR" "$WORKDIR/certs" "$WORKDIR/config" "$WORKDIR/secrets"
init_data_dirs

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$WORKDIR/certs/ca.key" -out "$WORKDIR/certs/ca.crt" \
  -days 7 -subj "/CN=hogman-acme-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$WORKDIR/certs/server.key" -out "$WORKDIR/certs/server.csr" \
  -subj "/CN=pebble1" >/dev/null 2>&1

cat >"$WORKDIR/certs/ext.cnf" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:pebble1,DNS:pebble2,DNS:mock429,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in "$WORKDIR/certs/server.csr" \
  -CA "$WORKDIR/certs/ca.crt" -CAkey "$WORKDIR/certs/ca.key" -CAcreateserial \
  -out "$WORKDIR/certs/server.crt" -days 7 \
  -extfile "$WORKDIR/certs/ext.cnf" >/dev/null 2>&1

chmod 644 "$WORKDIR/certs/ca.crt" "$WORKDIR/certs/server.crt" "$WORKDIR/certs/server.key"

cat >"$WORKDIR/config/pebble1.json" <<'EOF'
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "/certs/server.crt",
    "privateKey": "/certs/server.key",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "retryAfter": { "authz": 1, "order": 1 },
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": { "description": "test", "validityPeriod": 86400 }
    }
  }
}
EOF

cat >"$WORKDIR/config/pebble2.json" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "/certs/server.crt",
    "privateKey": "/certs/server.key",
    "httpPort": 5002,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": true,
    "externalAccountMACKeys": {
      "${ACME_EAB_KID}": "${ACME_EAB_HMAC}"
    },
    "retryAfter": { "authz": 1, "order": 1 },
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": { "description": "test-eab", "validityPeriod": 86400 }
    }
  }
}
EOF

cat >"$WORKDIR/config/portal.Caddyfile" <<'EOF'
{
	auto_https off
	admin unix//run/caddy-admin/admin.sock
}

https://home.{$ZONE}:443 {
	tls /home-tls/home.crt /home-tls/home.key
	handle /api/* {
		reverse_proxy unix//run/hogman-api/mesh.sock
	}
	respond "portal ok" 200
}
EOF

printf "test-headscale-key\n" >"$WORKDIR/secrets/headscale_api_key"
printf "%s\n" "$ACME_CHALLENGE_TOKEN" >"$WORKDIR/secrets/challenge_dns_token"
chown 65532:65532 "$WORKDIR/secrets/headscale_api_key" "$WORKDIR/secrets/challenge_dns_token"
chmod 600 "$WORKDIR/secrets/headscale_api_key" "$WORKDIR/secrets/challenge_dns_token"
chmod 644 "$WORKDIR/config/pebble1.json" "$WORKDIR/config/pebble2.json" "$WORKDIR/config/portal.Caddyfile"

step "Starting Pebble1, Pebble2, challtestsrv, and fake-challengedns"
dc up -d --build challtestsrv fake-challengedns pebble1 pebble2

retry 30 1 curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE1_DIR_PORT}/dir" >/dev/null || fail "pebble1 not ready"
retry 30 1 curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE2_DIR_PORT}/dir" >/dev/null || fail "pebble2 not ready"
retry 30 1 stats_json >/dev/null || fail "fake-challengedns not ready"

curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE1_MGMT_PORT}/roots/0" >"$WORKDIR/pebble1-root.crt"
curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE2_MGMT_PORT}/roots/0" >"$WORKDIR/pebble2-root.crt"
pass "Pebble CAs and fake-challengedns healthy"

step "Test 1: Initial home.${ACME_ZONE} cert issuance + portal HTTPS"
ACME_CA_URL="https://pebble1:14000/dir" ACME_FALLBACK_CA_URL="" \
  dc up -d --build registrar portal

retry 45 1 portal_http_ok "$WORKDIR/pebble1-root.crt" || fail "portal did not serve valid pebble1 HTTPS"
dc exec -T registrar registrar health || fail "registrar health failed"
serial1="$(portal_cert_serial "$WORKDIR/pebble1-root.crt")"
started1="$(docker inspect --format '{{.State.StartedAt}}' "$(dc ps -q portal)")"
stats1="$(stats_json)"
[ "$(jq -r .eab_count <<<"$stats1")" = "0" ] || fail "unexpected fallback EAB mint on happy path: $stats1"
[ "$(jq -r .distinct_fqdns <<<"$stats1")" = "1" ] || fail "expected 1 distinct FQDN after home issuance: $stats1"
[ "$(jq -r '.live | length' <<<"$stats1")" = "0" ] || fail "expected challenge TXT cleanup after home issuance: $stats1"
pass "portal serving pebble1 cert serial=${serial1} with zero EAB calls"

step "Test 2: SIGHUP forces renewal and hot-reloads portal over Caddy Unix admin socket"
dc kill -s SIGHUP registrar

check_renewed() {
  local s
  s="$(portal_cert_serial "$WORKDIR/pebble1-root.crt" 2>/dev/null || true)"
  [ -n "$s" ] && [ "$s" != "$serial1" ]
}
retry 30 1 check_renewed || fail "portal cert serial did not rotate after SIGHUP (stayed ${serial1})"
started2="$(docker inspect --format '{{.State.StartedAt}}' "$(dc ps -q portal)")"
[ "$started1" = "$started2" ] || fail "portal container restarted unexpectedly ($started1 -> $started2)"
portal_http_ok "$WORKDIR/pebble1-root.crt" || fail "portal HTTP check failed after reload"
pass "portal reloaded in-place (StartedAt=${started2}, new serial=$(portal_cert_serial "$WORKDIR/pebble1-root.crt"))"

step "Test 3: Mesh API /api/acme/txt and /api/acme/eab auth, live DNS, and caps"
dc exec -T registrar registrar member add alice >/dev/null
dc exec -T registrar registrar member add bob >/dev/null

issue_key() {
  dc exec -T registrar registrar device key "$1" "$2" | awk '/^key:/ {print $2}'
}

k_alice_lap="$(issue_key alice personal)"
k_alice_srv1="$(issue_key alice server)"
k_alice_srv2="$(issue_key alice server)"
k_bob_srv1="$(issue_key bob server)"

register_node() {
  curl -sf -X POST "http://127.0.0.1:${ACME_HS_PORT}/test/hs-node" \
    -H "Content-Type: application/json" \
    -d "{\"key\":\"$1\",\"ip\":\"$2\",\"name\":\"$3\"}" >/dev/null
}
register_node "$k_alice_lap"  "100.64.0.10" "alice-laptop"
register_node "$k_alice_srv1" "100.64.0.11" "alice-srv1"
register_node "$k_alice_srv2" "100.64.0.12" "alice-srv2"
register_node "$k_bob_srv1"   "100.64.0.21" "bob-srv1"
dc exec -T registrar registrar sync >/dev/null

assert_mesh_status "alice-srv1 claims photos" 201 "100.64.0.11" POST /api/names '{"name":"photos"}'
assert_mesh_status "alice-srv1 claims blog.photos" 201 "100.64.0.11" POST /api/names '{"name":"blog.photos"}'

txt_val="test_txt_value_0123456789abcdef"
assert_mesh_status "alice-srv1 writes TXT for photos" 201 "100.64.0.11" POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}"
got_dig="$(dig @127.0.0.1 -p "${ACME_DNS_PORT}" +short TXT "_acme-challenge.photos.${ACME_ZONE}." | tr -d '"' | tr -d '\r')"
[ "$got_dig" = "$txt_val" ] || fail "dig TXT mismatch for photos: got=$got_dig want=$txt_val"
pass "challtestsrv answered dig TXT=${got_dig}"

assert_mesh_status "alice-srv1 deletes TXT for photos" 204 "100.64.0.11" DELETE /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}"
got_dig_after="$(dig @127.0.0.1 -p "${ACME_DNS_PORT}" +short TXT "_acme-challenge.photos.${ACME_ZONE}." | tr -d '\r')"
[ -z "$got_dig_after" ] || fail "expected empty TXT after DELETE, got=$got_dig_after"
pass "challtestsrv cleared TXT on DELETE"

assert_mesh_status "alice-srv1 writes TXT for sub-name blog.photos" 201 "100.64.0.11" POST /api/acme/txt "{\"name\":\"blog.photos.${ACME_ZONE}\",\"value\":\"$txt_val\"}"
assert_mesh_status "alice-srv1 deletes TXT for sub-name blog.photos" 204 "100.64.0.11" DELETE /api/acme/txt "{\"name\":\"blog.photos\",\"value\":\"$txt_val\"}"

assert_mesh_status "personal device refused on /api/acme/txt" 403 "100.64.0.10" POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}"
assert_mesh_status "personal device refused on /api/acme/eab" 403 "100.64.0.10" POST /api/acme/eab ""
assert_mesh_status "same member other server refused" 403 "100.64.0.12" POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}"
assert_mesh_status "other member server refused on txt" 403 "100.64.0.21" POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}"
assert_mesh_status "server without claimed names refused on eab" 403 "100.64.0.21" POST /api/acme/eab ""
assert_mesh_status "unclaimed name refused" 403 "100.64.0.11" POST /api/acme/txt "{\"name\":\"unclaimed\",\"value\":\"$txt_val\"}"
assert_mesh_status "reserved home refused" 403 "100.64.0.11" POST /api/acme/txt "{\"name\":\"home\",\"value\":\"$txt_val\"}"
assert_mesh_status "reserved ns refused" 403 "100.64.0.11" POST /api/acme/txt "{\"name\":\"ns\",\"value\":\"$txt_val\"}"
assert_mesh_status "reserved ns1 refused" 403 "100.64.0.11" POST /api/acme/txt "{\"name\":\"ns1\",\"value\":\"$txt_val\"}"
assert_mesh_status "reserved nodes refused" 403 "100.64.0.11" POST /api/acme/txt "{\"name\":\"nodes\",\"value\":\"$txt_val\"}"
assert_mesh_status "reserved _acme-challenge refused" 403 "100.64.0.11" POST /api/acme/txt "{\"name\":\"_acme-challenge.photos\",\"value\":\"$txt_val\"}"
assert_mesh_status "bad txt value rejected" 400 "100.64.0.11" POST /api/acme/txt '{"name":"photos","value":"bad!val"}'
assert_mesh_status "CSRF Sec-Fetch-Site blocked" 403 "100.64.0.11" POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}" -H "Sec-Fetch-Site: same-site"

eab_raw="$(mesh_req "100.64.0.11" POST /api/acme/eab "")"
eab_code="${eab_raw##*$'\n'}"
eab_body="${eab_raw%$'\n'*}"
[ "$eab_code" = "200" ] || fail "owner server POST /api/acme/eab got $eab_code body=$eab_body"
[ "$(jq -r .kid <<<"$eab_body")" = "$ACME_EAB_KID" ] || fail "unexpected EAB body: $eab_body"
pass "owner server POST /api/acme/eab returned EAB pair"

used_fqdns="$(stats_json | jq -r .distinct_fqdns)"
rem=$((10 - used_fqdns))
for i in $(seq 1 "$rem"); do
  assert_mesh_status "claim cap${i}" 201 "100.64.0.11" POST /api/names "{\"name\":\"cap${i}\"}"
  assert_mesh_status "write TXT cap${i}" 201 "100.64.0.11" POST /api/acme/txt "{\"name\":\"cap${i}\",\"value\":\"$txt_val\"}"
done
assert_mesh_status "claim capoverflow" 201 "100.64.0.11" POST /api/names '{"name":"capoverflow"}'
assert_mesh_status "11th distinct FQDN hits 429 cap" 429 "100.64.0.11" POST /api/acme/txt "{\"name\":\"capoverflow\",\"value\":\"$txt_val\"}"

step "Test 4a: Broken DNS TXT fails primary WITHOUT triggering fallback EAB"
dc rm -sf portal registrar >/dev/null
init_data_dirs
curl -sf -X POST "http://127.0.0.1:${ACME_CHALLENGE_API_PORT}/test/reset" >/dev/null
curl -sf -X POST "http://127.0.0.1:${ACME_HS_PORT}/test/hs-reset" >/dev/null
curl -sf -X POST "http://127.0.0.1:${ACME_CHALLENGE_API_PORT}/test/mode" \
  -H "Content-Type: application/json" -d '{"corrupt_txt":true}' >/dev/null

ACME_CA_URL="https://pebble1:14000/dir" \
ACME_FALLBACK_CA_URL="https://pebble2:14000/dir" \
ACME_PROPAGATION_TIMEOUT="4s" \
  dc up -d --no-deps registrar

seen_broken_attempts() {
  [ "$(stats_json | jq -r .txt_writes)" -ge 2 ]
}
retry 30 1 seen_broken_attempts || fail "registrar did not attempt primary TXT writes under broken DNS mode"
stats4a="$(stats_json)"
[ "$(jq -r .eab_count <<<"$stats4a")" = "0" ] || fail "broken DNS falsely triggered fallback EAB: $stats4a"
[ ! -e "$WORKDIR/data/home-tls/home.crt" ] || fail "home.crt should not exist under broken DNS"
pass "broken DNS retried primary only (eab_count=0, no home.crt)"

step "Test 4b: Primary HTTP 429 fails over to Pebble2 with lazy EAB and supports SIGHUP renewal"
dc rm -sf registrar >/dev/null
init_data_dirs
curl -sf -X POST "http://127.0.0.1:${ACME_CHALLENGE_API_PORT}/test/reset" >/dev/null
curl -sf -X POST "http://127.0.0.1:${ACME_HS_PORT}/test/hs-reset" >/dev/null

ACME_CA_URL="https://mock429:14000/dir" \
ACME_FALLBACK_CA_URL="https://pebble2:14000/dir" \
ACME_PROPAGATION_TIMEOUT="10s" \
  dc up -d registrar portal

retry 45 1 portal_http_ok "$WORKDIR/pebble2-root.crt" || fail "portal did not fail over to pebble2 HTTPS"
if portal_cert_serial "$WORKDIR/pebble1-root.crt" >/dev/null 2>&1; then
  fail "portal cert unexpectedly verified against pebble1 root instead of pebble2"
fi
stats4b="$(stats_json)"
[ "$(jq -r .eab_count <<<"$stats4b")" = "1" ] || fail "expected exactly 1 EAB mint on failover, got: $stats4b"
fb_serial1="$(portal_cert_serial "$WORKDIR/pebble2-root.crt")"
fb_started1="$(docker inspect --format '{{.State.StartedAt}}' "$(dc ps -q portal)")"
pass "failover active on pebble2 (serial=${fb_serial1}, eab_count=1)"

dc kill -s SIGHUP registrar
check_fb_renewed() {
  local s
  s="$(portal_cert_serial "$WORKDIR/pebble2-root.crt" 2>/dev/null || true)"
  [ -n "$s" ] && [ "$s" != "$fb_serial1" ]
}
retry 30 1 check_fb_renewed || fail "fallback cert serial did not rotate after SIGHUP"
fb_started2="$(docker inspect --format '{{.State.StartedAt}}' "$(dc ps -q portal)")"
[ "$fb_started1" = "$fb_started2" ] || fail "portal restarted during fallback reload"
stats4b_after="$(stats_json)"
[ "$(jq -r .eab_count <<<"$stats4b_after")" = "1" ] || fail "expected reused fallback account without extra EAB mint: $stats4b_after"
pass "SIGHUP renewed on pebble2 in-place with eab_count still 1"

step "Test 5: Share public-certificate DNS-01 issuance, cache reuse, and failover (Pebble e2e)"
dc rm -sf portal registrar >/dev/null
init_data_dirs
curl -sf -X POST "http://127.0.0.1:${ACME_CHALLENGE_API_PORT}/test/reset" >/dev/null
curl -sf -X POST "http://127.0.0.1:${ACME_HS_PORT}/test/hs-reset" >/dev/null
dc restart pebble2 >/dev/null
retry 30 1 curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE2_DIR_PORT}/dir" >/dev/null || fail "pebble2 not ready after restart for Test 5"
curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE2_MGMT_PORT}/roots/0" >"$WORKDIR/pebble2-root.crt"

ACME_CA_URL="https://pebble1:14000/dir" \
ACME_FALLBACK_CA_URL="" \
ACME_PROPAGATION_TIMEOUT="10s" \
  dc up -d registrar portal
retry 45 1 portal_http_ok "$WORKDIR/pebble1-root.crt" || fail "portal/registrar not ready for Test 5"

dc exec -T registrar registrar member add alice >/dev/null
k_alice_srv5="$(issue_key alice server)"
register_node "$k_alice_srv5" "100.64.0.11" "alice-srv5"
dc exec -T registrar registrar sync >/dev/null

assert_mesh_status "alice-srv5 claims photos" 201 "100.64.0.11" POST /api/names '{"name":"photos"}'
assert_mesh_status "alice-srv5 claims sharefb" 201 "100.64.0.11" POST /api/names '{"name":"sharefb"}'

dc --profile join-e2e build join-e2e
dc --profile join-e2e run --rm join-e2e go test -count=1 -v -run TestSharePublicCertPebbleE2E . || fail "TestSharePublicCertPebbleE2E failed"
pass "share public-certificate issuance, restart cache reuse, ownership enforcement, and 429 EAB failover passed"

FAILED=0
echo ""
echo "ACME Pebble e2e suite PASSED."
