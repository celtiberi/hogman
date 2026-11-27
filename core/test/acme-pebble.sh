#!/usr/bin/env bash
# Offline end-to-end test suite for registrar and share ACME DNS-01 against
# real deploy/challenge-dns, real Headscale, real embedded-tsnet registrar,
# Pebble, and a minimal Caddy mock429 responder:
#   1. Initial home.<zone> cert issuance from Pebble1, registrar healthcheck,
#      and TLS verification over WireGuard directly against embedded tsnet.
#   2. Forced renewal via SIGHUP hot-swaps home.<zone>'s certificate in memory
#      (new cert serial, unchanged registrar container StartedAt).
#   3. WireGuard-authenticated mesh API /api/acme/txt and /api/acme/eab auth
#      (including XFF-spoof rejection), live TXT verification in challenge-dns
#      via dig, reserved names, and 10-FQDN cap.
#   4. Failover discipline:
#      (a) Broken DNS TXT fails primary WITHOUT triggering fallback or EAB mint.
#      (b) Primary HTTP 429 fails over to Pebble2 with lazy EAB mint, swaps
#          home.<zone> cert live, and supports SIGHUP renewal on fallback.
#   5. Share public-certificate DNS-01 issuance, restart cache reuse, ownership
#      enforcement, and 429 EAB failover (TestSharePublicCertPebbleE2E) over
#      real WireGuard.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

if [ "$(uname -s)" != Linux ]; then
  echo "SKIP: Linux required (Unix socket bind mounts for challenge-dns); CI runs this suite"
  exit 0
fi

source "$ROOT_DIR/core/test/e2e-lock.sh"
e2e_lock

export ACME_PEN_NAME="${ACME_PEN_NAME:-bobo}"
export ACME_PENS_ZONE="${ACME_PENS_ZONE:-pens.hogman.network}"
export ACME_ZONE="${ACME_ZONE:-${ACME_PEN_NAME}.${ACME_PENS_ZONE}}"
export ACME_PUBLIC_HOST="${ACME_PUBLIC_HOST:-gate.hogman.test}"
export ACME_EAB_KID="${ACME_EAB_KID:-test-eab-kid}"
export ACME_EAB_HMAC="${ACME_EAB_HMAC:-$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n')}"

export ACME_PEBBLE1_DIR_PORT="${ACME_PEBBLE1_DIR_PORT:-14001}"
export ACME_PEBBLE1_MGMT_PORT="${ACME_PEBBLE1_MGMT_PORT:-15001}"
export ACME_PEBBLE2_DIR_PORT="${ACME_PEBBLE2_DIR_PORT:-14002}"
export ACME_PEBBLE2_MGMT_PORT="${ACME_PEBBLE2_MGMT_PORT:-15002}"
export ACME_PEBBLE_BADDNS_DIR_PORT="${ACME_PEBBLE_BADDNS_DIR_PORT:-14003}"
export ACME_MOCK429_PORT="${ACME_MOCK429_PORT:-14004}"
export ACME_DNS_PORT="${ACME_DNS_PORT:-18054}"

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
    dc --profile clients ps >&2 || true
    dc --profile clients logs --tail=80 >&2 || true
  fi
  dc --profile clients --profile join-e2e down -v -t 1 --remove-orphans >/dev/null 2>&1 || true
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

render_template() {
  awk '{
    while (match($0, /@@[A-Z0-9_]+@@/)) {
      name = substr($0, RSTART + 2, RLENGTH - 4)
      $0 = substr($0, 1, RSTART - 1) ENVIRON[name] substr($0, RSTART + RLENGTH)
    }
    print
  }' "$1" > "$2"
}

render_headscale() {
  local core_ip="${1:-}"
  if [ -n "$core_ip" ]; then
    SPLIT_DNS="      \"${ACME_ZONE}\":
        - ${core_ip}"
  else
    SPLIT_DNS="      {}"
  fi
  NETWORK="$ACME_PEN_NAME" \
  ZONE="$ACME_ZONE" \
  PUBLIC_HOST="$ACME_PUBLIC_HOST" \
  STUN_PORT="3478" \
  DERP_IPV4_LINE="" \
  SPLIT_DNS="$SPLIT_DNS" \
    render_template "$ROOT_DIR/core/templates/headscale.yaml" "$WORKDIR/data/headscale/config/config.yaml"
  chmod 644 "$WORKDIR/data/headscale/config/config.yaml"
}

cdns_eab_count() {
  jq -r '[.eab // {} | .[] | length] | add // 0' "$WORKDIR/cdns/state.json" 2>/dev/null || echo 0
}

cdns_distinct_fqdns() {
  jq -r '[.seen // {} | .[] | length] | add // 0' "$WORKDIR/cdns/state.json" 2>/dev/null || echo 0
}

reset_cdns() {
  dc stop challenge-dns >/dev/null 2>&1 || true
  rm -f "$WORKDIR/cdns/state.json" "$WORKDIR/cdns/admin.sock" "$WORKDIR/sock/api.sock"
  dc up -d --force-recreate challenge-dns >/dev/null
  retry 30 1 env CDNS_ADMIN_SOCK="$WORKDIR/cdns/admin.sock" "$WORKDIR/cdns/challenge-dns" cred list >/dev/null \
    || fail "challenge-dns not ready"
  local out tok
  out="$(CDNS_ADMIN_SOCK="$WORKDIR/cdns/admin.sock" "$WORKDIR/cdns/challenge-dns" cred add pen "$ACME_PEN_NAME")" \
    || fail "challenge-dns cred add pen $ACME_PEN_NAME failed"
  tok="$(awk '/^token:/ {print $2}' <<<"$out")"
  [ -n "$tok" ] || fail "empty challenge-dns token"
  printf '%s\n' "$tok" >"$WORKDIR/secrets/challenge_dns_token"
  chown 65532:65532 "$WORKDIR/secrets/challenge_dns_token"
  chmod 600 "$WORKDIR/secrets/challenge_dns_token"
}

reset_registrar_acme_state() {
  dc stop registrar >/dev/null 2>&1 || true
  rm -rf "$WORKDIR/data/registrar/acme" "$WORKDIR/data/home-tls"
  mkdir -p "$WORKDIR/data/registrar/acme" "$WORKDIR/data/home-tls"
  chown -R 65532:65532 "$WORKDIR/data/registrar/acme" "$WORKDIR/data/home-tls"
  chmod 700 "$WORKDIR/data/home-tls"
}

portal_http_ok() {
  local ca_in_container="$1"
  local body
  body="$(dc --profile clients exec -T alice-laptop-tools curl -sf -m 5 \
    --cacert "$ca_in_container" \
    "https://home.${ACME_ZONE}/")" || return 1
  grep -q "You're in" <<<"$body"
}

portal_cert_serial() {
  local ca_in_container="$1"
  local out
  out="$(dc --profile clients exec -T alice-laptop-tools sh -c \
    "echo | openssl s_client -connect home.${ACME_ZONE}:443 -servername home.${ACME_ZONE} -CAfile ${ca_in_container} -verify_hostname home.${ACME_ZONE} -verify_return_error 2>/dev/null | openssl x509 -noout -serial")" || return 1
  printf "%s\n" "${out#serial=}" | tr -d '\r'
}

mesh_req() {
  local tools="$1" method="$2" path="$3" body="${4:-}"
  shift 4 || true
  local ca_file="${MESH_CA_FILE:-/work/pebble1-root.crt}"
  if [ -n "$body" ]; then
    dc --profile clients exec -T "$tools" curl -s -m 8 \
      --cacert "$ca_file" \
      -w '\n%{http_code}' -X "$method" \
      -H "Content-Type: application/json" \
      "$@" \
      -d "$body" \
      "https://home.${ACME_ZONE}${path}"
  else
    dc --profile clients exec -T "$tools" curl -s -m 8 \
      --cacert "$ca_file" \
      -w '\n%{http_code}' -X "$method" \
      -H "Content-Type: application/json" \
      "$@" \
      "https://home.${ACME_ZONE}${path}"
  fi
}

assert_mesh_status() {
  local desc="$1" want="$2" tools="$3" method="$4" path="$5" body="${6:-}"
  shift 6 || true
  local raw code payload
  raw="$(mesh_req "$tools" "$method" "$path" "$body" "$@")"
  raw="${raw//$'\r'/}"
  code="${raw##*$'\n'}"
  payload="${raw%$'\n'*}"
  if [ "$code" != "$want" ]; then
    fail "$desc: got HTTP $code want $want (body=$payload)"
  fi
  pass "$desc ($code)"
}

client_ip() {
  local out line
  out="$(dc --profile clients exec -T "$1" tailscale ip -4 2>/dev/null)" || return 1
  IFS= read -r line <<<"${out//$'\r'/}"
  [ -n "$line" ] && printf '%s\n' "$line"
}

step "Preparing ACME test certificates, challenge-dns binary, and configs in $WORKDIR"
mkdir -p "$WORKDIR"/{certs,config,secrets,cdns,empty-cdns,sock} \
         "$WORKDIR/data"/{headscale/config,headscale/lib,edge,edge-trust,registrar/acme,registrar/tsnet,home-tls}
chmod 755 "$WORKDIR" "$WORKDIR/certs" "$WORKDIR/config" "$WORKDIR/secrets" "$WORKDIR/cdns" "$WORKDIR/empty-cdns" "$WORKDIR/data" "$WORKDIR/data/edge-trust"
chgrp 65532 "$WORKDIR/sock"
chmod 750 "$WORKDIR/sock"
chown -R 65532:65532 "$WORKDIR/data"
chmod 700 "$WORKDIR/data/headscale/lib" "$WORKDIR/data/registrar" "$WORKDIR/data/registrar/tsnet" "$WORKDIR/data/home-tls"

case "$(uname -m)" in x86_64|amd64) HOST_GOARCH=amd64 ;; aarch64|arm64) HOST_GOARCH=arm64 ;; *) HOST_GOARCH="" ;; esac
if [ -n "$HOST_GOARCH" ] && [ -f "$ROOT_DIR/core/prebuilt/challenge-dns/challenge-dns-linux-$HOST_GOARCH" ]; then
  install -m 0755 "$ROOT_DIR/core/prebuilt/challenge-dns/challenge-dns-linux-$HOST_GOARCH" "$WORKDIR/cdns/challenge-dns"
else
  docker run --rm -v "$ROOT_DIR/deploy/challenge-dns:/src:ro" -v "$WORKDIR/cdns:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
    golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 \
    go build -o /out/challenge-dns . || fail "failed building challenge-dns"
fi

cat >"$WORKDIR/cdns/test-eab.json" <<EOF
{"kid":"${ACME_EAB_KID}","hmac_b64url":"${ACME_EAB_HMAC}"}
EOF
chmod 600 "$WORKDIR/cdns/test-eab.json"

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
subjectAltName=DNS:pebble1,DNS:pebble2,DNS:pebble-baddns,DNS:mock429,DNS:localhost,IP:127.0.0.1
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

cat >"$WORKDIR/config/mock429.Caddyfile" <<'EOF'
{
	auto_https off
	admin off
}

https://mock429:14000 {
	tls /certs/server.crt /certs/server.key
	handle /dir {
		header Content-Type application/json
		respond `{"newNonce":"https://mock429:14000/nonce","newAccount":"https://mock429:14000/acct","newOrder":"https://mock429:14000/order","revokeCert":"https://mock429:14000/revoke","keyChange":"https://mock429:14000/key"}` 200
	}
	handle /nonce {
		header Replay-Nonce "{http.request.uuid}"
		header Cache-Control "no-store"
		respond 200
	}
	handle /acct {
		header Replay-Nonce "{http.request.uuid}"
		header Cache-Control "no-store"
		header Location "https://mock429:14000/acct/1"
		header Content-Type application/json
		respond `{"status":"valid","orders":"https://mock429:14000/acct/1/orders"}` 201
	}
	handle /order {
		header Replay-Nonce "{http.request.uuid}"
		header Cache-Control "no-store"
		header Content-Type application/problem+json
		respond `{"type":"urn:ietf:params:acme:error:rateLimited","status":429,"detail":"simulated primary CA rate limit"}` 429
	}
}
EOF

cat >"$WORKDIR/config/edge.Caddyfile" <<'EOF'
{
	local_certs
}

{$PUBLIC_HOST} {
	handle /generate_204 {
		respond 204
	}
	handle /hogman/* {
		reverse_proxy registrar:8081
	}
	@control path /ts2021 /key /derp /derp/probe /derp/latency-check /bootstrap-dns /machine/ping-response /health
	handle @control {
		reverse_proxy headscale:8080 {
			header_up X-Real-IP {remote_host}
		}
	}
	handle {
		respond 404
	}
}
EOF

cp "$ROOT_DIR/core/templates/policy.hujson" "$WORKDIR/data/headscale/config/policy.hujson"
render_headscale ""
chmod 644 "$WORKDIR/config/"* "$WORKDIR/data/headscale/config/"*

step "Starting challenge-dns, empty-dns, Pebble CAs, mock429, Headscale, and edge"
dc up -d empty-dns pebble1 pebble2 pebble-baddns mock429 headscale edge >/dev/null
reset_cdns

retry 30 1 curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE1_DIR_PORT}/dir" >/dev/null || fail "pebble1 not ready"
retry 30 1 curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE2_DIR_PORT}/dir" >/dev/null || fail "pebble2 not ready"
retry 30 1 curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE_BADDNS_DIR_PORT}/dir" >/dev/null || fail "pebble-baddns not ready"
retry 30 1 curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_MOCK429_PORT}/dir" >/dev/null || fail "mock429 not ready"
retry 45 1 dc exec -T headscale headscale health >/dev/null || fail "headscale not ready"
retry 45 1 test -s "$WORKDIR/data/edge/caddy/pki/authorities/local/root.crt" || fail "edge local CA not ready"

cp "$WORKDIR/data/edge/caddy/pki/authorities/local/root.crt" "$WORKDIR/data/edge-trust/root.crt"
chmod 644 "$WORKDIR/data/edge-trust/root.crt"
curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE1_MGMT_PORT}/roots/0" >"$WORKDIR/pebble1-root.crt"
curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE2_MGMT_PORT}/roots/0" >"$WORKDIR/pebble2-root.crt"
chmod 644 "$WORKDIR/pebble1-root.crt" "$WORKDIR/pebble2-root.crt"

dc exec -T headscale headscale policy set --file /etc/headscale/policy.hujson >/dev/null
dc exec -T headscale headscale apikeys create --expiration 3650d | tail -1 | tr -d '\r\n' >"$WORKDIR/secrets/headscale_api_key"
chown 65532:65532 "$WORKDIR/secrets/headscale_api_key"
chmod 600 "$WORKDIR/secrets/headscale_api_key"

infra_key="$(dc exec -T headscale headscale preauthkeys create --tags tag:infra --expiration 15m --output json | jq -r .key)"
[ -n "$infra_key" ] && [ "$infra_key" != "null" ] || fail "failed creating infra preauthkey"
printf '%s\n' "$infra_key" >"$WORKDIR/data/registrar/tsnet/.authkey"
chown 65532:65532 "$WORKDIR/data/registrar/tsnet/.authkey"
chmod 600 "$WORKDIR/data/registrar/tsnet/.authkey"
pass "Pebble CAs, challenge-dns, mock429, Headscale, and edge healthy"

step "Bootstrapping embedded-tsnet registrar and mesh clients"
if [ "${ACME_NO_BUILD:-0}" = "1" ]; then
  ACME_CA_URL="https://pebble1:14000/dir" ACME_FALLBACK_CA_URL="" \
    dc up -d --no-build registrar >/dev/null
else
  ACME_CA_URL="https://pebble1:14000/dir" ACME_FALLBACK_CA_URL="" \
    dc up -d --build registrar >/dev/null
fi

retry 90 1 test -s "$WORKDIR/data/registrar/tsnet/mesh-ip" || fail "registrar did not publish tsnet/mesh-ip"
CORE_MESH_IP="$(tr -d '\r\n' <"$WORKDIR/data/registrar/tsnet/mesh-ip")"
render_headscale "$CORE_MESH_IP"
dc restart headscale >/dev/null
retry 45 1 dc exec -T headscale headscale health >/dev/null || fail "headscale not ready after split-DNS reload"
retry 60 1 dc exec -T registrar registrar health >/dev/null || fail "registrar health failed"

dc exec -T registrar registrar member add alice >/dev/null
dc exec -T registrar registrar member add bob >/dev/null
issue_key() {
  dc exec -T registrar registrar device key "$1" "$2" | awk '/^key:/ {print $2}'
}
export ALICE_LAPTOP_KEY="$(issue_key alice personal)"
export ALICE_SRV1_KEY="$(issue_key alice server)"
export ALICE_SRV2_KEY="$(issue_key alice server)"
export BOB_SRV1_KEY="$(issue_key bob server)"

dc --profile clients up -d alice-laptop alice-laptop-tools alice-srv1 alice-srv1-tools alice-srv2 alice-srv2-tools bob-srv1 bob-srv1-tools >/dev/null
for c in alice-laptop alice-srv1 alice-srv2 bob-srv1; do
  retry 90 1 client_ip "$c" >/dev/null || fail "$c did not get a mesh IP"
done
ALICE_SRV1_IP="$(client_ip alice-srv1)"
retry 30 1 dc exec -T registrar registrar sync >/dev/null || fail "registrar sync failed"
pass "embedded-tsnet registrar ($CORE_MESH_IP) and 4 WireGuard clients enrolled"

step "Test 1: Initial home.${ACME_ZONE} cert issuance + embedded tsnet portal HTTPS"
retry 60 1 portal_http_ok /work/pebble1-root.crt || fail "portal did not serve valid pebble1 HTTPS over WireGuard"
dc exec -T registrar registrar health >/dev/null || fail "registrar health failed"
serial1="$(portal_cert_serial /work/pebble1-root.crt)"
started1="$(docker inspect --format '{{.State.StartedAt}}' "$(dc ps -q registrar)")"
[ "$(cdns_eab_count)" = "0" ] || fail "unexpected fallback EAB mint on happy path: eab_count=$(cdns_eab_count)"
[ "$(cdns_distinct_fqdns)" = "1" ] || fail "expected 1 distinct FQDN after home issuance, got $(cdns_distinct_fqdns)"
home_txt="$(dig @127.0.0.1 -p "${ACME_DNS_PORT}" +short TXT "_acme-challenge.home.${ACME_ZONE}." | tr -d '\r')"
[ -z "$home_txt" ] || fail "expected challenge TXT cleanup after home issuance, got=$home_txt"
pass "embedded portal serving pebble1 cert serial=${serial1} with zero EAB calls and clean TXT"

step "Test 2: SIGHUP forces renewal and hot-swaps home.${ACME_ZONE} cert in memory"
dc kill -s SIGHUP registrar
check_renewed() {
  local s
  s="$(portal_cert_serial /work/pebble1-root.crt 2>/dev/null || true)"
  [ -n "$s" ] && [ "$s" != "$serial1" ]
}
retry 45 1 check_renewed || fail "portal cert serial did not rotate after SIGHUP (stayed ${serial1})"
started2="$(docker inspect --format '{{.State.StartedAt}}' "$(dc ps -q registrar)")"
[ "$started1" = "$started2" ] || fail "registrar container restarted unexpectedly ($started1 -> $started2)"
portal_http_ok /work/pebble1-root.crt || fail "portal HTTP check failed after reload"
pass "registrar rotated cert in-place (StartedAt=${started2}, new serial=$(portal_cert_serial /work/pebble1-root.crt))"

step "Test 3: WireGuard-authenticated /api/acme/txt and /api/acme/eab auth, live DNS, and 10-FQDN cap"
assert_mesh_status "alice-srv1 claims photos" 201 alice-srv1-tools POST /api/names '{"name":"photos"}'
assert_mesh_status "alice-srv1 claims blog.photos" 201 alice-srv1-tools POST /api/names '{"name":"blog.photos"}'

txt_val="test_txt_value_0123456789abcdef"
assert_mesh_status "alice-srv1 writes TXT for photos" 201 alice-srv1-tools POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}"
got_dig="$(dig @127.0.0.1 -p "${ACME_DNS_PORT}" +short TXT "_acme-challenge.photos.${ACME_ZONE}." | tr -d '"' | tr -d '\r')"
[ "$got_dig" = "$txt_val" ] || fail "dig TXT mismatch for photos: got=$got_dig want=$txt_val"
pass "challenge-dns answered dig TXT=${got_dig}"

assert_mesh_status "alice-srv1 deletes TXT for photos" 204 alice-srv1-tools DELETE /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}"
got_dig_after="$(dig @127.0.0.1 -p "${ACME_DNS_PORT}" +short TXT "_acme-challenge.photos.${ACME_ZONE}." | tr -d '\r')"
[ -z "$got_dig_after" ] || fail "expected empty TXT after DELETE, got=$got_dig_after"
pass "challenge-dns cleared TXT on DELETE"

assert_mesh_status "alice-srv1 writes TXT for sub-name blog.photos" 201 alice-srv1-tools POST /api/acme/txt "{\"name\":\"blog.photos.${ACME_ZONE}\",\"value\":\"$txt_val\"}"
assert_mesh_status "alice-srv1 deletes TXT for sub-name blog.photos" 204 alice-srv1-tools DELETE /api/acme/txt "{\"name\":\"blog.photos\",\"value\":\"$txt_val\"}"

assert_mesh_status "personal device refused on /api/acme/txt" 403 alice-laptop-tools POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}"
assert_mesh_status "personal device refused on /api/acme/eab" 403 alice-laptop-tools POST /api/acme/eab ""
assert_mesh_status "same member other server refused" 403 alice-srv2-tools POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}"
assert_mesh_status "other member server refused on txt" 403 bob-srv1-tools POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}"
assert_mesh_status "spoofed X-Forwarded-For ignored on /api/acme/txt" 403 bob-srv1-tools POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}" -H "X-Forwarded-For: ${ALICE_SRV1_IP}"
assert_mesh_status "server without claimed names refused on eab" 403 bob-srv1-tools POST /api/acme/eab ""
assert_mesh_status "unclaimed name refused" 403 alice-srv1-tools POST /api/acme/txt "{\"name\":\"unclaimed\",\"value\":\"$txt_val\"}"
assert_mesh_status "reserved home refused" 403 alice-srv1-tools POST /api/acme/txt "{\"name\":\"home\",\"value\":\"$txt_val\"}"
assert_mesh_status "reserved ns refused" 403 alice-srv1-tools POST /api/acme/txt "{\"name\":\"ns\",\"value\":\"$txt_val\"}"
assert_mesh_status "reserved ns1 refused" 403 alice-srv1-tools POST /api/acme/txt "{\"name\":\"ns1\",\"value\":\"$txt_val\"}"
assert_mesh_status "reserved nodes refused" 403 alice-srv1-tools POST /api/acme/txt "{\"name\":\"nodes\",\"value\":\"$txt_val\"}"
assert_mesh_status "reserved _acme-challenge refused" 403 alice-srv1-tools POST /api/acme/txt "{\"name\":\"_acme-challenge.photos\",\"value\":\"$txt_val\"}"
assert_mesh_status "bad txt value rejected" 400 alice-srv1-tools POST /api/acme/txt '{"name":"photos","value":"bad!val"}'
assert_mesh_status "CSRF Sec-Fetch-Site blocked" 403 alice-srv1-tools POST /api/acme/txt "{\"name\":\"photos\",\"value\":\"$txt_val\"}" -H "Sec-Fetch-Site: same-site"

eab_raw="$(mesh_req alice-srv1-tools POST /api/acme/eab "")"
eab_raw="${eab_raw//$'\r'/}"
eab_code="${eab_raw##*$'\n'}"
eab_body="${eab_raw%$'\n'*}"
[ "$eab_code" = "200" ] || fail "owner server POST /api/acme/eab got $eab_code body=$eab_body"
[ "$(jq -r .kid <<<"$eab_body")" = "$ACME_EAB_KID" ] || fail "unexpected EAB body: $eab_body"
[ "$(jq -r .contact <<<"$eab_body")" = "ops@example.com" ] || fail "unexpected EAB contact: $eab_body"
pass "owner server POST /api/acme/eab returned EAB pair + contact"

used_fqdns="$(cdns_distinct_fqdns)"
rem=$((10 - used_fqdns))
for i in $(seq 1 "$rem"); do
  assert_mesh_status "claim cap${i}" 201 alice-srv1-tools POST /api/names "{\"name\":\"cap${i}\"}"
  assert_mesh_status "write TXT cap${i}" 201 alice-srv1-tools POST /api/acme/txt "{\"name\":\"cap${i}\",\"value\":\"$txt_val\"}"
done
assert_mesh_status "claim capoverflow" 201 alice-srv1-tools POST /api/names '{"name":"capoverflow"}'
assert_mesh_status "11th distinct FQDN hits 429 cap" 429 alice-srv1-tools POST /api/acme/txt "{\"name\":\"capoverflow\",\"value\":\"$txt_val\"}"

step "Test 4a: Broken DNS TXT fails primary WITHOUT triggering fallback EAB"
reset_registrar_acme_state
reset_cdns

ACME_CA_URL="https://pebble-baddns:14000/dir" \
ACME_FALLBACK_CA_URL="https://pebble2:14000/dir" \
ACME_PROPAGATION_TIMEOUT="4s" \
  dc up -d --no-build --no-deps --force-recreate registrar >/dev/null

seen_broken_attempts() {
  local n
  n="$(dc logs challenge-dns 2>&1 | grep -c 'msg="txt put"' || true)"
  [ "${n:-0}" -ge 2 ]
}
retry 45 1 seen_broken_attempts || fail "registrar did not retry primary TXT writes under broken DNS mode"
[ "$(cdns_eab_count)" = "0" ] || fail "broken DNS falsely triggered fallback EAB: eab_count=$(cdns_eab_count)"
[ ! -e "$WORKDIR/data/home-tls/home.crt" ] || fail "home.crt should not exist under broken DNS"
pass "broken DNS retried primary only (eab_count=0, no home.crt)"

step "Test 4b: Primary HTTP 429 fails over to Pebble2 with lazy EAB and supports SIGHUP renewal"
reset_registrar_acme_state
reset_cdns

ACME_CA_URL="https://mock429:14000/dir" \
ACME_FALLBACK_CA_URL="https://pebble2:14000/dir" \
ACME_PROPAGATION_TIMEOUT="10s" \
  dc up -d --no-build --no-deps --force-recreate registrar >/dev/null

retry 60 1 portal_http_ok /work/pebble2-root.crt || fail "portal did not fail over to pebble2 HTTPS"
if portal_cert_serial /work/pebble1-root.crt >/dev/null 2>&1; then
  fail "portal cert unexpectedly verified against pebble1 root instead of pebble2"
fi
[ "$(cdns_eab_count)" = "1" ] || fail "expected exactly 1 EAB mint on failover, got $(cdns_eab_count)"
fb_serial1="$(portal_cert_serial /work/pebble2-root.crt)"
fb_started1="$(docker inspect --format '{{.State.StartedAt}}' "$(dc ps -q registrar)")"
pass "failover active on pebble2 (serial=${fb_serial1}, eab_count=1)"

dc kill -s SIGHUP registrar
check_fb_renewed() {
  local s
  s="$(portal_cert_serial /work/pebble2-root.crt 2>/dev/null || true)"
  [ -n "$s" ] && [ "$s" != "$fb_serial1" ]
}
retry 45 1 check_fb_renewed || fail "fallback cert serial did not rotate after SIGHUP"
fb_started2="$(docker inspect --format '{{.State.StartedAt}}' "$(dc ps -q registrar)")"
[ "$fb_started1" = "$fb_started2" ] || fail "registrar restarted during fallback reload"
[ "$(cdns_eab_count)" = "1" ] || fail "expected reused fallback account without extra EAB mint, got $(cdns_eab_count)"
pass "SIGHUP renewed on pebble2 in-place with eab_count still 1"

step "Test 5: Share public-certificate DNS-01 issuance, cache reuse, and failover (Pebble e2e)"
reset_registrar_acme_state
reset_cdns
dc restart pebble2 >/dev/null
retry 30 1 curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE2_DIR_PORT}/dir" >/dev/null || fail "pebble2 not ready after restart for Test 5"
curl -sf --cacert "$WORKDIR/certs/ca.crt" "https://127.0.0.1:${ACME_PEBBLE2_MGMT_PORT}/roots/0" >"$WORKDIR/pebble2-root.crt"
chmod 644 "$WORKDIR/pebble2-root.crt"

ACME_CA_URL="https://pebble1:14000/dir" \
ACME_FALLBACK_CA_URL="" \
ACME_PROPAGATION_TIMEOUT="10s" \
  dc up -d --no-build --no-deps --force-recreate registrar >/dev/null
retry 60 1 portal_http_ok /work/pebble1-root.crt || fail "registrar not ready for Test 5"

assert_mesh_status "alice-srv1 claims photos" 201 alice-srv1-tools POST /api/names '{"name":"photos"}'
assert_mesh_status "alice-srv1 claims sharefb" 201 alice-srv1-tools POST /api/names '{"name":"sharefb"}'

if [ "${ACME_NO_BUILD:-0}" != "1" ]; then
  dc --profile join-e2e build join-e2e
fi
dc --profile clients --profile join-e2e run --rm --no-deps join-e2e \
  /usr/local/bin/join.test -test.v -test.count=1 -test.run '^TestSharePublicCertPebbleE2E$' \
  || fail "TestSharePublicCertPebbleE2E failed"
pass "share public-certificate issuance, restart cache reuse, ownership enforcement, and 429 EAB failover passed"

FAILED=0
echo ""
echo "ACME Pebble e2e suite PASSED."
