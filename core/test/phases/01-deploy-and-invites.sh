# Phase 1: Challenge DNS + Pebble setup, pen deploy, and internet invite redemption.

step "Challenge DNS and test public CA (Pebble)"
if [ "$(uname -s)" != Linux ]; then
  echo "  SKIP  Linux required (Unix socket bind mounts for challenge-dns); CI runs this suite"
  exit 0
fi

mkdir -p "$ACME/cdns" "$ACME/sock" "$ACME/certs"
if [ "$(id -u)" = 0 ]; then chgrp 65532 "$ACME/sock"; fi
chmod 0750 "$ACME/sock"

HOST_GOARCH="$(test_goarch)"
if [ -n "$HOST_GOARCH" ] && [ -f "$SRC/prebuilt/challenge-dns/challenge-dns-linux-$HOST_GOARCH" ]; then
  install -m 0755 "$SRC/prebuilt/challenge-dns/challenge-dns-linux-$HOST_GOARCH" "$ACME/cdns/challenge-dns"
else
  docker run --rm -v "$REPO/deploy/challenge-dns:/src:ro" -v "$ACME/cdns:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
    golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 \
    go build -o /out/challenge-dns . || exit 1
fi
docker network inspect hogman-test-acme >/dev/null 2>&1 || docker network create hogman-test-acme >/dev/null
docker rm -f hogman-run-cdns hogman-run-pebble >/dev/null 2>&1 || true
docker run -d --name hogman-run-cdns --network hogman-test-acme \
  -v "$ACME/cdns:/cdns" -v "$ACME/sock:/run/hogman-acme" \
  -e CDNS_LISTEN=0.0.0.0:53 -e CDNS_PENS_ZONE=pens.hogman.test -e CDNS_GATE_NAME=_acme-challenge.gate.hogman.test \
  -e CDNS_STATE=/cdns/state.json -e CDNS_API_SOCK=/run/hogman-acme/api.sock -e CDNS_ADMIN_SOCK=/cdns/admin.sock \
  -e CDNS_HOURLY_CAP=10 \
  alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf /cdns/challenge-dns serve >/dev/null
retry 20 env CDNS_ADMIN_SOCK="$ACME/cdns/admin.sock" "$ACME/cdns/challenge-dns" cred list || exit 1

gen_pebble_certs "$ACME/certs" "hogman-test-ca" "pebble" "DNS:pebble" 2
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

