#!/usr/bin/env bash
# Local test of a shared host: one front door, two separate pens, a member
# joining each. Needs Docker and jq. Uses test certificates throughout.
#
# usage: deploy/test-host.sh [--keep]
set -uo pipefail
# shellcheck source=/dev/null
. "$(dirname "$0")/../core/test/e2e-lock.sh"
e2e_lock

REPO="$(cd "$(dirname "$0")/.." && pwd)"
KEEP=false; [ "${1:-}" = --keep ] && KEEP=true
export HOGMAN_HOME="$(mktemp -d "${TMPDIR:-/tmp}/hogman-host.XXXXXX")"
HOST="$REPO/deploy/hogman-host"
FRONT_CA="$HOGMAN_HOME/front/data/caddy/pki/authorities/local/root.crt"

pass=0; fail=0
step()  { echo; echo "== $*"; }
check() {
  local d="$1" log="$HOGMAN_HOME/.check.out"; shift
  if "$@" >"$log" 2>&1; then echo "  PASS  $d"; pass=$((pass + 1))
  else
    echo "  FAIL  $d"; fail=$((fail + 1))
    [ -s "$log" ] && tail -n 5 "$log" | sed 's/^/        | /'
  fi
}
fails() { ! "$@" >/dev/null 2>&1; }
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
perm()  { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
secret_dirs_ok() {
  local d
  for d in secrets/registrar mesh registrar headscale/lib api home-tls caddy-admin; do
    [ "$(perm "$HOGMAN_HOME/pens/bobo/data/$d")" = 700 ] || return 1
  done
}
retry() { local n="$1"; shift; for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

cleanup() {
  if [ "$KEEP" = true ]; then echo; echo "Left running. HOGMAN_HOME=$HOGMAN_HOME"; return; fi
  for c in client-bobo client-zebra client-signup client-alpha hogman-test-cdns hogman-test-pebble; do docker rm -f "$c" >/dev/null 2>&1; done
  (cd "$HOGMAN_HOME/signup" 2>/dev/null && docker compose down -v >/dev/null 2>&1)
  for n in bobo zebra alpha smithy jones; do (cd "$HOGMAN_HOME/pens/$n" 2>/dev/null && ./hogman down -v --remove-orphans >/dev/null 2>&1); done
  (cd "$HOGMAN_HOME/front" 2>/dev/null && docker compose down -v >/dev/null 2>&1)
  for n in bobo zebra alpha smithy jones; do docker network rm "pen-$n-core" >/dev/null 2>&1; done
  docker network rm hogman-front >/dev/null 2>&1
  rm -rf "$HOGMAN_HOME"
}
trap 'cleanup; e2e_unlock' EXIT

step "Set up the host"
mkdir -p "$HOGMAN_HOME/src"
rsync -a --exclude data --exclude .env "$REPO/core/" "$HOGMAN_HOME/src/"
check "front door starts" "$HOST" init --test

step "Public certificates (D-18): the challenge DNS server and a test CA"
# The registrars reach the challenge DNS server over a Unix socket in a bind
# mount, as on a real host, which needs Linux (Docker Desktop can't share one).
if [ "$(uname -s)" != Linux ]; then
  echo "  SKIP  public pens and sign-ups need Linux; CI runs them"
  echo; echo "Result: $pass passed, $fail failed (public sections skipped)"; [ "$fail" -eq 0 ]; exit
fi
ACME="$HOGMAN_HOME/acme"
mkdir -p "$ACME/cdns" "$ACME/sock" "$ACME/certs"
chgrp 65532 "$ACME/sock" && chmod 0750 "$ACME/sock"   # like /run/hogman-acme: the registrars' group may enter
build_cdns() {
  docker run --rm -v "$REPO/deploy/challenge-dns:/src:ro" -v "$ACME/cdns:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false golang:1.27-alpine go build -o /out/challenge-dns .
}
check "challenge-dns builds" build_cdns
docker run -d --name hogman-test-cdns --network hogman-front \
  -v "$ACME/cdns:/cdns" -v "$ACME/sock:/run/hogman-acme" \
  -e CDNS_LISTEN=0.0.0.0:53 -e CDNS_PENS_ZONE=pens.hogman.test -e CDNS_GATE_NAME=_acme-challenge.gate.hogman.test \
  -e CDNS_STATE=/cdns/state.json -e CDNS_API_SOCK=/run/hogman-acme/api.sock -e CDNS_ADMIN_SOCK=/cdns/admin.sock \
  alpine:3.22 /cdns/challenge-dns serve >/dev/null
check "challenge-dns answers on its admin socket" retry 20 env CDNS_ADMIN_SOCK="$ACME/cdns/admin.sock" "$ACME/cdns/challenge-dns" cred list
# Pebble, Let's Encrypt's test CA, asks the challenge DNS server for DNS-01.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$ACME/certs/ca.key" -out "$ACME/certs/ca.crt" \
  -days 2 -subj "/CN=hogman-test-host-ca" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" >/dev/null 2>&1
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
docker run -d --name hogman-test-pebble --network hogman-front --network-alias pebble -e PEBBLE_VA_NOSLEEP=1 \
  -v "$ACME/certs:/certs:ro" -v "$ACME/pebble.json:/pebble.json:ro" \
  ghcr.io/letsencrypt/pebble:2.10.3 -config /pebble.json -dnsserver hogman-test-cdns:53 >/dev/null
pebble_get() { docker run --rm --network hogman-front -v "$ACME/certs:/c:ro" nicolaka/netshoot:v0.14 curl -sf --cacert /c/ca.crt "https://pebble:$1"; }
check "Pebble is up" retry 30 pebble_get 14000/dir
pebble_get 15000/roots/0 > "$ACME/issued-root.crt"
check "Pebble's issuing root is fetched" grep -q 'BEGIN CERTIFICATE' "$ACME/issued-root.crt"
# The front door's *.gate wildcard (on a real host: gate-cert-setup's Let's
# Encrypt certificate), here signed by the front door's own test CA, which
# the test clients already trust.
FRONT_PKI="$HOGMAN_HOME/front/data/caddy/pki/authorities/local"
mkdir -p "$ACME/gate-tls"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$ACME/gate-tls/gate.key" \
  -out "$ACME/gate.csr" -subj "/CN=*.gate.hogman.test" >/dev/null 2>&1
printf 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:*.gate.hogman.test\n' > "$ACME/gate.ext"
openssl x509 -req -in "$ACME/gate.csr" -CA "$FRONT_PKI/root.crt" -CAkey "$FRONT_PKI/root.key" -CAcreateserial \
  -out "$ACME/gate-tls/gate.crt" -days 2 -extfile "$ACME/gate.ext" >/dev/null 2>&1
fuid="$(grep -h '^FRONT_UID=' "$HOGMAN_HOME/host.env" | cut -d= -f2 | tr -d "'")"
chown -R "${fuid:-0}" "$ACME/gate-tls"; chmod 644 "$ACME/gate-tls/gate.crt"; chmod 600 "$ACME/gate-tls/gate.key"
check "the test *.gate wildcard is made" test -s "$ACME/gate-tls/gate.crt"
# What a real host gets from challenge-dns-setup and gate-cert-setup; here the
# test's own server, CA and names. The broker reads these too (host.env).
cat >> "$HOGMAN_HOME/host.env" <<EOF
GATE_TLS='$ACME/gate-tls'
CDNS_BIN='$ACME/cdns/challenge-dns'
CDNS_ADMIN='$ACME/cdns/admin.sock'
HOGMAN_ACME_SOCK_DIR='$ACME/sock'
ACME_CA_URL='https://pebble:14000/dir'
ACME_RESOLVERS='hogman-test-cdns:53'
HOGMAN_TEST_ACME_ROOT='$ACME/certs/ca.crt'
GATE_DOMAIN='gate.hogman.test'
EOF
check "add <pen> refuses before a pens zone is set" fails "$HOST" add bobo
check "pens-zone sets where public pens live" "$HOST" pens-zone pens.hogman.test
# A pen's registrar reaches the challenge DNS server and the CA on the pen's
# own network (on a real host: the socket, and the internet).
pen_net() {
  docker network inspect "pen-$1-core" >/dev/null 2>&1 || docker network create "pen-$1-core" >/dev/null
  docker network connect "pen-$1-core" hogman-test-cdns
  docker network connect --alias pebble "pen-$1-core" hogman-test-pebble
}
pen_net_disconnect() {
  docker network disconnect -f "pen-$1-core" hogman-test-cdns >/dev/null 2>&1 || true
  docker network disconnect -f "pen-$1-core" hogman-test-pebble >/dev/null 2>&1 || true
}

step "Two pens on one host"
pen_net bobo && "$HOST" add bobo || exit 1
pen_net zebra && "$HOST" add zebra || exit 1
"$HOST" list
check "both pens are listed as running" sh -c "'$HOST' list | grep -c running | grep -qx 2"
check "each pen has its own relay port" sh -c "[ \"\$(grep -h ^STUN_PORT= $HOGMAN_HOME/pens/*/.env | sort -u | wc -l | tr -d ' ')\" = 2 ]"

# A computer on the internet with nothing but the join tool. It reaches the
# host only through the front door.
client() {  # client <pen>. Public DNS would point both names at the host; here, at the front door.
  local front_ip; front_ip="$(docker inspect -f '{{(index .NetworkSettings.Networks "hogman-front").IPAddress}}' hogman-front-front-1)"
  docker run -d --name "client-$1" --network hogman-front \
    --add-host "bobo.gate.hogman.test:$front_ip" --add-host "zebra.gate.hogman.test:$front_ip" \
    -e HOGMAN_ACME_CA_ROOT=/issued-root.crt -v "$ACME/issued-root.crt:/issued-root.crt:ro" \
    -v "$FRONT_CA:/front-ca.crt:ro" -v "$HOGMAN_HOME/pens/$1/data/join-dl:/dl:ro" \
    --entrypoint sh nicolaka/netshoot:v0.14 -c \
    'cp /front-ca.crt /usr/local/share/ca-certificates/front.crt && update-ca-certificates >/dev/null 2>&1; exec sleep infinity' >/dev/null
}
in_client() { local c="$1"; shift; docker exec "client-$c" "$@"; }

for pen in bobo zebra; do
  step "Pen $pen, through the front door"
  host="$pen.gate.hogman.test"
  zone="$pen.pens.hogman.test"
  check "$pen's front door is $host" grep -qx "PUBLIC_HOST=$host" "$HOGMAN_HOME/pens/$pen/.env"
  check "$pen's zone is $zone" grep -qx "ZONE=$zone" "$HOGMAN_HOME/pens/$pen/.env"
  check "$pen runs no certificate authority" fails docker inspect "pen-$pen-step-ca-1"
  check "$pen has no root key" test ! -e "$HOGMAN_HOME/pens/$pen/data/pki"
  check "$pen's challenge DNS credential is kept for the registrar only" test "$(perm "$HOGMAN_HOME/pens/$pen/data/secrets/registrar")" = 700
  "$HOST" pen "$pen" member add "${pen}-owner" --role owner >/dev/null
  link="$("$HOST" pen "$pen" invite create --note test | awk '/^link:/ {print $2}')"
  check "$pen's invite link carries no fingerprint" bash -c '[[ "$1" =~ ^https://'"$pen"'\.gate\.hogman\.test/join#t=[A-Za-z0-9._-]+$ ]]' _ "$link"
  client "$pen"
  retry 20 in_client "$pen" test -s /etc/ssl/certs/ca-certificates.crt
  info_ok() { in_client "$pen" curl -sf "https://$host/hogman/v1/network" | jq -e --arg z "$zone" '.zone == $z and .cert_mode == "public" and (.root_ca // "") == "" and (.root_fingerprint // "") == ""'; }
  check "https://$host answers as public pen $pen" info_ok
  check "the join page is served for $pen" match hogman in_client "$pen" curl -sf "https://$host/join"
  out="$(in_client "$pen" sh -c '"/dl/hogman-$(uname -s)-$(uname -m)" --no-open --handle member1 --hostname laptop "$1"' _ "$link" 2>&1)"; rc=$?
  [ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
  check "a member joins $pen (exit $rc)" grep -q "You're in. You are member1 on $zone" <<<"$out"
  check "nothing was added to the computer's trust store" no_match hogman docker exec "client-$pen" ls /usr/local/share/ca-certificates
  pen_proxy="$(in_client "$pen" sh -c 'jq -r .proxy_addr "${XDG_CONFIG_HOME:-$HOME/.config}/hogman/'"$zone"'/config.json"' 2>/dev/null)"
  check "home.$zone has a public certificate from the CA" in_client "$pen" sh -c 'curl -sf --cacert /issued-root.crt -x "http://$1" "https://home.'"$zone"'/api/me" | jq -e ".member.handle == \"member1\""' _ "$pen_proxy"
  check "the registrar of $pen recorded the device" retry 10 match 'member1.*laptop' "$HOST" pen "$pen" device list
  stun="$(grep -h ^STUN_PORT= "$HOGMAN_HOME/pens/$pen/.env" | cut -d= -f2)"
  derp_port() {
    local out
    out="$(docker exec "pen-$pen-core-mesh-1" tailscale debug derp-map 2>/dev/null | jq -r '.Regions[].Nodes[].STUNPort')" || return 1
    grep -qx -- "$stun" <<<"$out"
  }
  check "$pen's relay advertises its own port ($stun)" derp_port
done

step "Pens are separate"
check "bobo has no per-pen edge container"  fails docker inspect pen-bobo-edge-1
check "zebra has no per-pen edge container" fails docker inspect pen-zebra-edge-1
check "bobo has no coredns container"       fails docker inspect pen-bobo-coredns-1
check "zebra has no coredns container"      fails docker inspect pen-zebra-coredns-1
check "bobo runs 4 containers"  test "$(docker ps -q --filter name=^/pen-bobo- | wc -l | tr -d ' ')" = 4
check "zebra runs 4 containers" test "$(docker ps -q --filter name=^/pen-zebra- | wc -l | tr -d ' ')" = 4
pen_isolated() {  # no container in a pen joins hogman-front or another pen's network
  local pen="$1" nets
  nets="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "pen-$pen-core-mesh-1" "pen-$pen-headscale-1")"
  [ "$(tr ' ' '\n' <<<"$nets" | grep -v '^$' | sort -u | tr '\n' ' ')" = "pen-$pen-core " ]
}
check "bobo's containers stay off hogman-front and zebra" pen_isolated bobo
check "zebra's containers stay off hogman-front and bobo" pen_isolated zebra
front_dns_ok() {  # the front door resolves each pen's unique container names only to that pen
  local pen="$1" want_core want_hs got_core got_hs
  want_core="$(docker inspect -f '{{(index .NetworkSettings.Networks "pen-'"$pen"'-core").IPAddress}}' "pen-$pen-core-mesh-1")"
  want_hs="$(docker inspect -f '{{(index .NetworkSettings.Networks "pen-'"$pen"'-core").IPAddress}}' "pen-$pen-headscale-1")"
  for _ in 1 2 3 4 5 6; do
    got_core="$(docker exec hogman-front-front-1 getent hosts "pen-$pen-core-mesh-1" | awk 'NR==1 {print $1}')"
    got_hs="$(docker exec hogman-front-front-1 getent hosts "pen-$pen-headscale-1" | awk 'NR==1 {print $1}')"
    [ "$got_core" = "$want_core" ] && [ "$got_hs" = "$want_hs" ] || return 1
  done
}
check "front door reaches only bobo's core and headscale"  front_dns_ok bobo
check "front door reaches only zebra's core and headscale" front_dns_ok zebra
check "front door hides Headscale admin API (404)" test "$(in_client bobo curl -s -o /dev/null -w '%{http_code}' https://bobo.gate.hogman.test/api/v1/node)" = 404
check "front door hides Headscale Swagger (404)"   test "$(in_client bobo curl -s -o /dev/null -w '%{http_code}' https://bobo.gate.hogman.test/swagger)" = 404
front_blocked_routes_ok() {
  local p
  for p in / /version /apple /windows /register/test /auth/test; do
    [ "$(in_client bobo curl -s -o /dev/null -w '%{http_code}' "https://bobo.gate.hogman.test$p")" = 404 ] || return 1
  done
}
check "front door blocks Headscale root, register, auth, apple, windows, version (404)" front_blocked_routes_ok
check "front door allows Headscale /health" match '"pass"' in_client bobo curl -sf https://bobo.gate.hogman.test/health
check "front door allows Tailscale /key" match '"publicKey"' in_client bobo curl -sf 'https://bobo.gate.hogman.test/key?v=138'
check "front door allows /generate_204" test "$(in_client bobo curl -s -o /dev/null -w '%{http_code}' https://bobo.gate.hogman.test/generate_204)" = 204
join_hdrs="$(in_client bobo curl -sI https://bobo.gate.hogman.test/join | tr -d '\r')"
check "front door sets anti-framing headers and Origin-Agent-Cluster on /join" bash -c "grep -iq '^x-frame-options: DENY' <<<\"\$1\" && grep -iq \"^content-security-policy:.*frame-ancestors 'none'\" <<<\"\$1\" && grep -iq '^origin-agent-cluster: ?1' <<<\"\$1\"" _ "$join_hdrs"
check "front door serves /join/assets/join.js" test "$(in_client bobo curl -s -o /dev/null -w '%{http_code}' https://bobo.gate.hogman.test/join/assets/join.js)" = 200
check "front door serves /join/dl/SHA256SUMS"  test "$(in_client bobo curl -s -o /dev/null -w '%{http_code}' https://bobo.gate.hogman.test/join/dl/SHA256SUMS)" = 200
dl_hdrs="$(in_client bobo curl -sI https://bobo.gate.hogman.test/join/dl/SHA256SUMS | tr -d '\r')"
check "front door sets nosniff on /join/dl/" grep -iq '^x-content-type-options: nosniff' <<<"$dl_hdrs"
cross() { in_client bobo curl -sf "https://zebra.gate.hogman.test/hogman/v1/network" | jq -e '.zone == "zebra.pens.hogman.test"'; }
check "both control hosts answer through the same front door" cross
id_b="$(cat "$HOGMAN_HOME/pens/bobo/.challenge-dns-id")"
id_z="$(cat "$HOGMAN_HOME/pens/zebra/.challenge-dns-id")"
check "each pen has its own challenge DNS credential and no CA" bash -c 'test -n "$1" -a -n "$2" -a "$1" != "$2" && test ! -e "$3/pens/bobo/data/pki" && test ! -e "$3/pens/zebra/data/pki"' _ "$id_b" "$id_z" "$HOGMAN_HOME"
check "bobo's members are not zebra's" no_match bobo-owner "$HOST" pen zebra member list

step "The short join command: curl https://<pen>.gate.../start | sh"
start_hdrs="$(in_client zebra curl -sI https://bobo.gate.hogman.test/start | tr -d '\r')"
check "the front door serves /start as plain text" grep -iq '^content-type: text/plain' <<<"$start_hdrs"
link3="$("$HOST" pen bobo invite create --note start-script | awk '/^link:/ {print $2}')"
out3="$(in_client zebra sh -c 'curl -fsSL https://bobo.gate.hogman.test/start | sh -s -- "$1" --no-open --handle member3 --hostname laptop3' _ "$link3" 2>&1)"; rc3=$?
[ $rc3 = 0 ] || echo "$out3" | tail -12 | sed 's/^/        | /'
check "it checks the download's SHA-256" grep -q "checked: SHA-256 matches" <<<"$out3"
check "a member joins bobo with it (exit $rc3)" grep -q "You're in. You are member3 on bobo.pens.hogman.test" <<<"$out3"
check "the tool is kept as ~/hogman" in_client zebra test -x /root/hogman
bad_link="$(in_client zebra sh -c 'curl -fsSL https://bobo.gate.hogman.test/start | sh -s -- "https://evil.example/notjoin" 2>&1' || true)"
check "it refuses something that isn't an invite link" grep -q "doesn't look like a Hogman invite link" <<<"$bad_link"

step "One computer joins two pens (combined PAC)"
link2="$("$HOST" pen zebra invite create --note multi-pen | awk '/^link:/ {print $2}')"
out2="$(in_client bobo sh -c '"/dl/hogman-$(uname -s)-$(uname -m)" --no-open --handle member2 --hostname laptop2 "$1"' _ "$link2" 2>&1)"; rc2=$?
[ $rc2 = 0 ] || echo "$out2" | sed 's/^/        | /'
check "client-bobo joins zebra too (exit $rc2)" grep -q "You're in. You are member2 on zebra.pens.hogman.test" <<<"$out2"
bobo_proxy="$(in_client bobo sh -c 'jq -r .proxy_addr "${XDG_CONFIG_HOME:-$HOME/.config}/hogman/bobo.pens.hogman.test/config.json"')"
zebra_proxy="$(in_client bobo sh -c 'jq -r .proxy_addr "${XDG_CONFIG_HOME:-$HOME/.config}/hogman/zebra.pens.hogman.test/config.json"')"
pac_bobo="$(in_client bobo curl -sf "http://$bobo_proxy/proxy.pac")"
pac_zebra="$(in_client bobo curl -sf "http://$zebra_proxy/proxy.pac")"
check "bobo /proxy.pac routes bobo and zebra" bash -c 'grep -q "dnsDomainIs(host, \".bobo.pens.hogman.test\").*PROXY $1" <<<"$3" && grep -q "dnsDomainIs(host, \".zebra.pens.hogman.test\").*PROXY $2" <<<"$3"' _ "$bobo_proxy" "$zebra_proxy" "$pac_bobo"
check "zebra /proxy.pac matches bobo /proxy.pac" test "$pac_bobo" = "$pac_zebra"
check "client-bobo reaches home.bobo.pens.hogman.test through bobo proxy" in_client bobo sh -c 'curl -sf --cacert /issued-root.crt -x "http://$1" https://home.bobo.pens.hogman.test/api/me | jq -e ".member.handle == \"member1\""' _ "$bobo_proxy"
check "client-bobo reaches home.zebra.pens.hogman.test through zebra proxy" in_client bobo sh -c 'curl -sf --cacert /issued-root.crt -x "http://$1" https://home.zebra.pens.hogman.test/api/me | jq -e ".member.handle == \"member2\""' _ "$zebra_proxy"
out_leave="$(in_client bobo sh -c '"/dl/hogman-$(uname -s)-$(uname -m)" leave "$1" </dev/null' _ "$link2" 2>&1)"; rc_leave=$?
[ $rc_leave = 0 ] || echo "$out_leave" | sed 's/^/        | /'
check "client-bobo leaves zebra cleanly (exit $rc_leave)" test $rc_leave = 0
pac_after="$(in_client bobo curl -sf "http://$bobo_proxy/proxy.pac")"
check "bobo /proxy.pac drops zebra after leave" bash -c 'grep -q "dnsDomainIs(host, \".bobo.pens.hogman.test\")" <<<"$1" && ! grep -q "zebra.pens.hogman.test" <<<"$1"' _ "$pac_after"

step "Restore a pen from a backup, as on a new server"
# What hogman-host backup keeps: .env and data/, minus what the pen rebuilds.
(cd "$HOGMAN_HOME/pens/zebra" && tar -czf "$HOGMAN_HOME/zebra-backup.tar.gz" \
  --exclude data/join-dl --exclude data/edge --exclude data/portal --exclude data/tmp --exclude data/api .env data)
pen_net_disconnect zebra
"$HOST" remove zebra >/dev/null 2>&1
mv "$HOGMAN_HOME/pens/zebra" "$HOGMAN_HOME/zebra-old"
check "zebra is gone" fails docker network inspect pen-zebra-core
mkdir "$HOGMAN_HOME/pens/zebra" && tar -xzf "$HOGMAN_HOME/zebra-backup.tar.gz" -C "$HOGMAN_HOME/pens/zebra"
pen_net zebra
out="$("$HOST" upgrade zebra 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | tail -15 | sed 's/^/        | /'
check "hogman-host upgrade brings the restored pen up (exit $rc)" test $rc = 0
zebra_client_proxy="$(in_client zebra sh -c 'jq -r .proxy_addr "${XDG_CONFIG_HOME:-$HOME/.config}/hogman/zebra.pens.hogman.test/config.json"' 2>/dev/null)"
restored() {
  in_client zebra curl -sf https://zebra.gate.hogman.test/hogman/v1/network \
    | jq -e '.zone == "zebra.pens.hogman.test" and .cert_mode == "public"' >/dev/null || return 1
  in_client zebra curl -sf --cacert /issued-root.crt -x "http://$zebra_client_proxy" https://home.zebra.pens.hogman.test/api/me \
    | jq -e '.member.handle == "member1"' >/dev/null
}
check "the restored pen serves its public zone and home portal" retry 30 restored
check "the restored pen kept its members" match zebra-owner "$HOST" pen zebra member list
check "the restored pen kept its devices" match 'member1.*laptop' "$HOST" pen zebra device list
check "the restored pen is listed as running" match 'zebra.*running' "$HOST" list

step "Removed pen name stays burned (D-21)"
pen_net alpha
out="$("$HOST" add alpha 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | tail -15 | sed 's/^/        | /'
check "hogman-host add alpha raises a public pen (exit $rc)" test $rc = 0
check "the name alpha is now used" match '^used$' env CDNS_ADMIN_SOCK="$ACME/cdns/admin.sock" "$ACME/cdns/challenge-dns" name used alpha
pen_net_disconnect alpha
"$HOST" remove alpha >/dev/null 2>&1
mv "$HOGMAN_HOME/pens/alpha" "$HOGMAN_HOME/alpha-old"
reuse="$("$HOST" add alpha 2>&1)"
check "a removed pen's name is never given out again (D-21)" grep -q 'never given out again' <<<"$reuse"
check "removing it dropped its challenge DNS credential" no_match 'alpha' env CDNS_ADMIN_SOCK="$ACME/cdns/admin.sock" "$ACME/cdns/challenge-dns" cred list

step "Get a pen: the sign-up page raises a public pen for a stranger"
# The operator's backup key (sign-ups need backups set up).
agekey="$(docker run --rm alpine:3.22 sh -c 'apk add -q age >/dev/null && age-keygen 2>/dev/null')"
grep '^AGE-SECRET-KEY' <<<"$agekey" > "$HOGMAN_HOME/age-secret.txt"
grep -o 'age1[0-9a-z]*' <<<"$agekey" | head -1 > "$HOGMAN_HOME/backup-recipient.txt"
rsync -a --exclude hogman-signup.bin "$REPO/deploy/signup/" "$HOGMAN_HOME/signup-src/"
check "signup-setup refuses a front-door domain other than the gate" fails "$HOST" signup-setup pens.example get.example 3
check "signup-setup starts the page and its broker" "$HOST" signup-setup gate.hogman.test get.example 3
no_arg_signup_refresh() {
  local tmp; tmp="$(mktemp)"
  grep -v '^PENS_DOMAIN=' "$HOGMAN_HOME/host.env" > "$tmp"
  printf "PENS_DOMAIN='old.pens.example'\n" >> "$tmp"
  install -m 0600 "$tmp" "$HOGMAN_HOME/host.env"; rm -f "$tmp"
  "$HOST" signup-setup && grep -qx "PENS_DOMAIN='gate.hogman.test'" "$HOGMAN_HOME/host.env"
}
check "no-arg signup-setup refreshes to GATE_DOMAIN despite stale PENS_DOMAIN" no_arg_signup_refresh
std_out="$("$HOST" signup-code for standard test)"
std_code="$(awk '/^code:/ {print $2}' <<<"$std_out")"
check "signup-code makes a standard (suffixed) code" bash -c 'grep -q "^$1 for standard test$" "$2/signup/codes" && ! grep -q "vanity=1" <<<"$3"' _ "$std_code" "$HOGMAN_HOME" "$std_out"
vanity_out="$("$HOST" signup-code --vanity for the test)"
code="$(awk '/^code:/ {print $2}' <<<"$vanity_out")"
check "signup-code --vanity tags the code and link" bash -c 'grep -q "^$1 vanity for the test$" "$2/signup/codes" && grep -q "vanity=1" <<<"$3"' _ "$code" "$HOGMAN_HOME" "$vanity_out"

front_ip="$(docker inspect -f '{{(index .NetworkSettings.Networks "hogman-front").IPAddress}}' hogman-front-front-1)"
docker run -d --name client-signup --network hogman-front \
  --add-host "get.example:$front_ip" --add-host "smithy.gate.hogman.test:$front_ip" \
  -e HOGMAN_ACME_CA_ROOT=/issued-root.crt -v "$ACME/issued-root.crt:/issued-root.crt:ro" \
  -v "$FRONT_CA:/front-ca.crt:ro" --entrypoint sh nicolaka/netshoot:v0.14 -c \
  'cp /front-ca.crt /usr/local/share/ca-certificates/front.crt && update-ca-certificates >/dev/null 2>&1; exec sleep infinity' >/dev/null
retry 20 docker exec client-signup test -s /etc/ssl/certs/ca-certificates.crt
signup() { docker exec client-signup curl -s -m 30 -H 'content-type: application/json' "https://get.example$@"; }
create_pen() {  # create_pen <json>: start a sign-up and follow its job, like the page does; prints the result
  local raw status body job j i
  raw="$(docker exec client-signup curl -s -m 30 -w '\n%{http_code}' -H 'content-type: application/json' -d "$1" https://get.example/api/create)"
  status="${raw##*$'\n'}"
  body="${raw%$'\n'*}"
  job="$(jq -r '.job // empty' <<<"$body" 2>/dev/null)"
  if [ -z "$job" ]; then
    jq -c --argjson st "${status:-0}" '. + {status: $st}' <<<"$body" 2>/dev/null || echo "{\"error\":\"no job\",\"status\":${status:-0}}"
    return
  fi
  for i in $(seq 1 300); do
    j="$(signup "/api/job?id=$job")"
    case "$(jq -r .state <<<"$j" 2>/dev/null)" in
      done) jq -c .result <<<"$j"; return ;;
      failed) jq -c '{error, status}' <<<"$j"; return ;;
    esac
    sleep 2
  done
  echo '{"error":"timed out"}'
}
check "the page is served at https://get.example" match 'Get a pen' docker exec client-signup curl -sf https://get.example/
signup_hdrs="$(docker exec client-signup curl -sI https://get.example/ | tr -d '\r')"
check "the sign-up page sets Origin-Agent-Cluster" grep -iq '^origin-agent-cluster: ?1' <<<"$signup_hdrs"
check "it says sign-ups are open" sh -c "docker exec client-signup curl -sf https://get.example/api/status | jq -e '.open'"
check "it shows names under the pens zone" sh -c "docker exec client-signup curl -sf https://get.example/api/status | jq -e '.sites_domain == \"pens.hogman.test\"'"
check "a reserved name is refused" sh -c "docker exec client-signup curl -sf 'https://get.example/api/check?pen=www' | jq -e '.free == false'"
check "a name used before (alpha) shows as taken for vanity (D-21)" sh -c "docker exec client-signup curl -sf 'https://get.example/api/check?pen=alpha&vanity=1' | jq -e '.free == false'"
check "a standard suffixed prefix (alpha) is allowed without colliding with bare alpha" sh -c "docker exec client-signup curl -sf 'https://get.example/api/check?pen=alpha' | jq -e '.free == true and .vanity == false'"
check "a never-used vanity name shows as free" sh -c "docker exec client-signup curl -sf 'https://get.example/api/check?pen=freshname&vanity=1' | jq -e '.free == true and .vanity == true'"
long_std_prefix() { [ "$(create_pen "{\"code\":\"$std_code\",\"pen\":\"aaaaaaaaaaaaaaaaaaaaaaaaaa\",\"handle\":\"keeper\"}" | jq -r .status)" = 400 ]; }
check "a >25-char prefix is refused on a standard suffixed code" long_std_prefix
wrong_code() { [ "$(create_pen '{"code":"PIG-AAAA-AAAA","pen":"smithy","handle":"keeper"}' | jq -r .status)" = 403 ]; }
check "a wrong code is refused" wrong_code
front_started="$(docker inspect -f '{{.State.StartedAt}}' hogman-front-front-1)"
pen_net smithy
res="$(create_pen "{\"code\":\"$code\",\"pen\":\"smithy\",\"handle\":\"keeper\"}")"
check "raising a pen doesn't restart the front door (other pens stay up)" \
  test "$(docker inspect -f '{{.State.StartedAt}}' hogman-front-front-1)" = "$front_started"
link="$(jq -r .join_link <<<"$res" 2>/dev/null)"
check "a pen is raised from the page" test "$(jq -r .zone <<<"$res" 2>/dev/null)" = smithy.pens.hogman.test
check "its front door is smithy.gate.hogman.test" test "$(jq -r .host <<<"$res" 2>/dev/null)" = smithy.gate.hogman.test
# The broker rewrote the front door's routes: every gate route must still use
# the wildcard (a test front door would mint its own certificate anyway, so
# check the routes themselves; a real one can't: CAA allows only the wildcard).
gate_route_tls() { grep -A1 "^$1.gate.hogman.test {" "$HOGMAN_HOME/front/Caddyfile" | grep -q 'tls /gate-tls/gate.crt /gate-tls/gate.key'; }
check "the sign-up's pen uses the *.gate wildcard" gate_route_tls smithy
check "and the other pens' routes kept it after the sign-up" gate_route_tls bobo
if [ -z "$link" ] || [ "$link" = null ]; then
  echo "        | $res"
  docker inspect -f '        broker| state={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}}' hogman-signup-broker-1 2>&1 || true
  docker logs hogman-signup-broker-1 2>&1 | tail -25 | sed 's/^/        broker| /'
fi
qr_ok() { jq -e '.join_qr_svg | startswith("<svg")' <<<"$res"; }
check "with a QR code of the keeper's link" qr_ok
code_used() { [ -n "$code" ] && ! grep -q "^$code " "$HOGMAN_HOME/signup/codes"; }
check "the code is used up" code_used
check "the pen is marked hosted" grep -q '^HOSTED=true' "$HOGMAN_HOME/pens/smithy/.env"
check "it has public certificates: no root key at all" test ! -e "$HOGMAN_HOME/pens/smithy/data/pki"
check "the keeper's link carries no fingerprint" bash -c '[[ "$1" =~ ^https://smithy\.gate\.hogman\.test/join#k=[A-Za-z0-9_-]+$ ]]' _ "$link"
docker cp "$HOGMAN_HOME/pens/smithy/data/join-dl" client-signup:/dl >/dev/null
out="$(docker exec client-signup sh -c '"/dl/hogman-$(uname -s)-$(uname -m)" --no-open --hostname laptop "$1"' _ "$link" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | tail -8 | sed 's/^/        | /'
check "the keeper joins with the link (exit $rc)" grep -q "You're in. You are keeper on smithy.pens.hogman.test" <<<"$out"
check "and is the pen's owner" match 'keeper.*owner' "$HOST" pen smithy member list
code2="$("$HOST" signup-code | awk '/^code:/ {print $2}')"
check "the server is full at 3 pens" sh -c "docker exec client-signup curl -sf https://get.example/api/status | jq -e '.open == false'"
full="$(create_pen "{\"code\":\"$code2\",\"pen\":\"jones\",\"handle\":\"keeper\"}" | jq -r .status)"
check "a full server says so (503)" test "$full" = 503

# The waiting list, now that the server is full.
wl() { docker exec client-signup curl -s -H 'content-type: application/json' -d "$1" https://get.example/api/waitlist; }
check "a full server's page takes you onto the waiting list" bash -c "jq -e '.place == 1' <<<'$(wl '{"email":"Wanda@Example.com","pen":"wanda","note":"for the band"}')'"
check "joining twice keeps one place" bash -c "jq -e '.already and .place == 1' <<<'$(wl '{"email":"wanda@example.com"}')'"
bad_email() { wl '{"email":"nope"}' | jq -e '.error | test("email")'; }
check "a bad email is refused" bad_email
wl '{"email":"xavier@example.org"}' >/dev/null
check "the keeper sees who's waiting" match 'wanda@example.com.*wanda.*for the band' "$HOST" waitlist
inv="$("$HOST" waitlist invite 1 2>&1)"
wcode="$(grep -o 'PIG-[A-Z0-9]\{4\}-[A-Z0-9]\{4\}' <<<"$inv" | head -1)"
invite_ok() {
  [ -n "$wcode" ] && grep -q "^$wcode " "$HOGMAN_HOME/signup/codes" && grep -qF "get.example/#code=$wcode" <<<"$inv"
}
check "inviting from the list makes a working code and the message to send" invite_ok
check "and marks them invited" match "invited $wcode.*wanda@example.com" "$HOST" waitlist
"$HOST" waitlist remove 2 >/dev/null 2>&1
check "the keeper can remove someone" no_match xavier "$HOST" waitlist
wl '{"email":"yolanda@example.com"}' >/dev/null
self_leave() {
  docker exec client-signup curl -s -H 'content-type: application/json' -d '{"email":"yolanda@example.com"}' https://get.example/api/waitlist/leave | jq -e '.ok' \
    && no_match yolanda "$HOST" waitlist
}
check "someone can take themselves off the list" self_leave
mail_setup() {  # a sender with <...> must not break the host settings file
  echo re_testkeyonly_not_real | "$HOST" signup-mail "Hogman <pens@example.com>" >/dev/null 2>&1 \
    && "$HOST" capacity | jq -e '.max == 3' && grep -q "^SIGNUP_FROM='Hogman <pens@example.com>'$" "$HOGMAN_HOME/host.env"
}
check "signup-mail stores a sender like 'Hogman <pens@...>' safely" mail_setup
check "the page cannot reach Docker or the pens" no_match docker.sock docker inspect hogman-signup-web-1
broker_unreachable() {  # only the page shares a network with the broker
  local n; for n in $(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' hogman-signup-broker-1); do
    docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$n" | tr ' ' '\n' | grep -v '^$' \
      | grep -vxE 'hogman-signup-(broker|web)-1' && return 1
  done; return 0
}
check "nothing but the page shares a network with the broker" broker_unreachable
check "the page runs unprivileged" test "$(docker inspect -f '{{.Config.User}}' hogman-signup-web-1)" = 65534:65534

step "Host & secret hardening"
check "hogman-host pen rejects path traversal"     fails "$HOST" pen ../front status
check "hogman-host upgrade rejects path traversal" fails "$HOST" upgrade ../front
check "hogman-host remove rejects path traversal"  fails "$HOST" remove ../front
check "hogman-host add rejects extra arguments"     fails "$HOST" add badpen 'hs.example.com { respond 200 }'
check "hogman-host add rejects bad characters in name" fails "$HOST" add 'badpen;id'
check "front data dir is mode 700"  test "$(perm "$HOGMAN_HOME/front/data")" = 700
check "host.env is mode 600"        test "$(perm "$HOGMAN_HOME/host.env")" = 600
check "pen secret dirs are mode 700" secret_dirs_ok
front_user_ok() {
  local uid gid got
  uid="$(grep -h '^FRONT_UID=' "$HOGMAN_HOME/host.env" | cut -d= -f2)"
  gid="$(grep -h '^FRONT_GID=' "$HOGMAN_HOME/host.env" | cut -d= -f2)"
  got="$(docker inspect -f '{{.Config.User}}' hogman-front-front-1)"
  [ -n "$uid" ] && [ "$uid" != 0 ] && [ "$got" = "$uid:$gid" ]
}
portal_user_ok() {
  local got; got="$(docker inspect -f '{{.Config.User}}' pen-bobo-portal-1)"
  [ -n "$got" ] && [ "${got%%:*}" != 0 ]
}
check "front door Caddy runs non-root" front_user_ok
check "pen portal Caddy runs non-root" portal_user_ok

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
