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
KEEP=false; [ "${1:-}" = --keep ] && KEEP=true
WORK="$(mktemp -d "${TMPDIR:-/tmp}/hogman-test.XXXXXX")"
export COMPOSE_PROJECT_NAME=hogman-test
ROOT=/pki/root_ca.crt
ZONE=bobo.hogman
PUBLIC_HOST=control.bobo-test.example

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
    echo "  cd there, export COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME, then ./hogman <command>; ./hogman down -v to stop"
  else
    dc down -v --remove-orphans >/dev/null 2>&1
    rm -rf "$WORK"
  fi
}
trap 'cleanup; e2e_unlock' EXIT

rsync -a --exclude data --exclude .env "$SRC/" "$WORK/"
cd "$WORK"
cat > .env <<EOF
NETWORK=bobo
PUBLIC_HOST=$PUBLIC_HOST
PUBLIC_IPV4=
TEST_MODE=true
EOF

H=./hogman
dc() {
  local envs=(--env-file .env)
  [ -f data/state.env ] && envs+=(--env-file data/state.env)
  ZONE=$ZONE EDGE_TLS_MODE=local_certs docker compose "${envs[@]}" \
    -f compose.yaml -f test/compose.test.yaml --profile clients "$@"
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
verify_cert()  { openssl verify -CAfile data/pki/public/root_ca.crt \
                   -untrusted data/pki/public/intermediate_ca.crt "$1"; }
has_device()   { match "$1" $H device list; }
no_device_of() {
  local out
  out="$($H device list)" || return 1
  ! awk -v u="$1" '$2 == u { found=1 } END { exit !found }' <<<"$out"
}

site_cert() { run bob-tools sh -c "echo | openssl s_client -connect $1:443 -servername $1 \
                -CAfile $ROOT 2>/dev/null | openssl x509"; }
expires_within() {
  local pem; pem="$(site_cert "$1")" || return 1
  [ -n "$pem" ] || return 1
  openssl x509 -noout -checkend 0 <<<"$pem" >/dev/null || return 1
  ! openssl x509 -noout -checkend $(( $2 * 3600 )) <<<"$pem" >/dev/null
}

# ===========================================================================

step "Deploy"
$H init || exit 1
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
fp="$(jq -r .root_fingerprint <<<"$alice_json")"
check "the enrolment carries the network's root (fingerprint matches)" test "$fp" = "$(tr -d ':' <<<"$ROOT_FINGERPRINT")"
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

step "Alice adds a server and names it"
srv="$(api alice-laptop-tools POST /api/devices '{"kind":"server"}')"
ALICE_SERVER_KEY="$(jq -r .auth_key <<<"$srv")"
check "alice gets a server key from the portal" test -n "$ALICE_SERVER_KEY" -a "$ALICE_SERVER_KEY" != null
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
dc up -d alice-server alice-web alice-tools
retry 90 has_ip alice-server; ALICE_SERVER_IP="$(ip_of alice-server)"
check "her server is recorded as hers" retry 20 match 'alice.*server' $H device list
SERVER_ID="$(api alice-laptop-tools GET /api/me | jq -r '.devices[] | select(.kind=="server") | .id')"
echo "  core=$CORE_MESH_IP alice-laptop=$ALICE_LAPTOP_IP bob-laptop=$BOB_LAPTOP_IP alice-server=$ALICE_SERVER_IP (#$SERVER_ID) stray=$STRAY_IP"
LAPTOP_ID="$(api alice-laptop-tools GET /api/me | jq -r '.devices[] | select(.kind=="personal") | .id')"
check "a name can't point at a personal device"  expect 400 alice-laptop-tools POST /api/names "{\"name\":\"alice\",\"device_id\":$LAPTOP_ID}"
check "a sub-name needs its parent claimed first" expect 403 alice-laptop-tools POST /api/names "{\"name\":\"blog.alice\",\"device_id\":$SERVER_ID}"
check "alice claims alice.$ZONE"      expect 201 alice-laptop-tools POST /api/names "{\"name\":\"alice\",\"device_id\":$SERVER_ID}"
check "alice claims blog.alice.$ZONE" expect 201 alice-laptop-tools POST /api/names "{\"name\":\"blog.alice\",\"device_id\":$SERVER_ID}"
check "reserved names are refused"    expect 403 alice-laptop-tools POST /api/names "{\"name\":\"home\",\"device_id\":$SERVER_ID}"
check "bob can't take alice's name"   expect 409 bob-tools POST /api/names "{\"name\":\"alice\",\"device_id\":$SERVER_ID}"
check "bob can't point a name at alice's server" expect 400 bob-tools POST /api/names "{\"name\":\"bobsite\",\"device_id\":$SERVER_ID}"

step "Naming"
check "bob resolves alice.$ZONE to alice's server" retry 30 resolves_to alice.$ZONE "$ALICE_SERVER_IP"
check "bob resolves home.$ZONE to the core node"   resolves_to home.$ZONE "$CORE_MESH_IP"
check "bob resolves ca.$ZONE to the core node"     resolves_to ca.$ZONE "$CORE_MESH_IP"
check "device names work (alice-server.nodes.$ZONE)" resolves_to alice-server.nodes.$ZONE "$ALICE_SERVER_IP"
check "ordinary names still resolve (example.com)" resolves_any example.com
check "the network's DNS refuses outside names (not an open resolver)" refused example.com
in_directory() { match "$1" api bob-tools GET /api/directory; }
check "the directory lists alice's sites" in_directory "blog.alice.$ZONE"

step "HTTPS with the network's own CA"
legacy_acme_dir_ok() {
  run bob-tools curl -sf -m5 --cacert $ROOT "https://ca.$ZONE/acme/acme/directory" \
    | jq -e --arg p "https://ca.$ZONE/" \
      '(.newNonce | startswith($p)) and (.newAccount | startswith($p)) and (.newOrder | startswith($p))'
}
check "legacy CA URL https://ca.$ZONE/acme/acme/directory serves port-443 links" retry 60 legacy_acme_dir_ok
check "portal https://home.$ZONE is trusted"                    retry 60 fetch home.$ZONE "You're in"
check "alice's site https://alice.$ZONE is trusted (ACME cert)" retry 150 fetch alice.$ZONE "hello from alice.$ZONE"
check "sub-names work via legacy port-443 CA URL (https://blog.alice.$ZONE)" retry 150 fetch blog.alice.$ZONE "hello from blog.alice"
check "site certs are short-lived (expire within 7 days)" retry 10 expires_within alice.$ZONE 168
check "the CA is healthy" retry 30 sh -c "[ \"\$(docker inspect -f '{{.State.Health.Status}}' $COMPOSE_PROJECT_NAME-step-ca-1)\" = healthy ]"

step "Name constraints: the CA cannot vouch for outside names"
docker run --rm --user "$(id -u):$(id -g)" -v "$WORK/data:/d" --entrypoint sh smallstep/step-ca:0.30.2 -c '
  for n in www.google.com inside.bobo.hogman; do
    step certificate create "$n" "/d/$n.crt" "/d/$n.key" --profile leaf \
      --ca /d/pki/public/intermediate_ca.crt --ca-key /d/step/secrets/intermediate_ca_key \
      --ca-password-file /d/step/secrets/intermediate_password \
      --not-after 1h --no-password --insecure --force >/dev/null
  done'
check "a cert for inside.$ZONE verifies"                         verify_cert data/inside.bobo.hogman.crt
check "a cert for www.google.com from our own CA key is rejected" not verify_cert data/www.google.com.crt

step "Default-deny access policy"
# HTTPS only (D-11): members reach servers on 443 and nothing else.
docker exec -d "$(dc ps -q alice-tools)" sh -c 'nc -lk -p 2222 -e cat >/dev/null 2>&1 || nc -lk 2222'
check "bob's laptop can reach alice's server on 443"     retry 20 port_open bob-tools "$ALICE_SERVER_IP" 443
check "... but not on 80"                                 not port_open bob-tools "$ALICE_SERVER_IP" 80
check "... but on no other port (2222 is open there)"    not port_open bob-tools "$ALICE_SERVER_IP" 2222
# (Ping still answers: Tailscale's filter lets ICMP through between devices
# allowed any port. It can't carry data, so it isn't a way in.)
check "the server itself has 2222 open (so the above means something)" run alice-tools nc -z -w3 127.0.0.1 2222
check "bob's laptop cannot reach alice's laptop"         not port_open bob-tools "$ALICE_LAPTOP_IP" 443
check "alice's server cannot reach bob's laptop"         not port_open alice-tools "$BOB_LAPTOP_IP" 443
check "members cannot reach other ports on the core (22)" not port_open bob-tools "$CORE_MESH_IP" 22
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
check "it cannot reach the portal"     not port_open stray-tools "$CORE_MESH_IP" 443
check "it cannot reach the CA"         not port_open stray-tools "$CORE_MESH_IP" 9000
check "it cannot reach alice's server" not port_open stray-tools "$ALICE_SERVER_IP" 443
check "bob cannot reach it"            not can_ping bob-tools "$STRAY_IP"

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
  grep -q 'hogman-join' <<<"$html"
}
net_ok()   { match '"zone":"bobo.hogman"' from_internet "https://$PUBLIC_HOST/hogman/v1/network"; }
check "https://<host>/join serves the join page" page_ok
join_hdrs="$(from_internet -sI "https://$PUBLIC_HOST/join" | tr -d '\r')"
check "the join page sets anti-framing headers" bash -c "grep -iq '^x-frame-options: DENY' <<<\"\$1\" && grep -iq \"^content-security-policy:.*frame-ancestors 'none'\" <<<\"\$1\"" _ "$join_hdrs"
join_assets_ok() {
  from_internet "https://$PUBLIC_HOST/join/assets/join.js" >/dev/null &&
    from_internet "https://$PUBLIC_HOST/join/assets/join.css" >/dev/null
}
check "join page external JS/CSS load" join_assets_ok
check "edge blocks Headscale admin API (/api/v1/user -> 404)" test "$(from_internet_status "https://$PUBLIC_HOST/api/v1/user")" = 404
check "edge blocks Headscale Swagger UI (/swagger -> 404)" test "$(from_internet_status "https://$PUBLIC_HOST/swagger")" = 404
sums="$(from_internet "https://$PUBLIC_HOST/join/dl/SHA256SUMS")"
check "the join tool is downloadable for 5 platforms" test "$(grep -c hogman-join <<<"$sums")" = 5
check "the network info endpoint is public" net_ok

step "The join tool, on a fresh computer"
dc up -d carol-laptop carol-desktop
retry 30 run carol-laptop tailscale status --json
join_tool() {  # join_tool <container> <args...>
  local c="$1"; shift
  run "$c" sh -c '"/dl/hogman-join-$(uname -s)-$(uname -m)" --no-open "$@"' _ "$@"
}
CAROL_LINK="$($H invite create --note carol | awk '/^link:/ {print $2}')"
BAD_LINK="${CAROL_LINK%fp=*}fp=$(printf '%064d' 0)"
out="$(join_tool carol-laptop --handle carol "$BAD_LINK" 2>&1)"
check "a link with the wrong fingerprint is refused" grep -q 'fingerprint mismatch' <<<"$out"
check "... before the invite is used" match 'open.*carol' $H invite list
out="$(join_tool carol-laptop --handle carol --hostname carol-laptop "$CAROL_LINK" 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "the join tool succeeds (exit $rc)" test $rc = 0
check "it reports carol is in" grep -q "You're in. You are carol on bobo.hogman" <<<"$out"
check "with Tailscale installed, it still joins the usual HTTPS-only way" grep -q "own small connection" <<<"$out"
ts_untouched() { [ "$(run carol-laptop tailscale status --json | jq -r .BackendState)" != Running ]; }
check "... and leaves this computer's Tailscale alone" ts_untouched
check "it installed the network's root in the system store" \
  run carol-laptop test -s /usr/local/share/ca-certificates/hogman-bobo.hogman.crt
check "the registrar recorded carol's laptop" retry 10 match 'carol.*carol-laptop' $H device list
DEVICE_LINK="$($H device key carol personal | awk '/^link:/ {print $2}')"
out="$(join_tool carol-desktop --tailscale --hostname carol-desktop "$DEVICE_LINK" 2>&1)"; rc=$?
check "joining through the Tailscale app is no longer offered (--tailscale refused)" test $rc != 0
check "... and the device link is still unused" no_match 'carol.*carol-desktop' $H device list
out="$(join_tool carol-desktop --hostname carol-desktop "$DEVICE_LINK" 2>&1)"; rc=$?
check "a device link adds a second device (exit $rc)" grep -q "You're in. You are carol" <<<"$out"
check "the registrar recorded it as carol's" retry 10 match 'carol.*carol-desktop' $H device list
out="$(join_tool carol-desktop leave "$DEVICE_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "leave works (exit $rc)" grep -q "Left bobo.hogman" <<<"$out"
check "leave removed the root from the system store" \
  run carol-desktop sh -c '! test -e /usr/local/share/ca-certificates/hogman-bobo.hogman.crt'
conn_gone() { ! run carol-desktop test -e /root/.config/hogman/bobo.hogman; }
check "leave removed the pen's connection and its settings" conn_gone

step "Side by side: a computer with no Tailscale at all"
dc up -d dave-laptop
retry 20 run dave-laptop test -s /etc/ssl/certs/ca-certificates.crt
DAVE_LINK="$($H invite create --note dave | awk '/^link:/ {print $2}')"
out="$(join_tool dave-laptop --handle dave --hostname dave-laptop "$DAVE_LINK" 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "the join tool succeeds without Tailscale installed (exit $rc)" test $rc = 0
check "it joined the usual way (side by side)" grep -q "joining side by side" <<<"$out"
check "it reports dave is in" grep -q "You're in. You are dave on bobo.hogman" <<<"$out"
check "the registrar recorded dave's laptop" retry 10 match 'dave.*dave-laptop' $H device list
PROXY="$(run dave-laptop sh -c 'grep -o "127.0.0.1:[0-9]*" /root/.config/hogman/bobo.hogman/config.json | head -1' | tr -d '\r')"
via_pen()   { run dave-laptop curl -sf -m10 --proxy "http://$PROXY" "$1"; }
alice_via() { match "hello from alice.$ZONE" via_pen "https://alice.$ZONE"; }
check "dave loads alice's site through the pen, trusted by the system store" retry 20 alice_via
outside_code() { run dave-laptop curl -s -m10 -o /dev/null -w '%{http_code}' --proxy "http://$PROXY" http://example.com | tr -d '\r'; }
check "the pen's proxy refuses anything outside the pen (HTTP $(outside_code))" test "$(outside_code)" = 403
pac_ok() { match 'dnsDomainIs(host, ".bobo.hogman")' run dave-laptop curl -sf "http://$PROXY/proxy.pac"; }
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
dc up -d dave-server
retry 20 run dave-server test -s /etc/ssl/certs/ca-certificates.crt
SHARE_LINK="$($H device key dave server | awk '/^link:/ {print $2}')"
check "a server link is marked for share" grep -q 'for=share' <<<"$SHARE_LINK"
out="$(join_tool dave-server --hostname dave-server "$SHARE_LINK" 2>&1)"; rc=$?
check "joining a whole computer with a server link is refused (exit $rc)" test $rc != 0
check "... and says to use it with share" grep -q "hogman-join share" <<<"$out"
no_dave_server() { local out; out="$($H device list)" || return 1; [ -z "$(awk '$2 == "dave" && $4 == "dave-server"' <<<"$out")" ]; }
check "... and adds no device" no_dave_server

# A computer that isn't on the pen at all: one server link, one command.
docker exec -d "$(dc ps -q dave-server)" sh -c 'mkdir -p /tmp/www && echo "app from a server link" > /tmp/www/index.html && caddy file-server --listen 127.0.0.1:8080 --root /tmp/www >/tmp/fs.log 2>&1'
out="$(join_tool dave-server share app 8080 "$SHARE_LINK" --background 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "a server link plus one command shares a port (exit $rc)" grep -q "https://app.$ZONE is up" <<<"$out"
check "members load https://app.$ZONE" retry 30 fetch app.$ZONE "app from a server link"
out="$(join_tool dave-server share stop app 2>&1)"; rc=$?
check "and it stops cleanly (exit $rc)" grep -q "app.$ZONE is down" <<<"$out"

out="$(join_tool dave-laptop leave "$DAVE_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "leave works (exit $rc)" grep -q "Left bobo.hogman" <<<"$out"
gone() { ! run dave-laptop test -e /root/.config/hogman/bobo.hogman; }
check "leave removed the connection and its settings" gone
proxy_closed() { ! run dave-laptop curl -s -m3 -o /dev/null "http://$PROXY/status"; }
check "the proxy is no longer running" retry 10 proxy_closed

step "Suspend and resume"
check "alice (admin) cannot suspend the owner" expect 403 alice-laptop-tools POST /api/admin/members/root/suspend
$H member suspend bob "testing" >/dev/null
timed t 30 not fetch alice.$ZONE "hello"
check "suspended bob loses access (${t}s)" not fetch alice.$ZONE "hello"
check "suspended bob can't reach the portal" not api bob-tools GET /api/me
check "his device is still registered" has_device bob-laptop
$H member resume bob >/dev/null
timed t 30 fetch alice.$ZONE "hello"
check "resumed bob has access again (${t}s)" fetch alice.$ZONE "hello"

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
