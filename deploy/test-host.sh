#!/usr/bin/env bash
# Local test of a shared host: one front door, two separate pens, a member
# joining each. Needs Docker and jq. Uses test certificates throughout.
#
# usage: deploy/test-host.sh [--keep]
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
KEEP=false; [ "${1:-}" = --keep ] && KEEP=true
export HOGMAN_HOME="$(mktemp -d "${TMPDIR:-/tmp}/hogman-host.XXXXXX")"
HOST="$REPO/deploy/hogman-host"
FRONT_CA="$HOGMAN_HOME/front/data/caddy/pki/authorities/local/root.crt"

pass=0; fail=0
step()  { echo; echo "== $*"; }
check() { local d="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  PASS  $d"; pass=$((pass + 1)); else echo "  FAIL  $d"; fail=$((fail + 1)); fi; }
fails() { ! "$@" >/dev/null 2>&1; }
perm()  { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
secret_dirs_ok() {
  local d
  for d in pki/offline step/secrets secrets/registrar mesh registrar headscale/lib; do
    [ "$(perm "$HOGMAN_HOME/pens/bobo/data/$d")" = 700 ] || return 1
  done
}
retry() { local n="$1"; shift; for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

cleanup() {
  if [ "$KEEP" = true ]; then echo; echo "Left running. HOGMAN_HOME=$HOGMAN_HOME"; return; fi
  for c in client-bobo client-zebra client-signup; do docker rm -f "$c" >/dev/null 2>&1; done
  (cd "$HOGMAN_HOME/signup" 2>/dev/null && docker compose down -v >/dev/null 2>&1)
  for n in bobo zebra smithy jones; do (cd "$HOGMAN_HOME/pens/$n" 2>/dev/null && ./hogman down -v --remove-orphans >/dev/null 2>&1); done
  (cd "$HOGMAN_HOME/front" 2>/dev/null && docker compose down -v >/dev/null 2>&1)
  for n in bobo zebra smithy jones; do docker network rm "pen-$n-core" >/dev/null 2>&1; done
  docker network rm hogman-front >/dev/null 2>&1
  rm -rf "$HOGMAN_HOME"
}
trap cleanup EXIT

step "Set up the host"
mkdir -p "$HOGMAN_HOME/src"
rsync -a --exclude data --exclude .env "$REPO/core/" "$HOGMAN_HOME/src/"
check "front door starts" "$HOST" init --test

step "Two pens on one host"
"$HOST" add bobo control.bobo.example || exit 1
"$HOST" add zebra control.zebra.example || exit 1
"$HOST" list
check "both pens are listed as running" sh -c "'$HOST' list | grep -c running | grep -qx 2"
check "each pen has its own relay port" sh -c "[ \"\$(grep -h ^STUN_PORT= $HOGMAN_HOME/pens/*/.env | sort -u | wc -l | tr -d ' ')\" = 2 ]"

# A computer on the internet with nothing but the join tool. It reaches the
# host only through the front door.
client() {  # client <pen>. Public DNS would point both names at the host; here, at the front door.
  local front_ip; front_ip="$(docker inspect -f '{{(index .NetworkSettings.Networks "hogman-front").IPAddress}}' hogman-front-front-1)"
  docker run -d --name "client-$1" --network hogman-front \
    --add-host "control.bobo.example:$front_ip" --add-host "control.zebra.example:$front_ip" \
    -v "$FRONT_CA:/front-ca.crt:ro" -v "$HOGMAN_HOME/pens/$1/data/join-dl:/dl:ro" \
    --entrypoint sh nicolaka/netshoot:v0.14 -c \
    'cp /front-ca.crt /usr/local/share/ca-certificates/front.crt && update-ca-certificates >/dev/null 2>&1; exec sleep infinity' >/dev/null
}
in_client() { local c="$1"; shift; docker exec "client-$c" "$@"; }

for pen in bobo zebra; do
  step "Pen $pen, through the front door"
  host="control.$pen.example"
  "$HOST" pen "$pen" member add "${pen}-owner" --role owner >/dev/null
  link="$("$HOST" pen "$pen" invite create --note test | awk '/^link:/ {print $2}')"
  client "$pen"
  retry 20 in_client "$pen" test -s /etc/ssl/certs/ca-certificates.crt
  info_ok() { in_client "$pen" curl -sf "https://$host/hogman/v1/network" | jq -e --arg z "$pen.hogman" '.zone == $z'; }
  check "https://$host answers as pen $pen" info_ok
  check "the join page is served for $pen" sh -c "docker exec client-$pen curl -sf https://$host/join | grep -q hogman-join"
  out="$(in_client "$pen" sh -c '"/dl/hogman-join-$(uname -s)-$(uname -m)" --no-open --handle member1 --hostname laptop "$1"' _ "$link" 2>&1)"; rc=$?
  [ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
  check "a member joins $pen (exit $rc)" grep -q "You're in. You are member1 on $pen.hogman" <<<"$out"
  check "the registrar of $pen recorded the device" retry 10 sh -c "'$HOST' pen $pen device list | grep -q 'member1.*laptop'"
  stun="$(grep -h ^STUN_PORT= "$HOGMAN_HOME/pens/$pen/.env" | cut -d= -f2)"
  derp_port() { docker exec "pen-$pen-core-mesh-1" tailscale debug derp-map 2>/dev/null | jq -r '.Regions[].Nodes[].STUNPort' | grep -qx "$stun"; }
  check "$pen's relay advertises its own port ($stun)" derp_port
done

step "Pens are separate"
same_core() {  # every lookup of core-mesh from a pen's edge lands on that pen's own core
  local pen="$1" own; own="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "pen-$pen-core-mesh-1")"
  for _ in 1 2 3 4 5 6; do
    ip="$(docker exec "pen-$pen-edge-1" getent hosts core-mesh | awk '{print $1}' | head -1)"
    grep -qw "$ip" <<<"$own" || return 1
  done
}
check "bobo's edge only ever reaches bobo's core" same_core bobo
check "zebra's edge only ever reaches zebra's core" same_core zebra
cross() { in_client bobo curl -sf "https://control.zebra.example/hogman/v1/network" | jq -e '.zone == "zebra.hogman"'; }
check "both control hosts answer through the same front door" cross
fp_b="$(in_client bobo curl -sf https://control.bobo.example/hogman/v1/network | jq -r .root_fingerprint)"
fp_z="$(in_client zebra curl -sf https://control.zebra.example/hogman/v1/network | jq -r .root_fingerprint)"
check "each pen has its own certificate authority" test -n "$fp_b" -a "$fp_b" != "$fp_z"
check "bobo's members are not zebra's" sh -c "! '$HOST' pen zebra member list | grep -q bobo-owner"

step "Restore a pen from a backup, as on a new server"
# What hogman-host backup keeps: .env and data/, minus what the pen rebuilds.
(cd "$HOGMAN_HOME/pens/zebra" && tar -czf "$HOGMAN_HOME/zebra-backup.tar.gz" \
  --exclude data/join-dl --exclude data/edge --exclude data/portal --exclude data/step/db --exclude data/tmp .env data)
"$HOST" remove zebra >/dev/null 2>&1
mv "$HOGMAN_HOME/pens/zebra" "$HOGMAN_HOME/zebra-old"
check "zebra is gone" fails docker network inspect pen-zebra-core
mkdir "$HOGMAN_HOME/pens/zebra" && tar -xzf "$HOGMAN_HOME/zebra-backup.tar.gz" -C "$HOGMAN_HOME/pens/zebra"
out="$("$HOST" upgrade zebra 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | tail -15 | sed 's/^/        | /'
check "hogman-host upgrade brings the restored pen up (exit $rc)" test $rc = 0
restored() { in_client zebra curl -sf https://control.zebra.example/hogman/v1/network | jq -e --arg f "$fp_z" '.root_fingerprint == $f'; }
check "the restored pen answers with its own certificate authority" retry 30 restored
check "the restored pen kept its members" sh -c "'$HOST' pen zebra member list | grep -q zebra-owner"
check "the restored pen kept its devices" sh -c "'$HOST' pen zebra device list | grep -q 'member1.*laptop'"
check "the restored pen is listed as running" sh -c "'$HOST' list | grep zebra | grep -q running"

step "Get a pen: the sign-up page raises one for a stranger"
# The operator's backup key: hosted pens' root keys are escrowed to it.
agekey="$(docker run --rm alpine:3.22 sh -c 'apk add -q age >/dev/null && age-keygen 2>/dev/null')"
grep '^AGE-SECRET-KEY' <<<"$agekey" > "$HOGMAN_HOME/age-secret.txt"
grep -o 'age1[0-9a-z]*' <<<"$agekey" | head -1 > "$HOGMAN_HOME/backup-recipient.txt"
rsync -a --exclude hogman-signup.bin "$REPO/deploy/signup/" "$HOGMAN_HOME/signup-src/"
check "signup-setup starts the page and its broker" "$HOST" signup-setup pens.example get.example 3
code="$("$HOST" signup-code for the test | awk '/^code:/ {print $2}')"
check "signup-code makes a code" grep -q "^$code " "$HOGMAN_HOME/signup/codes"

front_ip="$(docker inspect -f '{{(index .NetworkSettings.Networks "hogman-front").IPAddress}}' hogman-front-front-1)"
docker run -d --name client-signup --network hogman-front \
  --add-host "get.example:$front_ip" --add-host "smithy.pens.example:$front_ip" \
  -v "$FRONT_CA:/front-ca.crt:ro" --entrypoint sh nicolaka/netshoot:v0.14 -c \
  'cp /front-ca.crt /usr/local/share/ca-certificates/front.crt && update-ca-certificates >/dev/null 2>&1; exec sleep infinity' >/dev/null
retry 20 docker exec client-signup test -s /etc/ssl/certs/ca-certificates.crt
signup() { docker exec client-signup curl -s -m 900 -H 'content-type: application/json' "https://get.example$@"; }
check "the page is served at https://get.example" sh -c "docker exec client-signup curl -sf https://get.example/ | grep -q 'Get a pen'"
check "it says sign-ups are open" sh -c "docker exec client-signup curl -sf https://get.example/api/status | jq -e '.open'"
check "a reserved name is refused" sh -c "docker exec client-signup curl -sf 'https://get.example/api/check?pen=www' | jq -e '.free == false'"
check "a wrong code is refused" sh -c "docker exec client-signup curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
  -d '{\"code\":\"PIG-AAAA-AAAA\",\"pen\":\"smithy\",\"handle\":\"keeper\"}' https://get.example/api/create | grep -qx 403"
front_started="$(docker inspect -f '{{.State.StartedAt}}' hogman-front-front-1)"
res="$(signup /api/create -d "{\"code\":\"$code\",\"pen\":\"smithy\",\"handle\":\"keeper\"}")"
check "raising a pen doesn't restart the front door (other pens stay up)" \
  test "$(docker inspect -f '{{.State.StartedAt}}' hogman-front-front-1)" = "$front_started"
link="$(jq -r .join_link <<<"$res" 2>/dev/null)"
check "a pen is raised from the page" test "$(jq -r .zone <<<"$res" 2>/dev/null)" = smithy.hogman
if [ -z "$link" ] || [ "$link" = null ]; then
  echo "        | $res"
  docker logs hogman-signup-broker-1 2>&1 | tail -25 | sed 's/^/        broker| /'
fi
qr_ok() { jq -e '.join_qr_svg | startswith("<svg")' <<<"$res"; }
check "with a QR code of the keeper's link" qr_ok
code_used() { [ -n "$code" ] && ! grep -q "^$code " "$HOGMAN_HOME/signup/codes"; }
check "the code is used up" code_used
check "the pen is marked hosted" grep -q '^HOSTED=true' "$HOGMAN_HOME/pens/smithy/.env"
no_plain_root() { local d="$HOGMAN_HOME/pens/smithy/data/pki/offline"; [ -d "$d" ] && [ -z "$(ls -A "$d")" ]; }
check "its root key is not on the server in the clear" no_plain_root
escrow_opens() {
  docker run --rm -v "$HOGMAN_HOME:/h:ro" alpine:3.22 sh -c \
    'apk add -q age >/dev/null && age -d -i /h/age-secret.txt /h/pens/smithy/data/pki/root-escrow.tar.gz.age | tar -tz' | grep -q root_ca_key
}
check "it is escrowed to the operator's backup key" escrow_opens
docker cp "$HOGMAN_HOME/pens/smithy/data/join-dl" client-signup:/dl >/dev/null
out="$(docker exec client-signup sh -c '"/dl/hogman-join-$(uname -s)-$(uname -m)" --no-open --hostname laptop "$1"' _ "$link" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | tail -8 | sed 's/^/        | /'
check "the keeper joins with the link (exit $rc)" grep -q "You're in. You are keeper on smithy.hogman" <<<"$out"
check "and is the pen's owner" sh -c "'$HOST' pen smithy member list | grep -q 'keeper.*owner'"
code2="$("$HOST" signup-code | awk '/^code:/ {print $2}')"
check "the server is full at 3 pens" sh -c "docker exec client-signup curl -sf https://get.example/api/status | jq -e '.open == false'"
full="$(docker exec client-signup curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
  -d "{\"code\":\"$code2\",\"pen\":\"jones\",\"handle\":\"keeper\"}" https://get.example/api/create)"
check "a full server says so (503)" test "$full" = 503
check "the page cannot reach Docker or the pens" sh -c "! docker inspect hogman-signup-web-1 | grep -q docker.sock"
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
check "hogman-host add rejects Caddy block in host" fails "$HOST" add badpen 'hs.example.com { respond 200 }'
check "hogman-host add rejects semicolon in host"   fails "$HOST" add badpen 'hs.example.com;id'
check "front data dir is mode 700"  test "$(perm "$HOGMAN_HOME/front/data")" = 700
check "host.env is mode 600"        test "$(perm "$HOGMAN_HOME/host.env")" = 600
check "pen secret dirs are mode 700" secret_dirs_ok

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
