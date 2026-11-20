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
retry() { local n="$1"; shift; for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

cleanup() {
  if [ "$KEEP" = true ]; then echo; echo "Left running. HOGMAN_HOME=$HOGMAN_HOME"; return; fi
  for c in client-bobo client-zebra; do docker rm -f "$c" >/dev/null 2>&1; done
  for n in bobo zebra; do (cd "$HOGMAN_HOME/pens/$n" 2>/dev/null && ./hogman down -v --remove-orphans >/dev/null 2>&1); done
  (cd "$HOGMAN_HOME/front" 2>/dev/null && docker compose down -v >/dev/null 2>&1)
  for n in bobo zebra; do docker network rm "pen-$n-core" >/dev/null 2>&1; done
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

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
