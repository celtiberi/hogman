#!/usr/bin/env bash
# End-to-end test of the core stack and registrar on one machine.
# Needs Docker and jq.
#
# Deploys a throwaway network "bobo" in a temporary copy of core/, then plays
# out the life of a small network across six phase scripts in core/test/phases/.
#
# usage: test/run.sh [--keep]     --keep leaves the stack running afterwards
set -uo pipefail
# shellcheck source=/dev/null
. "$(dirname "$0")/e2e-lock.sh"
# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"
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

cleanup() {
  if [ "$KEEP" = true ]; then
    echo; echo "Stack left running in $WORK"
    echo "  cd there, export COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME ACME_DIR=$ACME, then ./hogman <command>; ./hogman down -v to stop"
  else
    docker rm -f hogman-run-cdns hogman-run-pebble \
      "hogman-e2e-sidecar-$$" "hogman-e2e-bridge-$$" "hogman-e2e-app-$$" >/dev/null 2>&1 || true
    docker volume rm -f "hogman-e2e-state-$$" "hogman-e2e-in-$$" >/dev/null 2>&1 || true
    docker rmi -f "hogman-sidecar-e2e:$$" >/dev/null 2>&1 || true
    if [ -f "$WORK/.env" ]; then
      (cd "$WORK" && dc down -v -t 1 --remove-orphans >/dev/null 2>&1) || true
    fi
    docker network rm "${COMPOSE_PROJECT_NAME}_core" hogman-test-acme >/dev/null 2>&1 || true
    rm -rf "$WORK"
  fi
}
trap 'cleanup; e2e_unlock' EXIT

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
for phase in \
  01-deploy-and-invites.sh \
  02-devices-and-naming.sh \
  03-policy-and-join-page.sh \
  04-join-tool-and-shares.sh \
  05-sidecar-and-updates.sh \
  06-lifecycle.sh; do
  # shellcheck source=/dev/null
  . "$SRC/test/phases/$phase"
done

echo
echo "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
