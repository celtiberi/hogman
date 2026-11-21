#!/usr/bin/env bash
# Check that compose.yaml runs a public-certificate pen as intended: no step-ca,
# the portal waits for a healthy registrar, and only the registrar and portal
# see the sockets and home TLS.
set -euo pipefail
cd "$(dirname "$0")/.."
export ZONE=bobo.pens.hogman.network PUBLIC_HOST=bobo.gate.hogman.network NETWORK=bobo HOGMAN_UID=65532 HOGMAN_GID=65532
cfg="$(docker compose -p check -f compose.yaml config --format json)"
fail() { echo "FAIL: $*" >&2; exit 1; }
svcs="$(jq -r '.services | keys[]' <<<"$cfg")"
grep -qx step-ca <<<"$svcs" && fail "step-ca would start"
# Compose adds core-mesh itself (the portal shares its network); step-ca must be gone.
jq -e '.services.portal.depends_on | keys - ["core-mesh"] == ["registrar"]' <<<"$cfg" >/dev/null || fail "portal should depend only on the registrar (and core-mesh)"
jq -e '.services.portal.depends_on.registrar.condition == "service_healthy"' <<<"$cfg" >/dev/null || fail "portal must wait for a healthy registrar"
jq -e '.services.registrar.environment.CHALLENGE_DNS_URL == "unix:///run/hogman-acme/api.sock"' <<<"$cfg" >/dev/null || fail "registrar missing CHALLENGE_DNS_URL"
jq -e '.services.registrar.environment.HOME_TLS_DIR == "/home-tls"' <<<"$cfg" >/dev/null || fail "registrar missing HOME_TLS_DIR"
jq -e '.services.registrar.healthcheck.test | index("health")' <<<"$cfg" >/dev/null || fail "registrar has no health check"
mounts() { jq -r --arg s "$1" '.services[$s].volumes[]?.target' <<<"$cfg"; }
for s in $svcs; do
  for t in /run/hogman-acme /home-tls /run/caddy-admin /run/hogman-api; do
    if mounts "$s" | grep -qx "$t"; then
      case "$s:$t" in
        registrar:*|portal:/home-tls|portal:/run/caddy-admin|portal:/run/hogman-api) ;;
        *) fail "$s can see $t" ;;
      esac
    fi
  done
  mounts "$s" | grep -qx /pki && fail "$s still mounts /pki"
done
mounts portal | grep -qx /run/hogman-acme && fail "the portal can reach the challenge DNS API"
echo "public-certificate pen compose: ok"
