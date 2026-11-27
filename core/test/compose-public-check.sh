#!/usr/bin/env bash
# Check that compose.yaml runs a public-certificate pen as intended: no step-ca,
# no privileged core-mesh or portal Caddy containers (I-15), registrar embeds
# tsnet + DNS + portal unprivileged/read-only/cap_drop ALL, and only registrar
# sees challenge-dns and home TLS.
set -euo pipefail
cd "$(dirname "$0")/.."
export ZONE=bobo.pens.hogman.network PUBLIC_HOST=bobo.gate.hogman.network NETWORK=bobo HOGMAN_UID=65532 HOGMAN_GID=65532
cfg="$(docker compose -p check -f compose.yaml config --format json)"
fail() { echo "FAIL: $*" >&2; exit 1; }
svcs="$(jq -r '.services | keys[]' <<<"$cfg")"
grep -qx step-ca <<<"$svcs" && fail "step-ca would start"
grep -qx core-mesh <<<"$svcs" && fail "core-mesh should be folded into registrar (I-15)"
grep -qx portal <<<"$svcs" && fail "portal Caddy should be folded into registrar (I-15)"
jq -e '.services.registrar.read_only == true' <<<"$cfg" >/dev/null || fail "registrar must be read_only"
jq -e '.services.registrar.cap_drop == ["ALL"] and ((.services.registrar.cap_add // []) | length) == 0' <<<"$cfg" >/dev/null || fail "registrar must drop ALL caps and add none"
jq -e '((.services.registrar.devices // []) | length) == 0' <<<"$cfg" >/dev/null || fail "registrar must not mount /dev/net/tun or any devices"
jq -e '.services.registrar.environment.TSNET_STATE_DIR == "/var/lib/registrar/tsnet"' <<<"$cfg" >/dev/null || fail "registrar missing TSNET_STATE_DIR"
jq -e '.services.registrar.environment.PORTAL_DIR == "/srv/portal"' <<<"$cfg" >/dev/null || fail "registrar missing PORTAL_DIR"
jq -e '.services.registrar.environment.CHALLENGE_DNS_URL == "unix:///run/hogman-acme/api.sock"' <<<"$cfg" >/dev/null || fail "registrar missing CHALLENGE_DNS_URL"
jq -e '.services.registrar.environment.HOME_TLS_DIR == "/home-tls"' <<<"$cfg" >/dev/null || fail "registrar missing HOME_TLS_DIR"
jq -e '.services.registrar.healthcheck.test | index("health")' <<<"$cfg" >/dev/null || fail "registrar has no health check"
mounts() { jq -r --arg s "$1" '.services[$s].volumes[]?.target' <<<"$cfg"; }
for s in $svcs; do
  for t in /run/hogman-acme /home-tls /run/caddy-admin /run/hogman-api; do
    if mounts "$s" | grep -qx "$t"; then
      case "$s:$t" in
        registrar:/run/hogman-acme|registrar:/home-tls) ;;
        *) fail "$s can see $t" ;;
      esac
    fi
  done
  mounts "$s" | grep -qx /pki && fail "$s still mounts /pki"
done
for s in $svcs; do
  jq -e --arg s "$s" '(.services[$s].cpus // 0) > 0 and .services[$s].cpu_shares == 256' <<<"$cfg" >/dev/null \
    || fail "$s must set cpus > 0 and cpu_shares: 256 (I-14)"
done
# Verify front-door overlay leaves only 2 active services (headscale + registrar).
front_cfg="$(docker compose -p check -f compose.yaml -f compose.front.yaml config --format json)"
front_svcs="$(jq -r '.services | keys | sort | join(",")' <<<"$front_cfg")"
[ "$front_svcs" = "headscale,registrar" ] || fail "front-door pen services = [$front_svcs], want [headscale,registrar]"
echo "public-certificate pen compose: ok"

# Verify every shipped Dockerfile FROM and Compose image is explicitly pinned
# by immutable @sha256 digest (no untagged or :latest images).
REPO="$(cd .. && pwd)"
shipped_from() {
  awk '
    FNR == 1 { split("", stages) }
    tolower($1) == "from" {
      i = 2
      while (i <= NF && substr($i, 1, 2) == "--") i++
      if (i > NF) next
      img = $i
      if (tolower(img) != "scratch" && !(tolower(img) in stages)) print img
      if ((i + 2) <= NF && tolower($(i + 1)) == "as") stages[tolower($(i + 2))] = 1
    }
  ' "$@"
}
expected_all="$(
  {
    jq -r '.services[].image // empty' <<<"$cfg" | grep -v '^hogman/'
    shipped_from \
      "$REPO/core/registrar/Dockerfile" \
      "$REPO/core/registrar/Dockerfile.prebuilt" \
      "$REPO/core/join/Dockerfile" \
      "$REPO/core/join/Dockerfile.sidecar" \
      "$REPO/core/join/Dockerfile.sidecar.prebuilt"
  } | sort -u
)"
[ -n "$expected_all" ] || fail "found no shipped container images"
while IFS= read -r img; do
  [[ "$img" =~ @sha256:[0-9a-f]{64}$ ]] || fail "shipped image is not pinned by immutable @sha256 digest: $img"
done <<< "$expected_all"
build_go_img="$(grep -m1 '^GO_IMAGE=' "$REPO/deploy/build-bins.sh" | cut -d'"' -f2)"
[[ "$build_go_img" =~ @sha256:[0-9a-f]{64}$ ]] || fail "deploy/build-bins.sh GO_IMAGE is not pinned by immutable @sha256 digest: $build_go_img"

echo "pinned shipped images:"
printf '  %s\n' $expected_all
echo "shipped container images check: ok"

# Verify non-root headscale/lib ownership migration in core/hogman uses an
# absolute host path mounted on /hslib (never /lib) and fails loudly on error.
tmp_mig="$(mktemp -d)"
trap 'rm -rf "$tmp_mig"' EXIT
mkdir -p "$tmp_mig/bin" "$tmp_mig/data/headscale/lib" "$tmp_mig/data/headscale/config" "$tmp_mig/data/join-dl"
cat > "$tmp_mig/bin/id" <<'SH'
#!/bin/sh
echo 1000
SH
cat > "$tmp_mig/bin/find" <<'SH'
#!/bin/sh
echo "$1/db.sqlite"
SH
cat > "$tmp_mig/bin/docker" <<'SH'
#!/bin/sh
printf '%s\n' "$@" > "$FAKE_DOCKER_LOG"
exit "${FAKE_DOCKER_RC:-0}"
SH
chmod +x "$tmp_mig/bin/id" "$tmp_mig/bin/find" "$tmp_mig/bin/docker"
mig_fn="$(awk '/^own_runtime_files\(\)/,/^}/' "$REPO/core/hogman")"
(
  cd "$REPO/core"
  export PATH="$tmp_mig/bin:$PATH"
  export DATA="$tmp_mig/data" HOGMAN_UID=1000 HOGMAN_GID=1000
  export FAKE_DOCKER_LOG="$tmp_mig/docker.args"
  die() { echo "hogman: $*" >&2; exit 1; }
  eval "$mig_fn"
  own_runtime_files
) || fail "non-root own_runtime_files migration failed unexpectedly"
grep -qx -- "$tmp_mig/data/headscale/lib:/hslib" "$tmp_mig/docker.args" \
  || fail "own_runtime_files did not mount $tmp_mig/data/headscale/lib:/hslib (got: $(tr '\n' ' ' < "$tmp_mig/docker.args"))"
grep -qx -- "/hslib" "$tmp_mig/docker.args" \
  || fail "own_runtime_files did not chown /hslib"
! grep -q -- ":/lib$" "$tmp_mig/docker.args" \
  || fail "own_runtime_files mounted onto /lib"
mig_err="$(
  cd "$REPO/core"
  export PATH="$tmp_mig/bin:$PATH"
  export DATA="$tmp_mig/data" HOGMAN_UID=1000 HOGMAN_GID=1000
  export FAKE_DOCKER_LOG="$tmp_mig/docker.args" FAKE_DOCKER_RC=1
  die() { echo "hogman: $*" >&2; exit 1; }
  eval "$mig_fn"
  own_runtime_files 2>&1
  echo UNEXPECTED_OK
)" || true
grep -q "UNEXPECTED_OK" <<<"$mig_err" && fail "own_runtime_files swallowed docker chown failure"
grep -q "sudo chown -R 1000:1000 $tmp_mig/data/headscale/lib" <<<"$mig_err" \
  || fail "own_runtime_files failure missing manual chown hint: $mig_err"
echo "non-root headscale/lib migration check: ok"
