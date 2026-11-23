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

# Verify every shipped Dockerfile FROM and Compose image is explicitly pinned
# (no untagged or :latest images) and covered by `hogman-host pull-images` so
# the offline sign-up broker never needs container registry access.
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
    grep -m1 '^CADDY_IMAGE=' "$REPO/deploy/hogman-host" | cut -d'"' -f2
    jq -r '.services[].image // empty' <<<"$cfg" | grep -v '^hogman/'
    shipped_from \
      "$REPO/core/registrar/Dockerfile" \
      "$REPO/core/registrar/Dockerfile.prebuilt" \
      "$REPO/core/join/Dockerfile" \
      "$REPO/deploy/signup/Dockerfile" \
      "$REPO/deploy/signup/Dockerfile.prebuilt"
  } | sort -u
)"
[ -n "$expected_all" ] || fail "found no shipped container images"
while IFS= read -r img; do
  [[ "$img" =~ @sha256:[0-9a-f]{64}$ ]] || fail "shipped image is not pinned by immutable @sha256 digest: $img"
done <<< "$expected_all"
build_go_img="$(grep -m1 '^GO_IMAGE=' "$REPO/deploy/build-bins.sh" | cut -d'"' -f2)"
[[ "$build_go_img" =~ @sha256:[0-9a-f]{64}$ ]] || fail "deploy/build-bins.sh GO_IMAGE is not pinned by immutable @sha256 digest: $build_go_img"

tmp_home="$(mktemp -d)"
trap 'rm -rf "$tmp_home"' EXIT
ln -s "$REPO/core" "$tmp_home/src"
ln -s "$REPO/deploy/signup" "$tmp_home/signup-src"
got_all="$(HOGMAN_HOME="$tmp_home" "$REPO/deploy/hogman-host" pull-images --list --all)"
if [ "$got_all" != "$expected_all" ]; then
  echo "expected:" >&2; printf '  %s\n' $expected_all >&2
  echo "got:" >&2; printf '  %s\n' $got_all >&2
  fail "hogman-host pull-images --list --all mismatch"
fi

# Verify prebuilt-host mode covers every runtime + prebuilt base image without
# pulling the source-build Go toolchain image.
tmp_pre="$(mktemp -d)"
trap 'rm -rf "$tmp_home" "$tmp_pre"' EXIT
arch="$(uname -m)"; case "$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; esac
mkdir -p "$tmp_pre/src/registrar" "$tmp_pre/src/prebuilt/registrar" "$tmp_pre/src/prebuilt/join" "$tmp_pre/src/prebuilt/signup" "$tmp_pre/signup-src"
cp "$REPO/core/compose.yaml" "$tmp_pre/src/compose.yaml"
cp "$REPO/core/registrar/Dockerfile.prebuilt" "$tmp_pre/src/registrar/Dockerfile.prebuilt"
cp "$REPO/core/registrar/Dockerfile" "$tmp_pre/src/registrar/Dockerfile"
cp "$REPO/deploy/signup/Dockerfile.prebuilt" "$tmp_pre/signup-src/Dockerfile.prebuilt"
cp "$REPO/deploy/signup/Dockerfile" "$tmp_pre/signup-src/Dockerfile"
touch "$tmp_pre/src/prebuilt/registrar/registrar-linux-$arch" \
      "$tmp_pre/src/prebuilt/join/SHA256SUMS" \
      "$tmp_pre/src/prebuilt/signup/hogman-signup-linux-$arch"
got_pre="$(HOGMAN_HOME="$tmp_pre" "$REPO/deploy/hogman-host" pull-images --list)"
expected_pre="$(
  {
    grep -m1 '^CADDY_IMAGE=' "$REPO/deploy/hogman-host" | cut -d'"' -f2
    jq -r '.services[].image // empty' <<<"$cfg" | grep -v '^hogman/'
    shipped_from \
      "$REPO/core/registrar/Dockerfile.prebuilt" \
      "$REPO/deploy/signup/Dockerfile.prebuilt"
  } | sort -u
)"
[ "$got_pre" = "$expected_pre" ] || fail "prebuilt pull-images list mismatch: got [$got_pre], want [$expected_pre]"
grep -q '^golang:' <<<"$got_pre" && fail "prebuilt pull-images unexpectedly includes golang image"

echo "pinned shipped images (pull-images --all):"
printf '  %s\n' $got_all
echo "shipped container images check: ok"

# Verify non-root headscale/lib ownership migration in core/hogman uses an
# absolute host path mounted on /hslib (never /lib) and fails loudly on error.
tmp_mig="$(mktemp -d)"
trap 'rm -rf "$tmp_home" "$tmp_pre" "$tmp_mig"' EXIT
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
