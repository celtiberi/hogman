#!/usr/bin/env bash
# Compile Hogman's open-source binaries: the join client for every platform,
# plus the registrar and challenge DNS server for Linux (amd64, arm64).
# Needs Docker.
#
#   deploy/build-bins.sh <source-dir> <out-dir>
#
# <source-dir> holds core/join, core/registrar, and deploy/challenge-dns
# (a checkout, or an extracted git archive). Writes
# <out-dir>/{join,registrar,challenge-dns}.
# Run by the GitHub build workflow (.github/workflows/build.yml) and for local
# compilation checks. Releases only publish attested builds from build.yml.
set -euo pipefail
src="$(cd "$1" && pwd)"
out="$2"
mkdir -p "$out/join" "$out/registrar" "$out/challenge-dns"
out="$(cd "$out" && pwd)"

GO_IMAGE="golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

version="${VERSION:-}"
if [ -z "$version" ] && git -C "$src" rev-parse --verify HEAD >/dev/null 2>&1; then
  full="$(git -C "$src" rev-parse 'HEAD^{commit}')"
  commit_date="$(TZ=UTC git -C "$src" show -s --format=%cd --date=format-local:%Y.%m.%d "$full")"
  version="$commit_date-${full:0:7}"
fi
version="${version:-dev}"

echo "building the join tool (6 platforms, version $version), the registrar, and challenge-dns (linux amd64, arm64)..."

# Compile all three modules sequentially in the pinned Go container sharing
# hogman-gomod and hogman-gocache (no concurrent writers to shared volumes, no
# CPU/RAM oversubscription). core/join runs first so core/registrar reuses
# its compiled linux/amd64 and linux/arm64 tailscale/gvisor/certmagic objects
# under the identical GOFLAGS="-tags=ts_omit_peerapiserver -trimpath".
run_go_build() {
  local label="$1" mod_dir="$2" out_dir="$3" goflags="$4" script="$5"
  local t0=$SECONDS
  echo "  -> $label..."
  docker run --rm \
    -v "$mod_dir:/src:ro" \
    -v "$out_dir:/out" \
    -w /src \
    -e "GOFLAGS=$goflags" \
    -e "VERSION=$version" \
    -e "HOST_UID=$HOST_UID" \
    -e "HOST_GID=$HOST_GID" \
    -v hogman-gomod:/go/pkg/mod \
    -v hogman-gocache:/root/.cache/go-build \
    "$GO_IMAGE" sh -c "set -eu
$script
if [ \"\$HOST_UID\" != 0 ]; then
  chown -R \"\$HOST_UID:\$HOST_GID\" /out
fi"
  echo "  <- $label ($((SECONDS - t0))s)"
}

run_go_build "core/join" "$src/core/join" "$out/join" "-tags=ts_omit_peerapiserver -trimpath" '
  CGO_ENABLED=0 go vet ./...
  test_out="$(CGO_ENABLED=0 go test ./... 2>&1)" || { printf "%s\n" "$test_out" >&2; exit 1; }
  rm -f /out/hogman-* /out/SHA256SUMS
  for t in Linux-x86_64:linux/amd64 Linux-aarch64:linux/arm64 \
           Darwin-arm64:darwin/arm64 Darwin-x86_64:darwin/amd64 \
           windows-amd64.exe:windows/amd64 windows-arm64.exe:windows/arm64; do
    name=${t%%:*}; plat=${t#*:}
    GOOS=${plat%/*} GOARCH=${plat#*/} CGO_ENABLED=0 \
      go build -ldflags="-s -w -X main.version=$VERSION" -o "/out/hogman-$name" .
  done
  (cd /out && sha256sum hogman-* > SHA256SUMS)
'

run_go_build "core/registrar" "$src/core/registrar" "$out/registrar" "-tags=ts_omit_peerapiserver -trimpath" '
  CGO_ENABLED=0 go vet ./...
  test_out="$(CGO_ENABLED=0 go test ./... 2>&1)" || { printf "%s\n" "$test_out" >&2; exit 1; }
  for a in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -ldflags="-s -w" -o "/out/registrar-linux-$a" .
  done
'

run_go_build "deploy/challenge-dns" "$src/deploy/challenge-dns" "$out/challenge-dns" "-trimpath" '
  CGO_ENABLED=0 go vet ./...
  test_out="$(CGO_ENABLED=0 go test ./... 2>&1)" || { printf "%s\n" "$test_out" >&2; exit 1; }
  for a in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -ldflags="-s -w" -o "/out/challenge-dns-linux-$a" .
  done
'
