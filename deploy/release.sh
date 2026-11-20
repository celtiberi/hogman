#!/usr/bin/env bash
# Publish a Hogman release on hogman.network, where install.sh fetches it.
#
#   deploy/release.sh [git-ref]      default: origin/main
#
# Packages committed code only (never the working folder), writes
#   site/public/dl/hogman-<version>.tar.gz, SHA256SUMS and latest,
# plus hogman-bin-<version>.tar.gz (compiled join tool, registrar and sign-up page),
# then deploys the website.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
REF="${1:-origin/main}"
cd "$REPO"
git fetch -q origin 2>/dev/null || true
sha="$(git rev-parse --short=7 "$REF")"
ver="$(date -u +%Y.%m.%d)-$sha"
out="$REPO/site/public/dl"
mkdir -p "$out"

tarball="hogman-$ver.tar.gz"
git archive --format=tar --prefix= "$REF" core deploy/hogman-host deploy/bootstrap.sh deploy/README.md deploy/signup LICENSE README.md \
  | gzip -9n > "$out/$tarball"

# Compiled parts, so servers don't spend half an hour building them:
# the join tool for every platform, and the registrar for Linux servers.
bins="hogman-bin-$ver.tar.gz"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git archive --format=tar "$REF" core/join core/registrar deploy/signup | tar -x -C "$work"
echo "building the join tool (5 platforms), the registrar and the sign-up page (linux amd64, arm64)..."
docker build -q --output "type=local,dest=$work/prebuilt/join" "$work/core/join" >/dev/null
mkdir -p "$work/prebuilt/registrar"
docker run --rm -v "$work/core/registrar:/src:ro" -v "$work/prebuilt/registrar:/out" -w /src \
  -v hogman-gomod:/go/pkg/mod -v hogman-gocache:/root/.cache/go-build golang:1.27-alpine sh -c '
    set -e
    CGO_ENABLED=0 go test ./... >/dev/null
    for a in amd64 arm64; do
      CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -trimpath -ldflags="-s -w" -o /out/registrar-linux-$a .
    done'
mkdir -p "$work/prebuilt/signup"
docker run --rm -v "$work/deploy/signup:/src:ro" -v "$work/prebuilt/signup:/out" -w /src \
  -v hogman-gomod:/go/pkg/mod -v hogman-gocache:/root/.cache/go-build golang:1.27-alpine sh -c '
    set -e
    CGO_ENABLED=0 go test ./... >/dev/null
    for a in amd64 arm64; do
      CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -trimpath -ldflags="-s -w" -o /out/hogman-signup-linux-$a .
    done'
# No macOS file metadata in the bundle (Linux tar warns about it).
COPYFILE_DISABLE=1 tar -C "$work" -czf "$out/$bins" prebuilt

# Keep only the newest bundles; the website serves just the current release.
find "$out" -maxdepth 1 -name 'hogman-*.tar.gz' ! -name "$tarball" ! -name "$bins" -delete

( cd "$out"
  if command -v sha256sum >/dev/null; then sha256sum "$tarball" "$bins"; else shasum -a 256 "$tarball" "$bins"; fi > SHA256SUMS
  echo "$ver" > latest )
echo "compiled bundle $bins ($(du -h "$out/$bins" | cut -f1))"

echo "release $ver ($(du -h "$out/$tarball" | cut -f1)) from $REF"
if [ "${NO_DEPLOY:-}" != 1 ]; then
  (cd "$REPO/site" && fly deploy --ha=false 2>&1 | grep -E "Visit|rror")
  echo "live: https://hogman.network/dl/latest -> $(curl -fsS https://hogman.network/dl/latest)"
fi
