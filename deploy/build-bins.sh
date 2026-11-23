#!/usr/bin/env bash
# Compile Hogman's own programs, so servers don't spend half an hour building
# them: the join tool for every platform, and the registrar and the sign-up
# page for Linux servers (amd64, arm64). Needs Docker (with buildx).
#
#   deploy/build-bins.sh <source-dir> <out-dir>
#
# <source-dir> holds core/join, core/registrar, deploy/signup and
# deploy/challenge-dns (a checkout, or an extracted git archive). Writes
# <out-dir>/{join,registrar,signup,challenge-dns}.
# Used by release.sh when Docker is available, and by the GitHub build
# workflow (.github/workflows/build.yml) otherwise.
set -euo pipefail
src="$(cd "$1" && pwd)"
out="$2"
mkdir -p "$out/join" "$out/registrar" "$out/signup" "$out/challenge-dns"
out="$(cd "$out" && pwd)"

GO_IMAGE="golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280"

echo "building the join tool (5 platforms), the registrar and the sign-up page (linux amd64, arm64)..."
docker build -q --output "type=local,dest=$out/join" "$src/core/join" >/dev/null
docker run --rm -v "$src/core/registrar:/src:ro" -v "$out/registrar:/out" -w /src \
  -v hogman-gomod:/go/pkg/mod -v hogman-gocache:/root/.cache/go-build "$GO_IMAGE" sh -c '
    set -e
    CGO_ENABLED=0 go test ./... >/dev/null
    for a in amd64 arm64; do
      CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -trimpath -ldflags="-s -w" -o /out/registrar-linux-$a .
    done'
docker run --rm -v "$src/deploy/signup:/src:ro" -v "$out/signup:/out" -w /src \
  -v hogman-gomod:/go/pkg/mod -v hogman-gocache:/root/.cache/go-build "$GO_IMAGE" sh -c '
    set -e
    CGO_ENABLED=0 go test ./... >/dev/null
    for a in amd64 arm64; do
      CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -trimpath -ldflags="-s -w" -o /out/hogman-signup-linux-$a .
    done'
docker run --rm -v "$src/deploy/challenge-dns:/src:ro" -v "$out/challenge-dns:/out" -w /src \
  -v hogman-gomod:/go/pkg/mod -v hogman-gocache:/root/.cache/go-build "$GO_IMAGE" sh -c '
    set -e
    CGO_ENABLED=0 go test ./... >/dev/null
    for a in amd64 arm64; do
      CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -trimpath -ldflags="-s -w" -o /out/challenge-dns-linux-$a .
    done'
