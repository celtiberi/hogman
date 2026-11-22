# syntax=docker/dockerfile:1
# Cross-compiles hogman-join for every supported platform.
#   docker build --output type=local,dest=../data/join-dl join
# File names match `uname -s`-`uname -m`, so a one-line shell command can
# fetch the right one.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY *.go ./
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... && go test ./... && mkdir /out && \
    for t in Darwin-arm64:darwin/arm64 Darwin-x86_64:darwin/amd64 \
             Linux-x86_64:linux/amd64 Linux-aarch64:linux/arm64 \
             windows-amd64.exe:windows/amd64; do \
      name=${t%%:*}; plat=${t#*:}; \
      GOOS=${plat%/*} GOARCH=${plat#*/} CGO_ENABLED=0 \
        go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/hogman-join-$name . || exit 1; \
    done && cd /out && sha256sum hogman-join-* > SHA256SUMS

FROM scratch AS dist
COPY --from=build /out/ /
