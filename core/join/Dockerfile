# syntax=docker/dockerfile:1
# Cross-compiles the hogman client CLI for every supported platform.
#   docker build --output type=local,dest=../data/join-dl join
# File names match `uname -s`-`uname -m`, so a one-line shell command can
# fetch the right one.
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS test
WORKDIR /src
ENV GOFLAGS=-tags=ts_omit_peerapiserver
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY *.go ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... && go test ./...

FROM test AS build
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    mkdir /out && \
    for t in Darwin-arm64:darwin/arm64 Darwin-x86_64:darwin/amd64 \
             Linux-x86_64:linux/amd64 Linux-aarch64:linux/arm64 \
             windows-amd64.exe:windows/amd64; do \
      name=${t%%:*}; plat=${t#*:}; \
      GOOS=${plat%/*} GOARCH=${plat#*/} CGO_ENABLED=0 \
        go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/hogman-$name . || exit 1; \
    done && cd /out && sha256sum hogman-* > SHA256SUMS

FROM scratch AS dist
COPY --from=build /out/ /
