# syntax=docker/dockerfile:1
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
ENV GOFLAGS=-trimpath
COPY go.mod ./
COPY *.go ./
COPY web ./web
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -ldflags="-s -w" -o /hogman-ops .

FROM scratch
COPY --from=build /hogman-ops /hogman-ops
USER 65532:65532
ENTRYPOINT ["/hogman-ops"]
