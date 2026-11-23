# Two images from one program: the public page (web) and the pen-raiser (broker).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web ./web
RUN CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /hogman-signup .

FROM scratch AS web
COPY --from=build /hogman-signup /hogman-signup
USER 65534:65534
ENV ROLE=web
ENTRYPOINT ["/hogman-signup"]

# hogman-host and ./hogman run in here, so it carries what they use.
FROM alpine:3.24 AS broker
RUN apk add --no-cache bash coreutils findutils grep sed gawk tar gzip rsync age openssl curl util-linux \
      ca-certificates docker-cli docker-cli-compose docker-cli-buildx
COPY --from=build /hogman-signup /usr/local/bin/hogman-signup
ENV ROLE=broker
ENTRYPOINT ["hogman-signup"]
