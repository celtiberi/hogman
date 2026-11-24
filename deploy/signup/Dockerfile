# Two images from one program: the public page (web) and the pen-raiser (broker).
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN apk add --no-cache ca-certificates && go mod download
COPY *.go ./
COPY web ./web
RUN CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /hogman-signup .

FROM scratch AS web
# Root certificates: the page talks to Stripe's API over HTTPS when it sells pens.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /hogman-signup /hogman-signup
USER 65534:65534
ENV ROLE=web
ENTRYPOINT ["/hogman-signup"]

# hogman-host and ./hogman run in here, so it carries what they use.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS broker
RUN apk add --no-cache bash coreutils findutils grep sed gawk tar gzip rsync age openssl curl util-linux sqlite \
      ca-certificates docker-cli docker-cli-compose docker-cli-buildx
COPY --from=build /hogman-signup /usr/local/bin/hogman-signup
ENV ROLE=broker
ENTRYPOINT ["hogman-signup"]
