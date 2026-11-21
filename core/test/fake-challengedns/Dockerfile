FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fake-challengedns .

FROM alpine:3.22
COPY --from=build /out/fake-challengedns /usr/local/bin/fake-challengedns
ENTRYPOINT ["/usr/local/bin/fake-challengedns"]
