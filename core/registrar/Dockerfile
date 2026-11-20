FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /registrar .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=build /registrar /usr/local/bin/registrar
ENTRYPOINT ["registrar"]
CMD ["serve"]
