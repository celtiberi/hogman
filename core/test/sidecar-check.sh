#!/usr/bin/env bash
# Live Docker check for the 3-container sealed Hogman server topology:
#   sidecar (egress net, :ro socket) -> bridge (network_mode: none) -> app (service:bridge, lo only)
#
# Verifies:
#   1. The docker-compose.yml in docs/sealed-server.md passes `docker compose config -q`.
#   2. Scratch hogman-sidecar image builds for the host architecture (not hardcoded amd64)
#      and initializes named volumes with UID 65532:65532 and mode 0700.
#   3. App container has zero internet / cloud-metadata routes (1.1.1.1 and 169.254.169.254 fail).
#   4. A separate container mounting the ingress volume :ro reaches app:8080 through hogman-bridge.
#   5. Recreating hogman-bridge + app recovers cleanly while the :ro sidecar stays untouched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMG="${SIDECAR_PREBUILT_IMG:-hogman-sidecar-test:$$}"
VOL="hogman-sidecar-in-$$"
BRIDGE="hogman-bridge-test-$$"
APP="hogman-app-test-$$"
PROBE="hogman-probe-test-$$"
ALPINE_IMG="alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
CADDY_IMG="caddy:2.11.9@sha256:4851e54a46b206517c574821bb5cc67f170d2156041e9fbc4c9193b45e84a75b"
GO_IMG="golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280"
TMP_COMPOSE="$(mktemp "${TMPDIR:-/tmp}/sealed-compose.XXXXXX.yml")"

cleanup() {
  docker rm -f "$PROBE" "$APP" "$BRIDGE" >/dev/null 2>&1 || true
  docker volume rm -f "$VOL" >/dev/null 2>&1 || true
  if [ -z "${SIDECAR_PREBUILT_IMG:-}" ]; then
    docker rmi -f "$IMG" >/dev/null 2>&1 || true
  fi
  rm -f "$TMP_COMPOSE"
}
trap cleanup EXIT

pull_retry() {
  local img="$1" i
  for i in 1 2 3; do
    docker image inspect "$img" >/dev/null 2>&1 && return 0
    docker pull -q "$img" >/dev/null && return 0
    echo "docker pull $img failed (attempt $i/3); retrying..." >&2
    sleep 2
  done
  docker pull -q "$img" >/dev/null
}

echo "• Validating docker-compose.yml example in docs/sealed-server.md..."
awk '
  /^```yaml$/ { in_block=1; next }
  /^```$/ && in_block { exit }
  in_block { print }
' "$ROOT/docs/sealed-server.md" > "$TMP_COMPOSE"
test -s "$TMP_COMPOSE"
docker compose -f "$TMP_COMPOSE" config -q
echo "✓ docs/sealed-server.md compose config valid"

if [ -z "${SIDECAR_PREBUILT_IMG:-}" ]; then
  echo "• Building scratch hogman-sidecar image..."
  docker build -q -f "$ROOT/core/join/Dockerfile.sidecar" -t "$IMG" "$ROOT/core/join" >/dev/null
else
  echo "• Using prebuilt hogman-sidecar image ($IMG)..."
fi

want_arch="amd64"
case "$(uname -m)" in aarch64|arm64) want_arch="arm64" ;; esac
got_ver="$(docker run --rm "$IMG" --version)"
grep -q "linux/$want_arch" <<<"$got_ver" || {
  echo "expected linux/$want_arch binary, got: $got_ver" >&2
  exit 1
}
echo "✓ Image binary architecture matches host ($got_ver)"

echo "• Creating empty ingress volume (Docker initializes UID 65532 mode 0700 from image)..."
docker volume create "$VOL" >/dev/null

echo "• Pulling runtime test images..."
pull_retry "$CADDY_IMG"
pull_retry "$ALPINE_IMG"
pull_retry "$GO_IMG"

start_bridge_and_app() {
  docker rm -f "$APP" "$BRIDGE" >/dev/null 2>&1 || true
  docker run -d --name "$BRIDGE" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:size=4m,noexec,nosuid,nodev \
    -v "$VOL:/run/hogman-in" \
    "$IMG" bridge --listen-unix=/run/hogman-in/app.sock --forward-tcp=127.0.0.1:8080 >/dev/null

  for _ in $(seq 1 20); do
    if docker exec "$BRIDGE" /hogman bridge --check /run/hogman-in/app.sock >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
  docker exec "$BRIDGE" /hogman bridge --check /run/hogman-in/app.sock

  docker run -d --name "$APP" \
    --network "container:$BRIDGE" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
    "$CADDY_IMG" sh -c 'mkdir -p /tmp/www && printf "sealed-app-ok" > /tmp/www/index.html && exec caddy file-server --listen 127.0.0.1:8080 --root /tmp/www' >/dev/null
  sleep 0.5
}

start_bridge_and_app

echo "• Verifying volume ownership/mode (65532:65532 700)..."
vol_stat="$(docker run --rm -v "$VOL:/run/hogman-in:ro" "$ALPINE_IMG" stat -c '%u:%g %a' /run/hogman-in)"
test "$vol_stat" = "65532:65532 700" || {
  echo "unexpected volume stat: $vol_stat (want 65532:65532 700)" >&2
  exit 1
}
echo "✓ Named volume initialized as 65532:65532 0700"

echo "• Checking zero-egress isolation inside app container..."
if docker exec "$APP" sh -c 'nc -z -w 2 1.1.1.1 443' >/dev/null 2>&1; then
  echo "UNEXPECTED SUCCESS connecting to 1.1.1.1:443 from sealed app" >&2
  exit 1
fi
if docker exec "$APP" sh -c 'nc -z -w 2 169.254.169.254 80' >/dev/null 2>&1; then
  echo "UNEXPECTED SUCCESS connecting to 169.254.169.254:80 from sealed app" >&2
  exit 1
fi
echo "✓ Zero-egress check passed (1.1.1.1 and 169.254.169.254 unreachable)"

echo "• Starting persistent sidecar-role probe with :ro ingress mount (UID 65532)..."
docker run -d --name "$PROBE" \
  --user 65532:65532 \
  -e GOCACHE=/tmp/gocache \
  -v "$VOL:/run/hogman-in:ro" \
  "$GO_IMG" sleep 120 >/dev/null

docker exec "$PROBE" sh -c 'cat > /tmp/probe.go <<EOF
package main
import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)
func main() {
	c, err := net.DialTimeout("unix", "/run/hogman-in/app.sock", 3*time.Second)
	if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("GET / HTTP/1.0\r\nHost: lab.example\r\n\r\n"))
	b, err := io.ReadAll(c)
	if err != nil || !strings.Contains(string(b), "sealed-app-ok") {
		fmt.Fprintf(os.Stderr, "unexpected response: %q (err=%v)\n", string(b), err)
		os.Exit(1)
	}
	fmt.Println("http-ok")
}
EOF
go build -o /tmp/probe /tmp/probe.go'

probe_http() {
  docker exec "$PROBE" /tmp/probe | grep -q "http-ok"
}

probe_http
echo "✓ Initial :ro UDS -> bridge -> sealed app check passed"

echo "• Testing bridge + app recreation while :ro sidecar stays running..."
start_bridge_and_app
probe_http
echo "✓ Bridge restart recovery passed"
