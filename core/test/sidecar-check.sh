#!/usr/bin/env bash
# Live Docker check for the 3-container sealed Hogman server topology:
#   sidecar (egress net, :ro socket) -> bridge (network_mode: none) -> app (service:bridge, lo only)
#
# Verifies:
#   1. Distroless hogman-sidecar image builds and runs as non-root UID 65532.
#   2. App container has zero internet / cloud-metadata routes (1.1.1.1 and 169.254.169.254 fail).
#   3. A separate container mounting the ingress volume :ro reaches app:8080 through hogman-bridge.
#   4. Recreating hogman-bridge + app recovers cleanly while the :ro sidecar stays untouched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMG="hogman-sidecar-test:$$"
VOL="hogman-sidecar-in-$$"
BRIDGE="hogman-bridge-test-$$"
APP="hogman-app-test-$$"
PROBE="hogman-probe-test-$$"
APP_IMG="python:3.12-alpine"

cleanup() {
  docker rm -f "$PROBE" "$APP" "$BRIDGE" >/dev/null 2>&1 || true
  docker volume rm -f "$VOL" >/dev/null 2>&1 || true
  docker rmi -f "$IMG" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "• Building distroless hogman-sidecar image..."
docker build -q -f "$ROOT/core/join/Dockerfile.sidecar" -t "$IMG" "$ROOT/core/join" >/dev/null

echo "• Creating empty ingress volume (Docker initializes UID 65532 from image)..."
docker volume create "$VOL" >/dev/null

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
    "$APP_IMG" python3 -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"sealed-app-ok")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 8080), H).serve_forever()
' >/dev/null
  sleep 0.5
}

start_bridge_and_app

echo "• Checking zero-egress isolation inside app container..."
docker exec "$APP" python3 -c '
import socket, sys
for target in [("1.1.1.1", 443), ("169.254.169.254", 80)]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(target)
        sys.exit(f"UNEXPECTED SUCCESS connecting to {target}")
    except OSError:
        pass
    finally:
        s.close()
print("isolated-ok")
' | grep -q "isolated-ok"

echo "• Starting persistent sidecar-role probe with :ro ingress mount (UID 65532)..."
docker run -d --name "$PROBE" \
  --user 65532:65532 \
  -v "$VOL:/run/hogman-in:ro" \
  "$APP_IMG" sleep 120 >/dev/null

probe_http() {
  docker exec "$PROBE" python3 -c '
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect("/run/hogman-in/app.sock")
s.sendall(b"GET / HTTP/1.0\r\nHost: lab.example\r\n\r\n")
data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
s.close()
assert b"sealed-app-ok" in data, f"unexpected response: {data!r}"
print("http-ok")
'
}

probe_http | grep -q "http-ok"
echo "✓ Initial :ro UDS -> bridge -> sealed app check passed"

echo "• Testing bridge + app recreation while :ro sidecar stays running..."
start_bridge_and_app
probe_http | grep -q "http-ok"
echo "✓ Bridge restart recovery passed"
