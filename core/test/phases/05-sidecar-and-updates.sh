# Phase 5: Sealed sidecar E2E, hogman update / legacy migration / downgrade guard, and dave leave.

# Sealed sidecar E2E: real scratch hogman-sidecar container -> --enroll-only --link-stdin
# -> serve over mesh via :ro UDS -> network_mode: none bridge -> app -> docker kill PID 1
# -> restart on the exact same state volume and serve again.
step "Sealed server sidecar (enroll, serve, kill PID 1, restart)"
SIDECAR_IMG="hogman-sidecar-e2e:$$"
SIDECAR_STATE="hogman-e2e-state-$$"
SIDECAR_IN="hogman-e2e-in-$$"
SIDECAR_CTR="hogman-e2e-sidecar-$$"
BRIDGE_CTR="hogman-e2e-bridge-$$"
APP_CTR="hogman-e2e-app-$$"
OUTSIDE_NET="$(docker inspect "$(dc ps -q dave-server)" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' | tr ' ' '\n' | grep -v '^hogman-test-acme$' | grep -v '^$' | head -n 1)"
mkdir -p "$WORK/sidecar-ca"
cp "$WORK/data/edge-trust/root.crt" "$WORK/sidecar-ca/root.crt"
cp "$ACME/bundle.crt" "$WORK/sidecar-ca/bundle.crt"
cat "$WORK/data/edge-trust/root.crt" "$ACME/bundle.crt" > "$WORK/sidecar-ca/combined.crt"
chmod 755 "$WORK/sidecar-ca" && chmod 644 "$WORK/sidecar-ca"/*.crt

if [ -f "$SRC/prebuilt/join/hogman-$(uname -s)-$(uname -m)" ] && [ -f "$REPO/core/join/Dockerfile.sidecar.prebuilt" ]; then
  mkdir -p "$WORK/sidecar-ctx"
  sidecar_arch="$(test_goarch)"
  sidecar_arch="${sidecar_arch:-amd64}"
  install -m 0755 "$SRC/prebuilt/join/hogman-$(uname -s)-$(uname -m)" "$WORK/sidecar-ctx/hogman-linux-$sidecar_arch"
  docker build -q -f "$REPO/core/join/Dockerfile.sidecar.prebuilt" -t "$SIDECAR_IMG" "$WORK/sidecar-ctx" >/dev/null
else
  docker build -q -f "$REPO/core/join/Dockerfile.sidecar" -t "$SIDECAR_IMG" "$REPO/core/join" >/dev/null
fi
docker volume create "$SIDECAR_STATE" >/dev/null
docker volume create "$SIDECAR_IN" >/dev/null
SEALED_LINK="$($H device key dave server | awk '/^link:/ {print $2}')"

ENROLL_CTR="$(docker create -i \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
  --network "$OUTSIDE_NET" \
  -v "$SIDECAR_STATE:/var/lib/hogman" \
  -v "$WORK/sidecar-ca:/sidecar-ca:ro" \
  -e SSL_CERT_FILE=/sidecar-ca/combined.crt \
  -e HOGMAN_ACME_CA_ROOT=/sidecar-ca/bundle.crt \
  -e HOGMAN_ACME_CA_URL=https://pebble:14000/dir \
  -e HOGMAN_ACME_RESOLVERS=hogman-run-cdns:53 \
  -e HOGMAN_ACME_PROPAGATION_DELAY=100ms \
  -e HOGMAN_ACME_PROPAGATION_TIMEOUT=30s \
  "$SIDECAR_IMG" share sealed unix:///run/hogman-in/app.sock \
    --state-dir=/var/lib/hogman --control-ca=/sidecar-ca/root.crt --enroll-only --link-stdin)"
docker network connect hogman-test-acme "$ENROLL_CTR"
out="$(printf '%s\n' "$SEALED_LINK" | docker start -a -i "$ENROLL_CTR" 2>&1)"; rc=$?
docker rm -f "$ENROLL_CTR" >/dev/null 2>&1 || true
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "sidecar --enroll-only --link-stdin enrolls cleanly (exit $rc)" bash -c 'test "$1" = 0 && grep -q "Enrolled https://sealed.'"$ZONE"'" <<<"$2"' _ "$rc" "$out"

docker run -d --name "$BRIDGE_CTR" \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=4m,noexec,nosuid,nodev \
  -v "$SIDECAR_IN:/run/hogman-in" \
  "$SIDECAR_IMG" bridge --listen-unix=/run/hogman-in/app.sock --forward-tcp=127.0.0.1:8080 >/dev/null
retry 15 docker exec "$BRIDGE_CTR" /hogman bridge --check /run/hogman-in/app.sock

docker run -d --name "$APP_CTR" \
  --network "container:$BRIDGE_CTR" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
  caddy:2.11.9@sha256:4851e54a46b206517c574821bb5cc67f170d2156041e9fbc4c9193b45e84a75b \
  sh -c 'mkdir -p /tmp/www && printf "sealed sidecar ok" > /tmp/www/index.html && exec caddy file-server --listen 127.0.0.1:8080 --root /tmp/www' >/dev/null

start_live_sidecar() {
  docker rm -f "$SIDECAR_CTR" >/dev/null 2>&1 || true
  docker create --name "$SIDECAR_CTR" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
    --network "$OUTSIDE_NET" \
    -v "$SIDECAR_STATE:/var/lib/hogman" \
    -v "$SIDECAR_IN:/run/hogman-in:ro" \
    -v "$WORK/sidecar-ca:/sidecar-ca:ro" \
    -e SSL_CERT_FILE=/sidecar-ca/combined.crt \
    -e HOGMAN_ACME_CA_ROOT=/sidecar-ca/bundle.crt \
    -e HOGMAN_ACME_CA_URL=https://pebble:14000/dir \
    -e HOGMAN_ACME_RESOLVERS=hogman-run-cdns:53 \
    -e HOGMAN_ACME_PROPAGATION_DELAY=100ms \
    -e HOGMAN_ACME_PROPAGATION_TIMEOUT=30s \
    "$SIDECAR_IMG" share sealed unix:///run/hogman-in/app.sock \
      --state-dir=/var/lib/hogman --control-ca=/sidecar-ca/root.crt >/dev/null
  docker network connect hogman-test-acme "$SIDECAR_CTR"
  docker start "$SIDECAR_CTR" >/dev/null
}

start_live_sidecar
check "members load https://sealed.$ZONE through scratch sidecar -> :ro UDS -> bridge -> app" retry 45 fetch sealed.$ZONE "sealed sidecar ok"

docker kill "$SIDECAR_CTR" >/dev/null 2>&1 || true
start_live_sidecar
check "... and after docker kill (stale PID 1), sidecar restarts on same state volume" retry 45 fetch sealed.$ZONE "sealed sidecar ok"
docker rm -f "$SIDECAR_CTR" "$APP_CTR" "$BRIDGE_CTR" >/dev/null 2>&1 || true
docker volume rm -f "$SIDECAR_STATE" "$SIDECAR_IN" >/dev/null 2>&1 || true
docker rmi -f "$SIDECAR_IMG" >/dev/null 2>&1 || true

out="$(join_tool dave-laptop update --pen "$ZONE" --dry-run 2>&1)"; rc=$?
check "hogman update --dry-run checks SHA256SUMS cleanly (exit $rc)" bash -c 'test "$1" = 0 && grep -q "already up to date" <<<"$2"' _ "$rc" "$out"
BEFORE_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
# Simulate an existing hogman-join install layout (stale canonical binary,
# legacy per-pen hogman-join copy, and a regular-file native-host copy).
run dave-laptop sh -c '
  cp "/dl/hogman-$(uname -s)-$(uname -m)" "/root/.config/hogman/'"$ZONE"'/hogman-join"
  cp "/dl/hogman-$(uname -s)-$(uname -m)" "/root/.config/hogman/bin/hogman-native-host"
  printf "#!/bin/sh\nexit 1\n" > "/root/.config/hogman/bin/.stale-join" && chmod 755 "/root/.config/hogman/bin/.stale-join" && mv "/root/.config/hogman/bin/.stale-join" "/root/.config/hogman/bin/hogman"
'
out="$(join_tool dave-laptop update --pen "$ZONE" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "hogman update consolidates legacy hogman-join layout and restarts agent (exit $rc)" bash -c 'test "$1" = 0 && grep -q "Updated " <<<"$2"' _ "$rc" "$out"
AFTER_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
check "... restarted agent with a new process" test -n "$BEFORE_PID" -a -n "$AFTER_PID" -a "$BEFORE_PID" != "$AFTER_PID"
check "... and installed binary matches /join/dl exactly" run dave-laptop sh -c 'cmp -s "/root/.config/hogman/bin/hogman" "/dl/hogman-$(uname -s)-$(uname -m)"'
check "... and removed legacy per-pen hogman-join copy" run dave-laptop sh -c 'test ! -e "/root/.config/hogman/'"$ZONE"'/hogman-join"'
check "... and converted hogman-native-host into a symlink to hogman" run dave-laptop sh -c 'test -L "/root/.config/hogman/bin/hogman-native-host"'
check "... and restarted agent still loads alice.$ZONE" retry 20 alice_via

# I-10 E2E (1): a running legacy hogman-join agent holding the proxy port must
# be stopped cleanly when the new hogman client runs on the same pen (e.g. via /start).
run dave-laptop sh -c '
  pid="$(cat "/root/.config/hogman/'"$ZONE"'/agent.pid" 2>/dev/null || true)"
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  sleep 1
  cp "/dl/hogman-$(uname -s)-$(uname -m)" "/root/.config/hogman/'"$ZONE"'/hogman-join"
  rm -f "/root/.config/hogman/'"$ZONE"'/status.token"
  nohup "/root/.config/hogman/'"$ZONE"'/hogman-join" agent "/root/.config/hogman/'"$ZONE"'" >/root/.config/hogman/'"$ZONE"'/agent.log 2>&1 </dev/null &
'
retry 20 run dave-laptop sh -c 'test -s "/root/.config/hogman/'"$ZONE"'/agent.pid" && kill -0 "$(cat "/root/.config/hogman/'"$ZONE"'/agent.pid")" 2>/dev/null'
LEGACY_AGENT_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
out="$(join_tool dave-laptop --no-system-proxy "$DAVE_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "re-running hogman replaces a running legacy hogman-join agent on the same port (exit $rc)" bash -c 'test "$1" = 0 && grep -q "You'\''re in." <<<"$2"' _ "$rc" "$out"
NEW_AGENT_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
check "... replaced legacy agent PID ($LEGACY_AGENT_PID -> $NEW_AGENT_PID)" test -n "$LEGACY_AGENT_PID" -a -n "$NEW_AGENT_PID" -a "$LEGACY_AGENT_PID" != "$NEW_AGENT_PID"
check "... cleaned up legacy hogman-join copy after restart" run dave-laptop sh -c 'test ! -e "/root/.config/hogman/'"$ZONE"'/hogman-join"'
check "... and new agent loads alice.$ZONE" retry 20 alice_via

# I-10 E2E (2): two legacy pens where the first pen's server is unreachable and
# the second pen is healthy: `hogman update` must not stop at the dead pen, must
# skip the 60s online wait for it, and must still migrate the healthy pen.
docker exec -d "$(dc ps -q dave-server)" sh -c '
  set -e
  mkdir -p /tmp/rel/latest/download /tmp/rel/download/v2026.11.24
  printf "2026.11.24\n" > /tmp/rel/latest/download/latest
  cp /dl/SHA256SUMS /tmp/rel/download/v2026.11.24/hogman-SHA256SUMS
  cp /dl/hogman-* /tmp/rel/download/v2026.11.24/
  cat > /tmp/rel/Caddyfile <<EOF
{
  auto_https disable_redirects
}
dave-server:8443 {
  tls internal
  root * /tmp/rel
  file_server
}
EOF
  caddy run --config /tmp/rel/Caddyfile >/tmp/rel/caddy.log 2>&1
'
retry 20 run dave-server test -s /data/caddy/pki/authorities/local/root.crt
run dave-server cat /data/caddy/pki/authorities/local/root.crt | docker exec -i "$(dc ps -q dave-laptop)" sh -c 'cat > /usr/local/share/ca-certificates/rel-ca.crt && update-ca-certificates >/dev/null 2>&1'
BEFORE_MULTI_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
run dave-laptop sh -c '
  mkdir -p /root/.config/hogman/aaa-dead.example.test
  printf "{\"zone\":\"aaa-dead.example.test\",\"login_server\":\"https://127.0.0.1:1\",\"dns_server\":\"100.64.0.1\",\"hostname\":\"dead\",\"proxy_addr\":\"127.0.0.1:19999\"}\n" > /root/.config/hogman/aaa-dead.example.test/config.json
  cp "/dl/hogman-$(uname -s)-$(uname -m)" /root/.config/hogman/aaa-dead.example.test/hogman-join
  nohup /root/.config/hogman/aaa-dead.example.test/hogman-join agent /root/.config/hogman/aaa-dead.example.test >/root/.config/hogman/aaa-dead.example.test/agent.log 2>&1 </dev/null &
  cp "/dl/hogman-$(uname -s)-$(uname -m)" "/root/.config/hogman/'"$ZONE"'/hogman-join"
'
retry 20 run dave-laptop sh -c 'test -s /root/.config/hogman/aaa-dead.example.test/agent.pid && kill -0 "$(cat /root/.config/hogman/aaa-dead.example.test/agent.pid)" 2>/dev/null'
DEAD_OLD_PID="$(run dave-laptop cat /root/.config/hogman/aaa-dead.example.test/agent.pid 2>/dev/null | tr -d '\r')"
t0="$(date +%s)"
out="$(run dave-laptop sh -c 'HOGMAN_RELEASE_BASE="https://dave-server:8443" "/dl/hogman-$(uname -s)-$(uname -m)" --no-open update' 2>&1)"; rc=$?
t_multi=$(( $(date +%s) - t0 ))
check "hogman update with one dead pen + one live pen reports failure (exit $rc, ${t_multi}s)" bash -c 'test "$1" != 0 && grep -q "hogman leave aaa-dead.example.test" <<<"$2"' _ "$rc" "$out"
check "... skipped the 60s wait on the unreachable pen (${t_multi}s < 45s)" test "$t_multi" -lt 45
check "... replaced dead pen old agent ($DEAD_OLD_PID) with live canonical hogman agent without waiting (B1)" retry 10 run dave-laptop sh -c 'pid="$(cat /root/.config/hogman/aaa-dead.example.test/agent.pid 2>/dev/null || true)"; test -n "$pid" && test "$pid" != "$1" && kill -0 "$pid" 2>/dev/null && test "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" = "/root/.config/hogman/bin/hogman"' _ "$DEAD_OLD_PID"
AFTER_MULTI_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
check "... still migrated and restarted the healthy pen ($BEFORE_MULTI_PID -> $AFTER_MULTI_PID)" test -n "$BEFORE_MULTI_PID" -a -n "$AFTER_MULTI_PID" -a "$BEFORE_MULTI_PID" != "$AFTER_MULTI_PID"
check "... removed legacy hogman-join copy on BOTH pens" run dave-laptop sh -c 'test ! -e /root/.config/hogman/aaa-dead.example.test/hogman-join && test ! -e "/root/.config/hogman/'"$ZONE"'/hogman-join"'
check "... and healthy pen still loads alice.$ZONE" retry 20 alice_via
run dave-laptop sh -c 'pid="$(cat /root/.config/hogman/aaa-dead.example.test/agent.pid 2>/dev/null || true)"; [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; rm -rf /root/.config/hogman/aaa-dead.example.test'

# Downgrade guard E2E (I-8 follow-up) + I-20 stale running-agent self-heal E2E.
DAVE_ARCH="$(run dave-laptop uname -m | tr -d '\r')"
case "$DAVE_ARCH" in x86_64|amd64) DAVE_GOARCH=amd64 ;; aarch64|arm64) DAVE_GOARCH=arm64 ;; *) DAVE_GOARCH=amd64 ;; esac
mkdir -p "$WORK/ver-bins"
if [ -f "$SRC/prebuilt/test-bins/hogman-old" ] && [ -f "$SRC/prebuilt/test-bins/hogman-new" ]; then
  install -m 0755 "$SRC/prebuilt/test-bins/hogman-old" "$WORK/ver-bins/hogman-old"
  install -m 0755 "$SRC/prebuilt/test-bins/hogman-new" "$WORK/ver-bins/hogman-new"
else
  docker run --rm -v "$REPO/core/join:/src:ro" -v "$WORK/ver-bins:/out" -w /src \
    -v hogman-gomod:/go/pkg/mod -v hogman-gocache:/root/.cache/go-build \
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH="$DAVE_GOARCH" -e GOFLAGS="-buildvcs=false -tags=ts_omit_peerapiserver" \
    golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 sh -c '
      set -e
      go build -trimpath -ldflags="-s -w -X main.version=2025.01.01-aaaaaaa" -o /out/hogman-old .
      go build -trimpath -ldflags="-s -w -X main.version=2099.01.01-bbbbbbb" -o /out/hogman-new .
    ' >/dev/null
fi
DAVE_CID="$(dc ps -q dave-laptop)"
docker cp "$WORK/ver-bins/hogman-old" "$DAVE_CID:/tmp/hogman-old"
docker cp "$WORK/ver-bins/hogman-new" "$DAVE_CID:/tmp/hogman-new"
run dave-laptop chmod 0755 /tmp/hogman-old /tmp/hogman-new

# I-20 E2E: on-disk binaries already match the release, a deleted pen returns
# HTTP 404 from the front door, and the live pen's running agent is still on an
# older (then-deleted) binary. `hogman update` must NOT say "already up to date";
# it must skip the 404 pen's 60s wait and restart the live pen onto bin/hogman.
run dave-laptop sh -c '
  cp /tmp/hogman-old /tmp/hogman-stale-deleted && chmod 0755 /tmp/hogman-stale-deleted
  pid="$(cat "/root/.config/hogman/'"$ZONE"'/agent.pid" 2>/dev/null || true)"
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  sleep 1
  nohup /tmp/hogman-stale-deleted agent "/root/.config/hogman/'"$ZONE"'" >/root/.config/hogman/'"$ZONE"'/agent.log 2>&1 </dev/null &
  mkdir -p /root/.config/hogman/aaa-gone.example.test
  printf "{\"zone\":\"aaa-gone.example.test\",\"login_server\":\"https://dave-server:8443/gone\",\"dns_server\":\"100.64.0.1\",\"hostname\":\"gone\",\"proxy_addr\":\"127.0.0.1:19998\"}\n" > /root/.config/hogman/aaa-gone.example.test/config.json
  printf "0\n" > /root/.config/hogman/aaa-gone.example.test/.updating
  nohup /tmp/hogman-old agent /root/.config/hogman/aaa-gone.example.test >/root/.config/hogman/aaa-gone.example.test/agent.log 2>&1 </dev/null &
'
retry 20 run dave-laptop sh -c 'test -s /root/.config/hogman/aaa-gone.example.test/agent.pid && kill -0 "$(cat /root/.config/hogman/aaa-gone.example.test/agent.pid)" 2>/dev/null'
retry 20 alice_via
run dave-laptop rm -f /tmp/hogman-stale-deleted
STALE_LIVE_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
t0="$(date +%s)"
out="$(run dave-laptop sh -c 'HOGMAN_RELEASE_BASE="https://dave-server:8443" "/dl/hogman-$(uname -s)-$(uname -m)" --no-open update' 2>&1)"; rc=$?
t_i20=$(( $(date +%s) - t0 ))
check "I-20: update with 404 deleted pen + stale live agent does not say already up to date (exit $rc, ${t_i20}s)" bash -c 'test "$1" != 0 && ! grep -q "already up to date" <<<"$2" && grep -q "aaa-gone.example.test" <<<"$2"' _ "$rc" "$out"
check "... skipped 60s wait on HTTP 404 deleted pen (${t_i20}s < 45s)" test "$t_i20" -lt 45
HEALED_LIVE_PID="$(run dave-laptop cat "/root/.config/hogman/$ZONE/agent.pid" 2>/dev/null | tr -d '\r')"
check "... restarted live pen off deleted old binary onto canonical bin/hogman ($STALE_LIVE_PID -> $HEALED_LIVE_PID)" bash -c \
  'test -n "$1" && test -n "$2" && test "$1" != "$2"' _ "$STALE_LIVE_PID" "$HEALED_LIVE_PID"
check "... live pen agent now runs /root/.config/hogman/bin/hogman" run dave-laptop sh -c 'test "$(readlink -f "/proc/$1/exe" 2>/dev/null)" = "/root/.config/hogman/bin/hogman"' _ "$HEALED_LIVE_PID"
check "... and healed live pen still loads alice.$ZONE" retry 20 alice_via
run dave-laptop sh -c 'pid="$(cat /root/.config/hogman/aaa-gone.example.test/agent.pid 2>/dev/null || true)"; [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; rm -rf /root/.config/hogman/aaa-gone.example.test'
out="$(run dave-laptop sh -c 'HOGMAN_RELEASE_BASE="https://dave-server:8443" "/dl/hogman-$(uname -s)-$(uname -m)" --no-open update' 2>&1)"; rc=$?
check "... follow-up update with healthy current agent reports already up to date (exit $rc)" bash -c 'test "$1" = 0 && grep -q "already up to date" <<<"$2"' _ "$rc" "$out"
run dave-laptop sh -c 'rm -f /usr/local/share/ca-certificates/rel-ca.crt && update-ca-certificates --fresh >/dev/null 2>&1'

run dave-laptop sh -c 'cp /tmp/hogman-old /root/.config/hogman/bin/hogman.tmp && mv -f /root/.config/hogman/bin/hogman.tmp /root/.config/hogman/bin/hogman'
out="$(run dave-laptop /tmp/hogman-new --no-open "$DAVE_LINK" 2>&1)"; rc=$?
check "newer-dated client upgrades older shared binary (exit $rc)" test "$rc" = 0
check "... shared binary now reports 2099.01.01-bbbbbbb" match '2099\.01\.01-bbbbbbb' run dave-laptop /root/.config/hogman/bin/hogman --version
NEW_BIN_SUM="$(run dave-laptop sha256sum /root/.config/hogman/bin/hogman | awk '{print $1}')"
out="$(run dave-laptop /tmp/hogman-old --no-open "$DAVE_LINK" 2>&1)"; rc=$?
check "older-dated client does not downgrade newer shared binary (exit $rc)" bash -c 'test "$1" = 0 && grep -q "keeping newer shared binary" <<<"$2"' _ "$rc" "$out"
check "... shared binary version stays 2099.01.01-bbbbbbb" match '2099\.01\.01-bbbbbbb' run dave-laptop /root/.config/hogman/bin/hogman --version
check "... shared binary hash is unchanged" test "$(run dave-laptop sha256sum /root/.config/hogman/bin/hogman | awk '{print $1}')" = "$NEW_BIN_SUM"
run dave-laptop sh -c 'cp "/dl/hogman-$(uname -s)-$(uname -m)" /root/.config/hogman/bin/hogman.tmp && mv -f /root/.config/hogman/bin/hogman.tmp /root/.config/hogman/bin/hogman && rm -f /tmp/hogman-old /tmp/hogman-new'

out="$(join_tool dave-laptop leave "$DAVE_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "leave works (exit $rc)" grep -q "Left $ZONE" <<<"$out"
check "... and removed dave's laptop from his devices" grep -q "removed this computer from your devices" <<<"$out"
dave_laptop_gone() { local out; out="$($H device list)" || return 1; [ -z "$(awk '$2 == "dave" && $4 == "dave-laptop"' <<<"$out")" ]; }
check "... so it's no longer listed" retry 10 dave_laptop_gone
gone() { ! run dave-laptop test -e "/root/.config/hogman/$ZONE"; }
check "leave removed the connection and its settings" gone
proxy_closed() { ! run dave-laptop curl -s -m3 -o /dev/null "http://$PROXY/status"; }
check "the proxy is no longer running" retry 10 proxy_closed

