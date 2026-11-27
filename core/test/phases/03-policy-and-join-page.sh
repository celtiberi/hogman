# Phase 3: Default-deny access policy, stray device isolation, relay, and join page / downloads.

step "Default-deny access policy"
# HTTPS only (D-11): members reach servers on 443 and nothing else.
check "bob's laptop can reach alice's server on 443"     retry 20 port_open bob-tools "$ALICE_SERVER_IP" 443
# Run independent read-only negative connectivity probes in parallel so we keep
# full 3s nc timeouts without burning 18s serially.
_pd="$WORK/.probes"; rm -rf "$_pd"; mkdir -p "$_pd"
CORE_MESH_IPV6="$($H headscale nodes list --output json | jq -r --arg ip "$CORE_MESH_IP" '.[] | (.ip_addresses // .ipAddresses // []) | select(index($ip) != null) | .[] | select(contains(":"))' | tr -d '\r' | head -n1)"
ALICE_SHARE_IP=""
for _ in $(seq 10); do
  ALICE_SHARE_IP="$(run bob-tools dig +short "alice.$ZONE" | tr -d '\r' | grep -E '^[0-9.]+$' | head -n1)"
  [ -n "$ALICE_SHARE_IP" ] && break
  sleep 1
done
ALICE_SHARE_IPV6="$($H headscale nodes list --output json | jq -r --arg ip "$ALICE_SHARE_IP" '.[] | (.ip_addresses // .ipAddresses // []) | select(index($ip) != null) | .[] | select(contains(":"))' | tr -d '\r' | head -n1)"
port_blocked_v6() {
  local c="$1" ip="$2" port="$3" route out rc
  if [ -z "$ip" ]; then
    echo "missing target IPv6 address"
    return 1
  fi
  route="$(run "$c" ip -6 route get "$ip" 2>&1)" || { echo "no IPv6 route to $ip: $route"; return 1; }
  if ! grep -q 'tailscale0' <<<"$route"; then
    echo "IPv6 route for $ip does not use tailscale0: $route"
    return 1
  fi
  out="$(run "$c" nc -6 -v -z -w3 "$ip" "$port" 2>&1)"; rc=$?
  if [ "$rc" = 0 ]; then
    echo "unexpected IPv6 connection succeeded to [$ip]:$port: $out"
    return 1
  fi
  if grep -iqE 'unreachable|not supported|cannot assign|invalid' <<<"$out"; then
    echo "IPv6 probe failed before WireGuard ACLs: $out"
    return 1
  fi
  return 0
}
( not port_open bob-tools "$ALICE_SERVER_IP" 80   >"$_pd/p1.out" 2>&1; echo $? >"$_pd/p1.rc" ) &
( not port_open bob-tools "$ALICE_SERVER_IP" 2222 >"$_pd/p2.out" 2>&1; echo $? >"$_pd/p2.rc" ) &
( not port_open bob-tools "$CORE_MESH_IP" 9000    >"$_pd/p3.out" 2>&1; echo $? >"$_pd/p3.rc" ) &
( not port_open bob-tools "$ALICE_LAPTOP_IP" 443  >"$_pd/p4.out" 2>&1; echo $? >"$_pd/p4.rc" ) &
( not port_open alice-tools "$BOB_LAPTOP_IP" 443  >"$_pd/p5.out" 2>&1; echo $? >"$_pd/p5.rc" ) &
( not port_open bob-tools "$CORE_MESH_IP" 22      >"$_pd/p6.out" 2>&1; echo $? >"$_pd/p6.rc" ) &
( port_blocked_v6 bob-tools "$CORE_MESH_IPV6" 443   >"$_pd/p7.out" 2>&1; echo $? >"$_pd/p7.rc" ) &
( port_blocked_v6 bob-tools "$ALICE_SHARE_IPV6" 443 >"$_pd/p8.out" 2>&1; echo $? >"$_pd/p8.rc" ) &
wait
probe_ok() { local rc; rc="$(cat "$_pd/$1.rc" 2>/dev/null || echo 1)"; [ "$rc" = 0 ] || { cat "$_pd/$1.out" 2>/dev/null; return 1; }; }
check "... but not on 80"                                 probe_ok p1
check "... but on no other port (2222 is open there)"    probe_ok p2
# (Ping still answers: Tailscale's filter lets ICMP through between devices
# allowed any port. It can't carry data, so it isn't a way in.)
check "the server itself has 2222 open (so the above means something)" run alice-tools nc -z -w3 127.0.0.1 2222
check "bob's laptop cannot reach retired CA port 9000"     probe_ok p3
check "bob's laptop cannot reach alice's laptop"         probe_ok p4
check "alice's server cannot reach bob's laptop"         probe_ok p5
check "members cannot reach other ports on the core (22)" probe_ok p6
check "active Headscale policy contains no IPv6 addresses" no_match 'fd7a:' $H headscale policy get
check "mesh IPv6 is default-deny: bob cannot reach core over IPv6 :443"         probe_ok p7
check "mesh IPv6 is default-deny: bob cannot reach alice's share over IPv6 :443" probe_ok p8
check "bob can't use the admin API"   expect 403 bob-tools GET /api/admin/members
check "alice (admin) can"             expect 200 alice-laptop-tools GET /api/admin/members
page_invite() {  # an invite made from the home page comes with its link and QR code
  api alice-laptop-tools POST /api/invites '{"note":"from the page"}' \
    | jq -e --arg h "$PUBLIC_HOST" '(.url | startswith("https://\($h)/join#t=")) and (.qr_svg | startswith("<svg"))'
}
check "alice (admin) makes an invite from the home page" page_invite
invite_open()  { match 'open.*from the page' $H invite list; }
offers_keeper(){ api "$1" GET /api/me | jq -e '.can_invite and .is_admin'; }
offers_none()  { api "$1" GET /api/me | jq -e '(.can_invite or .is_admin) | not'; }
check "the ledger lists it as open"   invite_open
check "the home page offers alice the keeper controls" offers_keeper alice-laptop-tools
check "and offers bob neither"        offers_none bob-tools
check "the home page has the herd"    fetch "home.$ZONE" 'The herd'
check "the home page has the pen directory" fetch "home.$ZONE" 'Sites in this pen'
herd_finds_bob() {  # searched on the registrar, with his devices counted
  api alice-laptop-tools GET '/api/admin/herd?q=bo' | jq -e '.total >= 1 and any(.members[]; .handle == "bob" and .devices >= 1)'
}
check "alice finds bob in the herd, devices counted" herd_finds_bob
check "bob can't list the herd"       expect 403 bob-tools GET /api/admin/herd
check "alice's server can read /api/me"        expect 200 alice-tools GET /api/me
check "alice's server can read /api/directory" expect 200 alice-tools GET /api/directory
check "alice's server cannot use the admin API"   expect 403 alice-tools GET /api/admin/members
check "alice's server cannot issue device keys"   expect 403 alice-tools POST /api/devices '{"kind":"personal"}'
check "alice's server cannot claim names"         expect 403 alice-tools POST /api/names '{"name":"x","device_id":1}'
check "mesh API rejects text/plain CSRF attempts (415)" \
  test "$(api_raw_status alice-laptop-tools POST /api/devices -H 'Content-Type: text/plain' -d '{"kind":"personal"}')" = 415
check "mesh API rejects cross-origin requests (403)" \
  test "$(api_raw_status alice-laptop-tools POST /api/devices -H 'Content-Type: application/json' -H "Origin: https://alice.$ZONE" -d '{"kind":"personal"}')" = 403
check "mesh API rejects same-site browser requests (403)" \
  test "$(api_raw_status alice-laptop-tools POST /api/devices -H 'Content-Type: application/json' -H 'Sec-Fetch-Site: same-site' -d '{"kind":"personal"}')" = 403

step "A device that bypassed the registrar gets nothing"
check "it is not recorded as anyone's device" no_match stray-device $H device list
rm -rf "$_pd"; mkdir -p "$_pd"
( not port_open stray-tools "$CORE_MESH_IP" 443   >"$_pd/s1.out" 2>&1; echo $? >"$_pd/s1.rc" ) &
( not port_open stray-tools "$CORE_MESH_IP" 9000  >"$_pd/s2.out" 2>&1; echo $? >"$_pd/s2.rc" ) &
( not port_open stray-tools "$ALICE_SERVER_IP" 443 >"$_pd/s3.out" 2>&1; echo $? >"$_pd/s3.rc" ) &
( not can_ping bob-tools "$STRAY_IP"              >"$_pd/s4.out" 2>&1; echo $? >"$_pd/s4.rc" ) &
wait
check "it cannot reach the portal"     probe_ok s1
check "it cannot reach retired CA port 9000" probe_ok s2
check "it cannot reach alice's server" probe_ok s3
check "bob cannot reach it"            probe_ok s4

step "Relay"
relay="$(run bob-laptop tailscale ping -c 3 "$CORE_MESH_IP" 2>&1 | tr -d '\r')"
echo "$relay" | head -1 | sed 's/^/        /'
check "traffic with no direct path is carried by the network's own relay" grep -q 'DERP(hogman)' <<<"$relay"
regions="$(run bob-laptop tailscale debug derp-map 2>/dev/null | grep '"RegionCode"' | sort -u | tr -d ' \t\r')"
check "only our relay region is offered, none of Tailscale's" test "$regions" = '"RegionCode":"hogman",'

step "The join page and downloads"
from_internet() {  # from_internet <curl args...>
  docker run --rm --network "${COMPOSE_PROJECT_NAME}_outside" -v "$WORK/data/edge-trust:/t:ro" \
    nicolaka/netshoot:v0.14 curl -sf --cacert /t/root.crt "$@"
}
from_internet_status() {
  docker run --rm --network "${COMPOSE_PROJECT_NAME}_outside" -v "$WORK/data/edge-trust:/t:ro" \
    nicolaka/netshoot:v0.14 curl -s -o /dev/null -w '%{http_code}' --cacert /t/root.crt "$1" \
    | tr -d '\r' | tail -c 3
}
page_ok() {
  local html
  html="$(from_internet "https://$PUBLIC_HOST/join")" || return 1
  grep -q 'hogman' <<<"$html"
}
net_ok()   { from_internet "https://$PUBLIC_HOST/hogman/v1/network" | jq -e --arg z "$ZONE" '.zone == $z and .cert_mode == "public" and (.root_ca // "") == "" and (.root_fingerprint // "") == ""'; }
check "https://<host>/join serves the join page" page_ok
check "edge runs non-root ($HOGMAN_UID:$HOGMAN_GID)" bash -c 'test "$1" != 0 && test "$2" = "$1:$3"' _ "$HOGMAN_UID" "$(docker inspect -f '{{.Config.User}}' "$(dc ps -q edge)")" "$HOGMAN_GID"
check "registrar (portal + DNS + core mesh) runs non-root ($HOGMAN_UID:$HOGMAN_GID)" bash -c 'test "$1" != 0 && test "$2" = "$1:$3"' _ "$HOGMAN_UID" "$(docker inspect -f '{{.Config.User}}' "$(dc ps -q registrar)")" "$HOGMAN_GID"
check "core-mesh and portal containers are gone (I-15)" bash -c 'test -z "$1" && test -z "$2"' _ "$(dc ps -q core-mesh 2>/dev/null || true)" "$(dc ps -q portal 2>/dev/null || true)"
tcp_dns_ok() {
  local out
  out="$(run bob-tools dig +tcp +short "@$CORE_MESH_IP" "home.$ZONE" | tr -d '\r')" || return 1
  grep -qx -- "$CORE_MESH_IP" <<<"$out"
}
check "TCP :53 DNS resolves home.$ZONE over tsnet" tcp_dns_ok
xff_spoof_refused() {
  local code
  code="$(run bob-tools curl -s -m5 -o /dev/null -w '%{http_code}' --cacert "$ROOT" -H "X-Forwarded-For: $ALICE_LAPTOP_IP" "https://home.$ZONE/api/admin/members" | tr -d '\r')" || return 1
  test "$code" = 403
}
check "direct tsnet identity ignores spoofed X-Forwarded-For on /api/admin/members" xff_spoof_refused
join_hdrs="$(from_internet -sI "https://$PUBLIC_HOST/join" | tr -d '\r')"
check "the join page sets anti-framing headers and Origin-Agent-Cluster" bash -c "grep -iq '^x-frame-options: DENY' <<<\"\$1\" && grep -iq \"^content-security-policy:.*frame-ancestors 'none'\" <<<\"\$1\" && grep -iq '^origin-agent-cluster: ?1' <<<\"\$1\"" _ "$join_hdrs"
portal_hdrs="$(run bob-tools curl -sfI --cacert $ROOT "https://home.$ZONE/" | tr -d '\r')"
check "the portal page sets Origin-Agent-Cluster" grep -iq '^origin-agent-cluster: ?1' <<<"$portal_hdrs"
join_assets_ok() {
  from_internet "https://$PUBLIC_HOST/join/assets/join.js" >/dev/null &&
    from_internet "https://$PUBLIC_HOST/join/assets/commands.js" >/dev/null &&
    from_internet "https://$PUBLIC_HOST/join/assets/tokens.css" >/dev/null &&
    from_internet "https://$PUBLIC_HOST/join/assets/base.css" >/dev/null &&
    from_internet "https://$PUBLIC_HOST/join/assets/join.css" >/dev/null
}
check "join page external JS/CSS load" join_assets_ok
dl_hdrs="$(from_internet -sI "https://$PUBLIC_HOST/join/dl/SHA256SUMS" | tr -d '\r')"
check "/join/dl/ sets nosniff" grep -iq '^x-content-type-options: nosniff' <<<"$dl_hdrs"
check "edge allows Headscale /health" match '"pass"' from_internet "https://$PUBLIC_HOST/health"
check "edge allows Tailscale /key" match '"publicKey"' from_internet "https://$PUBLIC_HOST/key?v=138"
check "edge allows /generate_204" test "$(from_internet_status "https://$PUBLIC_HOST/generate_204")" = 204
check "edge blocks Headscale admin API (/api/v1/user -> 404)" test "$(from_internet_status "https://$PUBLIC_HOST/api/v1/user")" = 404
check "edge blocks Headscale Swagger UI (/swagger -> 404)" test "$(from_internet_status "https://$PUBLIC_HOST/swagger")" = 404
edge_blocked_routes_ok() {
  local p
  for p in / /version /apple /windows /register/test /auth/test /robots.txt; do
    [ "$(from_internet_status "https://$PUBLIC_HOST$p")" = 404 ] || return 1
  done
}
check "edge blocks Headscale root, register, auth, apple, windows, version (-> 404)" edge_blocked_routes_ok
sums="$(from_internet "https://$PUBLIC_HOST/join/dl/SHA256SUMS")"
check "the join tool is downloadable for 6 platforms" test "$(grep -c hogman <<<"$sums")" = 6
check "edge serves /start.ps1 as plain text" match 'Join a Hogman pen on Windows' from_internet "https://$PUBLIC_HOST/start.ps1"
check "the network info endpoint is public" net_ok

