# Phase 2: Initial device enrollment, billing grace, server shares, naming, and public certs.

step "Devices join; the registrar recognises them"
# A device added straight through Headscale, around the registrar.
STRAY_KEY="$($H headscale preauthkeys create --tags tag:server --expiration 1h --output json | jq -r .key)"
export ALICE_LAPTOP_KEY BOB_LAPTOP_KEY STRAY_KEY
dc up -d alice-laptop bob-laptop stray-device alice-laptop-tools bob-tools stray-tools
for d in alice-laptop bob-laptop stray-device; do retry 90 has_ip $d; done
ALICE_LAPTOP_IP="$(ip_of alice-laptop)"; BOB_LAPTOP_IP="$(ip_of bob-laptop)"; STRAY_IP="$(ip_of stray-device)"
both_laptops() {
  local out
  out="$($H device list)" || return 1
  grep -q 'alice.*personal' <<<"$out" && grep -q 'bob.*personal' <<<"$out"
}
check "alice's and bob's laptops are recorded as theirs" retry 20 both_laptops
retry 30 api alice-laptop-tools GET /api/me
me="$(api alice-laptop-tools GET /api/me)"
check "the portal knows alice from her mesh address (alice, admin)" \
  test "$(jq -r '.member.handle + "/" + .member.role' <<<"$me")" = alice/admin
me="$(api bob-tools GET /api/me)"
check "... and bob from his (bob, member)" test "$(jq -r '.member.handle + "/" + .member.role' <<<"$me")" = bob/member

# D-35 grace-period banner + in-pen signed renewal token (owners/admins only).
printf '{"pen":"bobo","state":"grace","grace_until":"2027-12-24T00:00:00Z","renew_url":"https://get.example.com"}\n' \
  > "$WORK/data/registrar/billing-status.json"
chmod 0644 "$WORK/data/registrar/billing-status.json"
me_grace_alice="$(api alice-laptop-tools GET /api/me)"
me_grace_bob="$(api bob-tools GET /api/me)"
check "alice (admin) sees grace status with can_renew=true in /api/me" \
  jq -e '.billing.state == "grace" and .billing.can_renew == true' <<<"$me_grace_alice"
check "bob (non-admin member) sees grace status without can_renew in /api/me" \
  jq -e '.billing.state == "grace" and (.billing.can_renew // false) == false' <<<"$me_grace_bob"
check "bob (non-admin) cannot mint a renewal token (403)" \
  expect 403 bob-tools POST /api/billing/renew-token '{}'
renew_tok="$(api alice-laptop-tools POST /api/billing/renew-token '{}')"
check "alice (admin) mints a signed fragment renewal URL" \
  jq -e '.url | startswith("https://get.example.com/#renew=")' <<<"$renew_tok"
# Verify registrar created a 0600 renew.key and that the minted token's HMAC matches it (host/broker compatibility).
renew_verify_hmac() {
  local tok payload sig key_hex expected
  [ "$(stat -c '%a' "$WORK/data/registrar/renew.key")" = "600" ] || return 1
  tok="$(jq -r '.url | split("#renew=")[1]' <<<"$renew_tok")"
  payload="${tok%%.*}"; sig="${tok#*.}"
  key_hex="$(tr -d ' \r\n' < "$WORK/data/registrar/renew.key")"
  expected="$(printf 'hogman-renew-v1:%s' "$payload" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  [ -n "$expected" ] && [ "$sig" = "$expected" ]
}
check "registrar wrote 0600 renew.key and minted token HMAC verifies against it" renew_verify_hmac
rm -f "$WORK/data/registrar/billing-status.json" "$WORK/data/registrar/renew.key"
me_clear="$(api bob-tools GET /api/me)"
check "removing billing-status.json clears /api/me billing field" \
  jq -e '.billing == null' <<<"$me_clear"

step "Alice adds a server and shares a site"
srv="$(api alice-laptop-tools POST /api/devices '{"kind":"server"}')"
ALICE_SERVER_KEY="$(jq -r .auth_key <<<"$srv")"
check "alice gets a server key from the portal" test -n "$ALICE_SERVER_KEY" -a "$ALICE_SERVER_KEY" != null
check "the device link carries no fingerprint" bash -c '! grep -q "fp=" <<<"$1"' _ "$(jq -r .join_link <<<"$srv")"
check "the device link comes with a QR code drawn inside the pen" grep -q '^<svg ' <<<"$(jq -r .join_qr_svg <<<"$srv")"
portal_has_ui() {
  local body
  body="$(run alice-laptop-tools curl -sf -m5 --cacert $ROOT "https://home.$ZONE/")" || return 1
  grep -q 'id="add-personal"' <<<"$body"
}
check "the portal offers 'Add a device'" portal_has_ui
portal_hdrs="$(run alice-laptop-tools curl -sI -m5 --cacert $ROOT "https://home.$ZONE/" | tr -d '\r')"
check "the portal sets anti-framing headers" bash -c "grep -iq '^x-frame-options: DENY' <<<\"\$1\" && grep -iq \"^content-security-policy:.*frame-ancestors 'none'\" <<<\"\$1\"" _ "$portal_hdrs"
portal_assets_ok() {
  run alice-laptop-tools curl -sf -m5 --cacert $ROOT "https://home.$ZONE/portal.js" >/dev/null &&
    run alice-laptop-tools curl -sf -m5 --cacert $ROOT "https://home.$ZONE/js/api.js" >/dev/null &&
    run alice-laptop-tools curl -sf -m5 --cacert $ROOT "https://home.$ZONE/tokens.css" >/dev/null &&
    run alice-laptop-tools curl -sf -m5 --cacert $ROOT "https://home.$ZONE/base.css" >/dev/null &&
    run alice-laptop-tools curl -sf -m5 --cacert $ROOT "https://home.$ZONE/portal.css" >/dev/null
}
check "portal external JS/CSS load" portal_assets_ok
export ALICE_SERVER_KEY
dc up -d alice-server alice-tools
retry 90 has_ip alice-server; ALICE_SERVER_IP="$(ip_of alice-server)"
docker exec -d "$(dc ps -q alice-tools)" sh -c 'while true; do nc -l -p 443 >/dev/null 2>&1 || nc -l 443 >/dev/null 2>&1; done'
docker exec -d "$(dc ps -q alice-tools)" sh -c 'while true; do nc -l -p 2222 >/dev/null 2>&1 || nc -l 2222 >/dev/null 2>&1; done'
check "her server is recorded as hers" retry 20 match 'alice.*server' $H device list
SERVER_ID="$(api alice-laptop-tools GET /api/me | jq -r '.devices[] | select(.kind=="server") | .id')"
echo "  core=$CORE_MESH_IP alice-laptop=$ALICE_LAPTOP_IP bob-laptop=$BOB_LAPTOP_IP alice-server=$ALICE_SERVER_IP (#$SERVER_ID) stray=$STRAY_IP"
LAPTOP_ID="$(api alice-laptop-tools GET /api/me | jq -r '.devices[] | select(.kind=="personal") | .id')"
check "a name can't point at a personal device"  expect 400 alice-laptop-tools POST /api/names "{\"name\":\"srv\",\"device_id\":$LAPTOP_ID}"
check "a sub-name needs its parent claimed first" expect 403 alice-laptop-tools POST /api/names "{\"name\":\"sub.srv\",\"device_id\":$SERVER_ID}"
check "alice claims srv.$ZONE"      expect 201 alice-laptop-tools POST /api/names "{\"name\":\"srv\",\"device_id\":$SERVER_ID}"
check "alice claims sub.srv.$ZONE" expect 201 alice-laptop-tools POST /api/names "{\"name\":\"sub.srv\",\"device_id\":$SERVER_ID}"
check "reserved names are refused"    expect 403 alice-laptop-tools POST /api/names "{\"name\":\"home\",\"device_id\":$SERVER_ID}"
check "bob can't take srv"          expect 409 bob-tools POST /api/names "{\"name\":\"srv\",\"device_id\":$SERVER_ID}"
check "bob can't point a name at alice's server" expect 400 bob-tools POST /api/names "{\"name\":\"bobsite\",\"device_id\":$SERVER_ID}"

srv_share="$(api alice-laptop-tools POST /api/devices '{"kind":"server"}')"
ALICE_SHARE_LINK="$(jq -r .join_link <<<"$srv_share")"
dc up -d alice-share
retry 20 run alice-share test -s /etc/ssl/certs/ca-certificates.crt
run alice-share sh -c 'mkdir -p /tmp/www && echo "hello from alice.'"$ZONE"'" > /tmp/www/index.html'
out="$(run alice-share sh -c '"/dl/hogman-$(uname -s)-$(uname -m)" --no-open share alice /tmp/www "$1" --background' _ "$ALICE_SHARE_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "alice shares https://alice.$ZONE with hogman share (exit $rc)" grep -q "https://alice.$ZONE is up" <<<"$out"

step "Naming"
check "bob resolves srv.$ZONE to alice's server" retry 30 resolves_to srv.$ZONE "$ALICE_SERVER_IP"
check "bob resolves alice.$ZONE to alice's share" retry 30 resolves_any alice.$ZONE
check "bob resolves home.$ZONE to the core node"   resolves_to home.$ZONE "$CORE_MESH_IP"
check "ca.$ZONE has no DNS record"                 resolves_none ca.$ZONE
dns_aaaa_nodata() {
  local name="$1" out
  out="$(run bob-tools dig "@$CORE_MESH_IP" AAAA "$name" | tr -d '\r')" || return 1
  grep -q 'status: NOERROR' <<<"$out" &&
    grep -q 'flags:.*aa' <<<"$out" &&
    grep -q 'ANSWER: 0,' <<<"$out" &&
    grep -q 'AUTHORITY: 1,' <<<"$out"
}
check "IPv4-only DNS: AAAA for home.$ZONE returns NOERROR NODATA" dns_aaaa_nodata "home.$ZONE"
check "IPv4-only DNS: AAAA for srv.$ZONE returns NOERROR NODATA"  dns_aaaa_nodata "srv.$ZONE"
check "IPv4-only DNS: AAAA for alice.$ZONE returns NOERROR NODATA" dns_aaaa_nodata "alice.$ZONE"
split_dns_v4_only() {
  local ns
  ns="$(awk '/split:/{flag=1; next} flag && /^  [^ ]/{exit} flag && /- /{print $2}' "$WORK/data/headscale/config/config.yaml")"
  [ "$ns" = "$CORE_MESH_IP" ] && ! grep -q ':' <<<"$ns"
}
check "Headscale split-DNS hands clients only core's IPv4 resolver" split_dns_v4_only
check "device names work (alice-server.nodes.$ZONE)" resolves_to alice-server.nodes.$ZONE "$ALICE_SERVER_IP"
check "ordinary names still resolve (example.com)" resolves_any example.com
check "the network's DNS refuses outside names (not an open resolver)" refused example.com
in_directory() { match "$1" api bob-tools GET /api/directory; }
check "the directory lists alice's server sub-name" in_directory "sub.srv.$ZONE"
check "the directory lists alice's shared site"     in_directory "alice.$ZONE"

step "Public HTTPS certificates (ACME DNS-01)"
check "there is no step-ca container"            not docker inspect "$COMPOSE_PROJECT_NAME-step-ca-1"
check "there is no private PKI directory"        test ! -e "$WORK/data/pki"
check "portal https://home.$ZONE answers"        retry 60 fetch home.$ZONE "You're in"
check "portal certificate verifies against test public CA" cert_verifies "home.$ZONE"
check "alice's site https://alice.$ZONE answers" retry 150 fetch alice.$ZONE "hello from alice.$ZONE"
check "alice's site certificate verifies against test public CA" cert_verifies "alice.$ZONE"

