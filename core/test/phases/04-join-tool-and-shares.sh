# Phase 4: Fresh join tool, pasted zsh/bash join commands, side-by-side shares, and private names.

step "The join tool, on a fresh computer"
dc up -d carol-laptop carol-desktop
retry 30 run carol-laptop tailscale status --json
join_tool() {  # join_tool <container> <args...>
  local c="$1"; shift
  run "$c" sh -c '"/dl/hogman-$(uname -s)-$(uname -m)" --no-open "$@"' _ "$@"
}
CAROL_LINK="$($H invite create --note carol | awk '/^link:/ {print $2}')"
check "the invite link carries no fingerprint" bash -c '! grep -q "fp=" <<<"$1"' _ "$CAROL_LINK"
BAD_LINK="${CAROL_LINK}&fp=$(printf '%064d' 0)"
out="$(join_tool carol-laptop --handle carol "$BAD_LINK" 2>&1)"
check "a legacy link with fp= is refused" grep -q 'older release' <<<"$out"
check "... before the invite is used" match 'open.*carol' $H invite list
out="$(join_tool carol-laptop --handle carol --hostname carol-laptop "$CAROL_LINK" 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "the join tool succeeds (exit $rc)" test $rc = 0
check "it reports carol is in" grep -q "You're in. You are carol on $ZONE" <<<"$out"
check "with Tailscale installed, it still joins the usual HTTPS-only way" grep -q "own small connection" <<<"$out"
ts_untouched() { [ "$(run carol-laptop tailscale status --json | jq -r .BackendState)" != Running ]; }
check "... and leaves this computer's Tailscale alone" ts_untouched
check "nothing was added to the system trust store" \
  no_match hogman run carol-laptop ls /usr/local/share/ca-certificates
check "the registrar recorded carol's laptop" retry 10 match 'carol.*carol-laptop' $H device list
check "no account recovery: the server won't make a device link for carol, who has joined" not $H device key carol personal
check "a new member can still be given a first device link from the server" $H member add erin
DEVICE_LINK="$($H device key erin personal | awk '/^link:/ {print $2}')"
out="$(join_tool carol-desktop --tailscale --hostname carol-desktop "$DEVICE_LINK" 2>&1)"; rc=$?
check "joining through the Tailscale app is no longer offered (--tailscale refused)" test $rc != 0
check "... and the device link is still unused" no_match 'erin.*carol-desktop' $H device list
out="$(join_tool carol-desktop --hostname carol-desktop "$DEVICE_LINK" 2>&1)"; rc=$?
check "a device link joins that member (exit $rc)" grep -q "You're in. You are erin" <<<"$out"
check "the registrar recorded it as erin's" retry 10 match 'erin.*carol-desktop' $H device list
out="$(join_tool carol-desktop leave "$DEVICE_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "leave works (exit $rc)" grep -q "Left $ZONE" <<<"$out"
conn_gone() { ! run carol-desktop test -e "/root/.config/hogman/$ZONE"; }
check "leave removed the pen's connection and its settings" conn_gone

step "The join page's own command, pasted into a terminal (zsh and bash)"
# Run the exact text join.js shows people, the way they paste it: zsh is the
# default shell in macOS Terminal, bash on most Linux. (Before #191, zsh
# stopped at an unquoted --proto =https and nothing here noticed.) The only
# additions are the flags a terminal without a keyboard needs.
dc up -d zsh-laptop bash-laptop
for c in zsh-laptop bash-laptop; do retry 20 run "$c" test -s /etc/ssl/certs/ca-certificates.crt; done
paste_join() {  # paste_join <container> <shell> <handle>
  local c="$1" shell="$2" handle="$3" link cmd
  link="$($H invite create --note "$handle (pasted join command)" | awk '/^link:/ {print $2}')"
  cmd="$("$SRC/test/render-join-cmd.sh" "$PUBLIC_HOST" "$link") --no-open --handle $handle --hostname $c"
  run "$c" "$shell" -c "$cmd" 2>&1
}
pasted_portal_ok() {  # pasted_portal_ok <container> <handle>
  run "$1" sh -c 'p="$(jq -r .proxy_addr "$HOME/.config/hogman/$1/config.json")" &&
    curl -sf -m 10 --cacert "$2" -x "http://$p" "https://home.$1/api/me"' _ "$ZONE" "$ROOT" | jq -e --arg h "$2" '.member.handle == $h' >/dev/null
}
for pair in "zsh-laptop zsh zara" "bash-laptop bash bart"; do
  set -- $pair
  out="$(paste_join "$1" "$2" "$3")"; rc=$?
  [ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
  check "pasted join command works under $2 (exit $rc)" grep -q "You're in. You are $3 on $ZONE" <<<"$out"
  check "... with no shell error (e.g. zsh's 'https not found')" bash -c '! grep -qE "not found|parse error|no matches found" <<<"$1"' _ "$out"
  check "... installed ~/hogman from the front door" run "$1" sh -c 'test -x "$HOME/hogman" && "$HOME/hogman" --version'
  check "... and $3 reaches the portal through the local proxy" retry 15 pasted_portal_ok "$1" "$3"
done
dc kill zsh-laptop bash-laptop >/dev/null 2>&1 || true
dc rm -f zsh-laptop bash-laptop >/dev/null 2>&1 || true

step "Side by side: a computer with no Tailscale at all"
dc up -d dave-laptop
retry 20 run dave-laptop test -s /etc/ssl/certs/ca-certificates.crt
DAVE_LINK="$($H invite create --note dave | awk '/^link:/ {print $2}')"
out="$(join_tool dave-laptop --handle dave --hostname dave-laptop "$DAVE_LINK" 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "the join tool succeeds without Tailscale installed (exit $rc)" test $rc = 0
check "it joined the usual way (side by side)" grep -q "joining side by side" <<<"$out"
check "it reports dave is in" grep -q "You're in. You are dave on $ZONE" <<<"$out"
check "nothing was added to dave's system trust store" \
  no_match hogman run dave-laptop ls /usr/local/share/ca-certificates
check "the registrar recorded dave's laptop" retry 10 match 'dave.*dave-laptop' $H device list
PROXY="$(run dave-laptop sh -c 'grep -o "127.0.0.1:[0-9]*" "/root/.config/hogman/'"$ZONE"'/config.json" | head -1' | tr -d '\r')"
via_pen()   { run dave-laptop curl -sf -m10 --cacert $ROOT --proxy "http://$PROXY" "$1"; }
alice_via() { match "hello from alice.$ZONE" via_pen "https://alice.$ZONE"; }
check "dave loads alice's site through the pen, trusted by the system store" retry 20 alice_via
outside_code() { run dave-laptop curl -s -m10 -o /dev/null -w '%{http_code}' --proxy "http://$PROXY" http://example.com | tr -d '\r'; }
check "the pen's proxy refuses anything outside the pen (HTTP $(outside_code))" test "$(outside_code)" = 403
pac_ok() { match "dnsDomainIs(host, \".$ZONE\")" run dave-laptop curl -sf "http://$PROXY/proxy.pac"; }
check "its rules file sends only pen names through the pen" pac_ok
no_tun() {
  local out
  out="$(run dave-laptop ip -o link)" || return 1
  ! grep -qi tailscale <<<"$out"
}
check "no network interface was added to the computer" no_tun
direct_ok() { run dave-laptop curl -sf -m10 -o /dev/null https://example.com; }
check "dave's ordinary internet is untouched" direct_ok

# One command puts a folder on the pen, from a laptop that only joined side by side.
run dave-laptop sh -c 'mkdir -p /tmp/notes && echo "notes from dave" > /tmp/notes/index.html'
out="$(join_tool dave-laptop share notes /tmp/notes --note "Dave's test notes" --background 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "share puts a folder on the pen in one command (exit $rc)" grep -q "https://notes.$ZONE is up" <<<"$out"
notes_via() { match "notes from dave" via_pen "https://notes.$ZONE"; }
check "dave's laptop loads https://notes.$ZONE" retry 20 notes_via
check "bob loads it too (with Tailscale)" retry 30 fetch notes.$ZONE "notes from dave"
check "the name is dave's" match 'notes.*dave' $H name list
share_dir_note() { api bob-tools GET /api/directory | jq -e --arg n "notes.$ZONE" --arg desc "Dave's test notes" 'any(.[]; .name == $n and .member == "dave" and .note == $desc)'; }
check "the directory shows the share's note" share_dir_note
notes_listed() { match "notes.*running" join_tool dave-laptop share list; }
check "share list shows it running" notes_listed
only_proxy_tcp_listen() {
  # I-27: with ts_omit_peerapiserver, hogman agent + share must ONLY listen on
  # the agent's 127.0.0.1:<proxyPort> socket — zero wildcard or extra TCP listeners.
  # Ignore Docker's built-in container DNS listener on 127.0.0.11 (0B00007F).
  local want_hex
  want_hex="$(printf '0100007F:%04X' "${PROXY##*:}")"
  run dave-laptop sh -c '
    want="'"$want_hex"'"
    v4="$(awk "NR>1 && \$4==\"0A\" && \$2 !~ /^0B00007F:/ { print \$2 }" /proc/net/tcp 2>/dev/null || true)"
    v6="$(awk "NR>1 && \$4==\"0A\" { print \$2 }" /proc/net/tcp6 2>/dev/null || true)"
    if [ "$v4" != "$want" ] || [ -n "$v6" ]; then
      echo "unexpected TCP listeners on dave-laptop: want v4=[$want] v6=[], got v4=[$v4] v6=[$v6]" >&2
      exit 1
    fi
  '
}
check "hogman agent and share only open 127.0.0.1:<proxy> TCP listener (I-27)" only_proxy_tcp_listen
DAVE_LAPTOP_IP="$(ip_of dave-laptop)"
check "bob's laptop cannot reach dave's tsnet laptop over the mesh (443)" not port_open bob-tools "$DAVE_LAPTOP_IP" 443
NOTES_IP="$(ip_of notes)"
check "alice's server cannot reach dave's notes share on 443 (server isolation)" not port_open alice-tools "$NOTES_IP" 443
notes_device() {
  local out
  out="$($H device list)" || return 1
  awk '$2 == "dave" && $4 == "notes" { found=1 } END { exit !found }' <<<"$out"
}
check "it is a server of dave's, called notes" notes_device
out="$(join_tool dave-laptop share notes /tmp/notes 2>&1)"
check "sharing the same name twice is refused while it runs" grep -q "already being shared" <<<"$out"
out="$(join_tool dave-laptop share stop notes 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "share stop takes it down (exit $rc)" grep -q "notes.$ZONE is down" <<<"$out"
check "... and gives the name back" no_match notes $H name list
check "... and removes its server" retry 10 not notes_device
check "bob can't load it any more" retry 15 not fetch notes.$ZONE "notes from dave"

# Server links only put something in the pen with share (D-11): joining a
# whole computer with one is refused before the link is used, and the same
# link then works with share.
dc up -d dave-server dave-server-tools
retry 20 run dave-server test -s /etc/ssl/certs/ca-certificates.crt

# Second-device link minted from an existing member's portal (I-21): verifies
# device-link enrollment survives the transient ACL sync window, actually
# reaches https://home.$ZONE/api/me through its own local proxy, and loses
# access cleanly when removed via DELETE /api/devices/:id.
DAVE_DEV_LINK="$(run dave-laptop curl -sf -m10 --cacert "$ROOT" --proxy "http://$PROXY" \
  -H "Origin: https://home.$ZONE" -H 'Content-Type: application/json' \
  -d '{"kind":"personal"}' "https://home.$ZONE/api/devices" | jq -r '.join_link')"
check "dave mints a second-device link from his portal" bash -c '[[ "$1" == https://*/join#k=* ]]' _ "$DAVE_DEV_LINK"
out="$(join_tool dave-server --hostname dave-second "$DAVE_DEV_LINK" 2>&1)"; rc=$?
[ $rc = 0 ] || echo "$out" | sed 's/^/        | /'
check "second device joins via portal device link (exit $rc)" grep -q "You're in. You are dave on $ZONE" <<<"$out"
DAVE2_PROXY="$(run dave-server sh -c 'cat "${XDG_CONFIG_HOME:-$HOME/.config}/hogman/'"$ZONE"'/config.json"' | jq -r '.proxy_addr' | tr -d '\r')"
dave2_me() {
  run dave-server-tools curl -sf -m10 --cacert "$ROOT" --proxy "http://$DAVE2_PROXY" "https://home.$ZONE/api/me" \
    | jq -e '.member.handle == "dave"' >/dev/null
}
check "... second device reaches /api/me through its proxy" retry 10 dave2_me
DAVE2_ID="$(run dave-server-tools curl -sf -m10 --cacert "$ROOT" --proxy "http://$DAVE2_PROXY" "https://home.$ZONE/api/me" | jq -r '.this_device.id')"
check "... dave removes his second device via DELETE /api/devices/$DAVE2_ID" run dave-laptop curl -sf -m10 --cacert "$ROOT" --proxy "http://$PROXY" \
  -X DELETE -H "Origin: https://home.$ZONE" "https://home.$ZONE/api/devices/$DAVE2_ID"
dave2_blocked() {
  ! run dave-server-tools curl -sf -m5 --cacert "$ROOT" --proxy "http://$DAVE2_PROXY" "https://home.$ZONE/api/me"
}
check "... removed second device loses access to home.$ZONE" retry 15 dave2_blocked
check "... while dave's first laptop still reaches home.$ZONE" run dave-laptop curl -sf -m10 --cacert "$ROOT" --proxy "http://$PROXY" "https://home.$ZONE/api/me"
join_tool dave-server leave --force "$ZONE" >/dev/null 2>&1 || true

SHARE_LINK="$($H device key dave server | awk '/^link:/ {print $2}')"
check "a server link is marked for share" grep -q 'for=share' <<<"$SHARE_LINK"
check "the server link carries no fingerprint" bash -c '! grep -q "fp=" <<<"$1"' _ "$SHARE_LINK"
out="$(join_tool dave-server --hostname dave-server "$SHARE_LINK" 2>&1)"; rc=$?
check "joining a whole computer with a server link is refused (exit $rc)" test $rc != 0
check "... and says to use it with share" grep -q "hogman share" <<<"$out"
no_dave_server() { local out; out="$($H device list)" || return 1; [ -z "$(awk '$2 == "dave" && $4 == "dave-server"' <<<"$out")" ]; }
check "... and adds no device" no_dave_server

# A computer that isn't on the pen at all: one server link, one command.
docker exec -d "$(dc ps -q dave-server)" sh -c 'mkdir -p /tmp/www && echo "app from a server link" > /tmp/www/index.html && caddy file-server --listen 127.0.0.1:8080 --root /tmp/www >/tmp/fs.log 2>&1'
out="$(join_tool dave-server share app 8080 "$SHARE_LINK" 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
check "a server link plus one command shares a port (exit $rc)" grep -q "https://app.$ZONE is up" <<<"$out"
check "members load https://app.$ZONE" retry 30 fetch app.$ZONE "app from a server link"
out="$(join_tool dave-server share stop app 2>&1)"; rc=$?
check "and it stops cleanly (exit $rc)" grep -q "app.$ZONE is down" <<<"$out"

# Opt-in private site name (I-17 Part 2): random 12-char hostname in DNS/cert,
# friendly --note stays inside the pen, discoverable via /api/directory both
# through a local hogman proxy (no browser) and from a tag:server device, and
# permanently retired on stop (D-21).
step "Private site names (--private-name) and headless /api/directory discovery"
PRIV_LINK="$($H device key dave server | awk '/^link:/ {print $2}')"
out="$(join_tool dave-server share --private-name 8080 "$PRIV_LINK" --note "Cooler 3 - North Bay" --background 2>&1)"; rc=$?
echo "$out" | sed 's/^/        | /'
PRIV_FQDN="$(grep -oE "https://[a-z][a-z0-9]{11}\.${ZONE}" <<<"$out" | head -n 1 | sed 's|^https://||')"
PRIV_LABEL="${PRIV_FQDN%.$ZONE}"
check "share --private-name brings up a random 12-char hostname (exit $rc, label=$PRIV_LABEL)" \
  bash -c 'test "$1" = 0 && [[ "$2" =~ ^[a-z][a-z0-9]{11}$ ]]' _ "$rc" "$PRIV_LABEL"
check "private-name output prints honest certificate-log notice" grep -q "only this random name appears in certificate logs" <<<"$out"
DAVE_STATUS_PORT="$(join_tool dave-laptop status --json | jq -r --arg z "$ZONE" '.pens[] | select(.zone == $z) | .port')"
check "hogman status --json reports the local proxy port ($DAVE_STATUS_PORT)" test "127.0.0.1:$DAVE_STATUS_PORT" = "$PROXY"
priv_dir_via_proxy() {
  run dave-laptop curl -sf -m10 --cacert $ROOT --proxy "http://127.0.0.1:$DAVE_STATUS_PORT" "https://home.$ZONE/api/directory" \
    | jq -e --arg n "$PRIV_FQDN" 'any(.[]; .name == $n and .member == "dave" and .note == "Cooler 3 - North Bay" and .private == true and .online == true)'
}
check "headless client discovers private site via /api/directory through local proxy" retry 20 priv_dir_via_proxy
priv_dir_via_server() {
  api alice-tools GET /api/directory \
    | jq -e --arg n "$PRIV_FQDN" 'any(.[]; .name == $n and .member == "dave" and .note == "Cooler 3 - North Bay" and .private == true)'
}
check "tag:server device discovers private site via /api/directory without a browser" retry 20 priv_dir_via_server
priv_via_proxy() { match "app from a server link" via_pen "https://$PRIV_FQDN"; }
check "members load the private-name site over HTTPS" retry 30 priv_via_proxy
priv_listed() {
  join_tool dave-server share list --json \
    | jq -e --arg n "$PRIV_LABEL" 'any(.[]; .name == $n and .private == true and .note == "Cooler 3 - North Bay" and .running == true)'
}
check "share list --json shows private=true and note" priv_listed
out="$(join_tool dave-server share stop "$PRIV_LABEL" 2>&1)"; rc=$?
check "share stop retires the private name (exit $rc)" grep -q "private name is retired" <<<"$out"
check "retired private label stays retired in registrar (D-21)" match "${PRIV_LABEL}.*retired" $H name list

