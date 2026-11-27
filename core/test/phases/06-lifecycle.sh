# Phase 6: Member suspend/resume, renew-only wake, and member kick.

step "Suspend and resume"
check "alice (admin) cannot suspend the owner" expect 403 alice-laptop-tools POST /api/admin/members/root/suspend
$H member suspend bob "testing" >/dev/null
timed t 30 not fetch alice.$ZONE "hello"
check "suspended bob loses access (${t}s)" not fetch alice.$ZONE "hello"
check "suspended bob can't reach the portal" not api_blocked bob-tools GET /api/me
check "his device is still registered" has_device bob-laptop
$H member resume bob >/dev/null
timed t 30 fetch alice.$ZONE "hello"
check "resumed bob has access again (${t}s)" fetch alice.$ZONE "hello"

step "Renew-only wake (I-7 Part 2)"
check "headscale template disables node key expiry for sleeping pens" awk '/^node:[[:space:]]*$/{f=1;next} f && /^  expiry: 0[[:space:]]*$/{ok=1;exit} f && /^[^[:space:]]/{f=0} END{exit !ok}' "$SRC/templates/headscale.yaml"
check "rendered headscale config disables node key expiry for sleeping pens" awk '/^node:[[:space:]]*$/{f=1;next} f && /^  expiry: 0[[:space:]]*$/{ok=1;exit} f && /^[^[:space:]]/{f=0} END{exit !ok}' "$WORK/data/headscale/config/config.yaml"
printf 'renew_only\n' > "$WORK/data/registrar/.renew-only"
cat > "$WORK/data/registrar/billing-status.json" <<'EOF'
{"pen":"bobo","state":"renew_only","wake_until":"2030-01-01T00:10:00Z","renew_url":"https://get.example.com"}
EOF
chmod 0644 "$WORK/data/registrar/.renew-only" "$WORK/data/registrar/billing-status.json"
$H sync >/dev/null
timed t 30 not fetch alice.$ZONE "hello"
check "during renew_only, regular member bob cannot reach alice's share (${t}s)" not fetch alice.$ZONE "hello"
check "during renew_only, regular member bob cannot reach the portal" not api_blocked bob-tools GET /api/me
check "during renew_only, admin alice still reaches /api/me with renew_only state" match '"state":"renew_only"' api alice-laptop-tools GET /api/me
check "during renew_only, admin alice can mint a renewal token" match 'https://get.example.com/#renew=' api alice-laptop-tools POST /api/billing/renew-token '{}'
check "during renew_only, admin alice gets 403 on /api/directory" expect 403 alice-laptop-tools GET /api/directory
r="$(redeem bad x)"
check "during renew_only, public /hogman/v1/redeem returns 403 (HTTP ${r##* })" test "${r##* }" = 403
# Simulate payment completion: clear .renew-only and billing-status.json and reconcile with ZERO container restarts.
rm -f "$WORK/data/registrar/.renew-only" "$WORK/data/registrar/billing-status.json" "$WORK/data/registrar/renew.key"
$H sync >/dev/null
timed t 30 fetch alice.$ZONE "hello"
check "after payment clears renew_only (no restart), bob reaches alice's share again (${t}s)" fetch alice.$ZONE "hello"
check "... and admin alice reaches /api/directory again" api alice-laptop-tools GET /api/directory

step "Kick"
check "nobody can kick the owner" not $H member kick root
check "bob can load alice's site before the kick" fetch alice.$ZONE "hello"
t0="$(date +%s)"
kick_out="$($H member kick alice "test kick")"
echo "        $kick_out"
timed t 60 not fetch alice.$ZONE "hello"
check "bob can no longer reach alice's site (${t}s after the kick)" not fetch alice.$ZONE "hello"
check "alice.$ZONE no longer resolves" retry 20 resolves_none alice.$ZONE
check "all of alice's devices are gone from the mesh" no_device_of alice
check "alice's laptop can no longer reach the portal" retry 30 not port_open alice-laptop-tools "$CORE_MESH_IP" 443
check "alice's server can no longer reach anyone" retry 30 not port_open alice-tools "$CORE_MESH_IP" 443
check "her name is held: bob can't claim alice" expect 409 bob-tools POST /api/names '{"name":"alice","device_id":1}'
check "the kick is in the audit log" match 'member.kick.*alice' $H audit
match 'member.kick.*alice' $H audit || { $H audit | tail -8; dc logs --tail 20 registrar 2>&1 | grep -i audit; } | sed 's/^/        audit| /'
check "bob is unaffected" fetch home.$ZONE "You're in"

