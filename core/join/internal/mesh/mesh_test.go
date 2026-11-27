package mesh

import (
	"net/netip"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func TestResolvePenDNSIPAndEvaluateLiveNodeStatus(t *testing.T) {
	t.Parallel()
	k1 := key.NewNode().Public()
	k2 := key.NewNode().Public()
	k3 := key.NewNode().Public()
	st := &ipnstate.Status{
		BackendState: "Running",
		Self:         &ipnstate.PeerStatus{TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.10")}},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			k1: {TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.5")}, Online: true, Tags: &views.Slice[string]{}},
			k2: {TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.20")}, Online: true},
			k3: {TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")}, Online: true},
		},
	}
	infraTags := views.SliceOf([]string{"tag:infra"})
	serverTags := views.SliceOf([]string{"tag:server"})
	st.Peer[k1].Tags = &serverTags
	st.Peer[k2].Tags = &infraTags
	st.Peer[k3].Tags = &infraTags

	// Configured IP still in tailnet is preferred directly.
	if ip, ok := ResolvePenDNSIP(st, "100.64.0.5"); !ok || ip != netip.MustParseAddr("100.64.0.5") {
		t.Fatalf("configured IP = (%v, %v), want 100.64.0.5", ip, ok)
	}
	// If configured IP moved, lowest online tag:infra IPv4 is chosen (ignoring tag:server).
	if ip, ok := ResolvePenDNSIP(st, "100.64.0.99"); !ok || ip != netip.MustParseAddr("100.64.0.3") {
		t.Fatalf("fallback tag:infra IP = (%v, %v), want 100.64.0.3", ip, ok)
	}

	if up, nl, reason := EvaluateLiveNodeStatus(st, "100.64.0.99"); !up || nl || reason != "" {
		t.Fatalf("Running with infra fallback = (%v, %v, %q)", up, nl, reason)
	}
	if up, nl, _ := EvaluateLiveNodeStatus(&ipnstate.Status{BackendState: "NeedsLogin"}, "100.64.0.1"); up || !nl {
		t.Fatalf("NeedsLogin = (%v, %v), want (false, true)", up, nl)
	}
	if up, nl, reason := EvaluateLiveNodeStatus(&ipnstate.Status{
		BackendState: "Running",
		Self:         &ipnstate.PeerStatus{Expired: true},
	}, ""); up || nl || reason == "" {
		t.Fatalf("Expired = (%v, %v, %q), want down non-NeedsLogin", up, nl, reason)
	}
}
