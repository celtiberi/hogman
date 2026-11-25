package main

import (
	"net/netip"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func tagsPtr(tags ...string) *views.Slice[string] {
	v := views.SliceOf(tags)
	return &v
}

func TestResolvePenDNSIPAndLiveStatusFollowsInfraPeer(t *testing.T) {
	k1 := key.NewNode().Public()
	k2 := key.NewNode().Public()
	k3 := key.NewNode().Public()

	t.Run("prefers configured DNSServer when still present", func(t *testing.T) {
		st := &ipnstate.Status{
			BackendState: "Running",
			Peer: map[key.NodePublic]*ipnstate.PeerStatus{
				k1: {
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
					Tags:         tagsPtr("tag:infra"),
					Online:       true,
				},
				k2: {
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.9")},
					Tags:         tagsPtr("tag:infra"),
					Online:       true,
				},
			},
		}
		got, ok := resolvePenDNSIP(st, "100.64.0.9")
		if !ok || got.String() != "100.64.0.9" {
			t.Fatalf("resolvePenDNSIP = (%v, %v), want (100.64.0.9, true)", got, ok)
		}
	})

	t.Run("falls back to online tag:infra IPv4 when configured IP is gone", func(t *testing.T) {
		st := &ipnstate.Status{
			BackendState: "Running",
			Peer: map[key.NodePublic]*ipnstate.PeerStatus{
				k1: {
					// Untagged personal peer must NEVER be selected.
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
					Online:       true,
				},
				k2: {
					// tag:server peer must NEVER be selected.
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
					Tags:         tagsPtr("tag:server"),
					Online:       true,
				},
				k3: {
					// Moved core node with tag:infra.
					TailscaleIPs: []netip.Addr{
						netip.MustParseAddr("fd7a:115c:a1e0::7"),
						netip.MustParseAddr("100.64.0.7"),
					},
					Tags:   tagsPtr("tag:infra"),
					Online: true,
				},
			},
		}
		got, ok := resolvePenDNSIP(st, "100.64.0.1")
		if !ok || got.String() != "100.64.0.7" {
			t.Fatalf("resolvePenDNSIP = (%v, %v), want (100.64.0.7, true)", got, ok)
		}
		up, needsLogin, reason := evaluateLiveNodeStatus(st, "100.64.0.1")
		if !up || needsLogin || reason != "" {
			t.Fatalf("evaluateLiveNodeStatus = (%v, %v, %q), want (true, false, \"\")", up, needsLogin, reason)
		}
	})

	t.Run("prefers online tag:infra over offline tag:infra", func(t *testing.T) {
		st := &ipnstate.Status{
			BackendState: "Running",
			Peer: map[key.NodePublic]*ipnstate.PeerStatus{
				k1: {
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
					Tags:         tagsPtr("tag:infra"),
					Online:       false,
				},
				k2: {
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.8")},
					Tags:         tagsPtr("tag:infra"),
					Online:       true,
				},
			},
		}
		got, ok := resolvePenDNSIP(st, "100.64.0.1")
		if !ok || got.String() != "100.64.0.8" {
			t.Fatalf("resolvePenDNSIP = (%v, %v), want (100.64.0.8, true)", got, ok)
		}
	})

	t.Run("fails closed when neither configured IP nor any tag:infra peer exists", func(t *testing.T) {
		st := &ipnstate.Status{
			BackendState: "Running",
			Peer: map[key.NodePublic]*ipnstate.PeerStatus{
				k1: {
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
					Tags:         tagsPtr("tag:server"),
					Online:       true,
				},
			},
		}
		if got, ok := resolvePenDNSIP(st, "100.64.0.1"); ok {
			t.Fatalf("expected fail-closed false, got (%v, true)", got)
		}
		up, needsLogin, reason := evaluateLiveNodeStatus(st, "100.64.0.1")
		if up || needsLogin || reason != "not connected to pen" {
			t.Fatalf("evaluateLiveNodeStatus = (%v, %v, %q), want (false, false, \"not connected to pen\")", up, needsLogin, reason)
		}
	})

	t.Run("rejects IPv6-only tag:infra and configured IPv6 DNSServer (IPv4-only mesh)", func(t *testing.T) {
		st := &ipnstate.Status{
			BackendState: "Running",
			Peer: map[key.NodePublic]*ipnstate.PeerStatus{
				k1: {
					TailscaleIPs: []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::1")},
					Tags:         tagsPtr("tag:infra"),
					Online:       true,
				},
			},
		}
		if got, ok := resolvePenDNSIP(st, "fd7a:115c:a1e0::1"); ok {
			t.Fatalf("expected IPv6-only DNS peer to fail closed, got (%v, true)", got)
		}
		if inMeshRanges(netip.MustParseAddr("fd7a:115c:a1e0::1")) {
			t.Fatal("inMeshRanges must reject mesh IPv6 addresses")
		}
		if !inMeshRanges(netip.MustParseAddr("100.64.0.1")) {
			t.Fatal("inMeshRanges must accept mesh IPv4 addresses")
		}
	})
}
