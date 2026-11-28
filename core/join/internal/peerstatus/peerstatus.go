package peerstatus

import (
	"errors"
	"net/netip"

	"tailscale.com/ipn/ipnstate"
)

// ErrDeviceRemoved is returned when an already-enrolled device is rejected by
// Headscale and asked to re-authenticate (NeedsLogin).
var ErrDeviceRemoved = errors.New("device is no longer authorized on this pen (NeedsLogin)")

func StatusHasPeerIP(st *ipnstate.Status, want netip.Addr) bool {
	if st == nil {
		return false
	}
	want = want.Unmap()
	if st.Self != nil {
		for _, ip := range st.Self.TailscaleIPs {
			if ip.Unmap() == want {
				return true
			}
		}
	}
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		for _, ip := range p.TailscaleIPs {
			if ip.Unmap() == want {
				return true
			}
		}
	}
	return false
}

func PeerHasTag(p *ipnstate.PeerStatus, want string) bool {
	if p == nil || p.Tags == nil {
		return false
	}
	for _, t := range p.Tags.All() {
		if t == want {
			return true
		}
	}
	return false
}

// ResolvePenDNSIP returns the IPv4 mesh IP of the pen's DNS server from st.
// It prefers the configured IPv4 DNSServer when that peer is still in the
// tailnet, and falls back to an active tag:infra peer (preferring online IPv4,
// then any IPv4, sorted deterministically) if the pen's core node moved IP.
// Only tag:infra peers are eligible as fallback — members and tag:server nodes
// can never claim tag:infra.
func ResolvePenDNSIP(st *ipnstate.Status, configured string) (netip.Addr, bool) {
	if st == nil {
		return netip.Addr{}, false
	}
	if configured != "" {
		if ip, err := netip.ParseAddr(configured); err == nil {
			ip = ip.Unmap()
			if ip.Is4() && StatusHasPeerIP(st, ip) {
				return ip, true
			}
		}
	}
	var onlineV4, anyV4 []netip.Addr
	for _, p := range st.Peer {
		if !PeerHasTag(p, "tag:infra") {
			continue
		}
		for _, raw := range p.TailscaleIPs {
			ip := raw.Unmap()
			if !ip.Is4() {
				continue
			}
			if p.Online {
				onlineV4 = append(onlineV4, ip)
			} else {
				anyV4 = append(anyV4, ip)
			}
		}
	}
	pick := func(list []netip.Addr) (netip.Addr, bool) {
		if len(list) == 0 {
			return netip.Addr{}, false
		}
		best := list[0]
		for _, ip := range list[1:] {
			if ip.Less(best) {
				best = ip
			}
		}
		return best, true
	}
	for _, bucket := range [][]netip.Addr{onlineV4, anyV4} {
		if ip, ok := pick(bucket); ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// EvaluateLiveNodeStatus translates a running node's current Status into
// (up, needsLogin, reason). needsLogin is true only when the control plane
// explicitly reports BackendState == "NeedsLogin"; missing peers or other
// transient states report down without claiming the device was removed.
func EvaluateLiveNodeStatus(st *ipnstate.Status, dnsServer string) (up bool, needsLogin bool, reason string) {
	if st == nil {
		return false, false, "no node status"
	}
	switch st.BackendState {
	case "Running":
		if st.Self != nil && st.Self.Expired {
			return false, false, "device session expired"
		}
		if dnsServer != "" {
			if _, ok := ResolvePenDNSIP(st, dnsServer); !ok {
				return false, false, "not connected to pen"
			}
		}
		return true, false, ""
	case "NeedsLogin":
		return false, true, "device removed from pen"
	case "":
		return false, false, "not connected"
	default:
		return false, false, "not connected (" + st.BackendState + ")"
	}
}
