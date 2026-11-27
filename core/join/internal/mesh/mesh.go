package mesh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netns"
	"tailscale.com/tsnet"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/state"
)

// ErrDeviceRemoved is returned by UpNode when an already-enrolled device is
// rejected by Headscale and asked to re-authenticate (NeedsLogin).
var ErrDeviceRemoved = errors.New("device is no longer authorized on this pen (NeedsLogin)")

// NewNode constructs an embedded userspace tsnet.Server rooted at <dir>/node.
func NewNode(dir string, c *state.AgentConfig, authKey string) *tsnet.Server {
	// On Linux 5.7+ inside containers or isolated networks with no default
	// route (such as Docker --internal bridges), tailscale's netns bindToDevice
	// falls back to SO_BINDTODEVICE("lo") unprivileged and blackholes outbound
	// dials. Opting out via HOGMAN_DISABLE_NETNS=1 keeps isolated test harnesses
	// working without weakening container network isolation or changing normal
	// host VPN bypass behavior.
	if os.Getenv("HOGMAN_DISABLE_NETNS") == "1" {
		netns.SetEnabled(false)
	}
	s := &tsnet.Server{
		Dir:        filepath.Join(dir, "node"),
		Hostname:   c.Hostname,
		ControlURL: c.LoginServer,
		AuthKey:    authKey,
		Logf:       func(string, ...any) {},
		UserLogf:   func(string, ...any) {},
	}
	if os.Getenv("HOGMAN_DEBUG") != "" {
		dbgLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		s.Logf = fsutil.SlogLogf(dbgLogger, "tsnet")
		s.UserLogf = fsutil.SlogLogf(dbgLogger, "tsnet.user")
	}
	return s
}

// UpNode brings node up and returns its status. For already-enrolled nodes
// (hasAuthKey == false), it fails fast with ErrDeviceRemoved if the control
// server rejects the device and requests interactive login, instead of
// blocking until ctx expires as tsnet.Server.Up does.
func UpNode(ctx context.Context, node *tsnet.Server, hasAuthKey bool) (*ipnstate.Status, error) {
	if hasAuthKey {
		return node.Up(ctx)
	}
	lc, err := node.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("tsnet.Up: %w", err)
	}
	watcher, err := lc.WatchIPNBus(ctx, ipn.NotifyInitialState)
	if err != nil {
		return nil, fmt.Errorf("tsnet.Up: %w", err)
	}
	defer watcher.Close()

	sawStarting := false
	for {
		n, err := watcher.Next()
		if err != nil {
			return nil, fmt.Errorf("tsnet.Up: %w", err)
		}
		if n.ErrMessage != nil && *n.ErrMessage != "" {
			return nil, fmt.Errorf("tsnet.Up: backend: %s", *n.ErrMessage)
		}
		if n.BrowseToURL != nil && *n.BrowseToURL != "" {
			return nil, ErrDeviceRemoved
		}
		if n.State == nil {
			continue
		}
		switch *n.State {
		case ipn.Starting:
			sawStarting = true
		case ipn.Running:
			sawStarting = true
			st, err := lc.Status(ctx)
			if err != nil {
				return nil, fmt.Errorf("tsnet.Up: %w", err)
			}
			if len(st.TailscaleIPs) > 0 {
				return st, nil
			}
		case ipn.NeedsLogin:
			if sawStarting {
				return nil, ErrDeviceRemoved
			}
			if st, err := lc.StatusWithoutPeers(ctx); err == nil && st != nil && st.AuthURL != "" {
				return nil, ErrDeviceRemoved
			}
		}
	}
}

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

// EvaluateLiveNodeStatus translates a running tsnet node's current Status into
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

// TsnetNeedsLogin returns a probe function that checks whether node's control
// plane explicitly reports BackendState == "NeedsLogin".
func TsnetNeedsLogin(node *tsnet.Server) func(context.Context) bool {
	if node == nil {
		return nil
	}
	return func(ctx context.Context) bool {
		lc, err := node.LocalClient()
		if err != nil {
			return false
		}
		st, err := lc.StatusWithoutPeers(ctx)
		return err == nil && st != nil && st.BackendState == "NeedsLogin"
	}
}
