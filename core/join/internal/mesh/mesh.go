package mesh

import (
	"context"
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
	"hogman/join/internal/peerstatus"
	"hogman/join/internal/state"
)

// ErrDeviceRemoved is returned by UpNode when an already-enrolled device is
// rejected by Headscale and asked to re-authenticate (NeedsLogin).
var ErrDeviceRemoved = peerstatus.ErrDeviceRemoved

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
	return peerstatus.StatusHasPeerIP(st, want)
}

func PeerHasTag(p *ipnstate.PeerStatus, want string) bool {
	return peerstatus.PeerHasTag(p, want)
}

// ResolvePenDNSIP returns the IPv4 mesh IP of the pen's DNS server from st.
func ResolvePenDNSIP(st *ipnstate.Status, configured string) (netip.Addr, bool) {
	return peerstatus.ResolvePenDNSIP(st, configured)
}

// EvaluateLiveNodeStatus translates a running tsnet node's current Status into
// (up, needsLogin, reason).
func EvaluateLiveNodeStatus(st *ipnstate.Status, dnsServer string) (up bool, needsLogin bool, reason string) {
	return peerstatus.EvaluateLiveNodeStatus(st, dnsServer)
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
