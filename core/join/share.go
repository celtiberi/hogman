package main

// Sharing: one command puts something on the pen under a name of its own.
//
//	hogman share blog 3000                     https://blog.<pen>.hogman -> this computer's port 3000
//	hogman share notes ./public                a folder, served as a website
//	hogman share blog 3000 '<server link>'     a computer that isn't on the pen yet
//
// Each share is a small device of its own: a server (so the pen lets members
// in), named after the share. It names itself, gets a publicly trusted
// certificate by DNS-01, and passes visitors to the port or serves the folder.
// This computer opens no ports and needs no administrator rights; its own
// connection to the pen (personal devices accept no visitors) is untouched.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tsnet"

	"hogman/join/internal/agent"
	"hogman/join/internal/bridge"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/mesh"
	"hogman/join/internal/penapi"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
)

const shareUsage = `hogman share: put something on your pen under its own name

usage:
  hogman share <name> <target>                         share from this computer (it must be on the pen)
  hogman share <name> <target> '<server link>'         share from a computer that isn't on the pen
  hogman share --private-name <target> [--note TEXT]   share under a random hostname (label stays inside the pen)
  hogman share list                                    what this computer shares
  hogman share stop <name>                             take a share down and give its name back

<target> is a port on this computer (3000), a local web address
(http://localhost:8080) or a folder (./site) to serve as a website.
<name> becomes https://<name>.<pen-zone>, open to everyone in the pen.
Note: <name> is publicly visible in certificate logs (contents stay private);
don't put anything sensitive in it.

options:
  --private-name      use a random hostname so the friendly name stays inside the pen (pair with --note "Label" for the portal directory). Does not hide the pen name, site count, or issuance/renewal timing in certificate logs, and does not change certificate caps.
  --note TEXT         short one-line description shown on the pen's home page (--note "" clears it)
  --foreground        stay attached to this terminal (Ctrl-C to stop) instead of running in the background
  --no-service        don't register a login item, just run in the background
  --pen ZONE          which pen, if this computer is on more than one
  --identity-headers  pass verified X-Hogman-* caller identity headers to a local upstream target
  --force             with stop, remove local files even if the pen cannot be reached
`

var (
	shareNameRE      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){0,3}$`)
	reservedShareNS  = regexp.MustCompile(`^ns[0-9]*$`)
	reservedShareTop = map[string]bool{
		"home": true, "ns": true, "registrar": true,
		"search": true, "nodes": true, "www": true, "join": true, "admin": true,
	}
)

func isReservedShareName(name string) bool {
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "_acme-challenge" || reservedShareNS.MatchString(l) {
			return true
		}
	}
	return reservedShareTop[labels[len(labels)-1]]
}

var blockedShareMetadataIPs = map[netip.Addr]bool{
	netip.MustParseAddr("169.254.169.254"): true, // AWS/GCP/Azure/DO/Oracle IMDS
	netip.MustParseAddr("169.254.170.2"):   true, // AWS ECS task metadata
	netip.MustParseAddr("169.254.169.253"): true, // AWS VPC DNS
	netip.MustParseAddr("169.254.169.123"): true, // AWS Time Sync
	netip.MustParseAddr("100.100.100.200"): true, // Alibaba Cloud IMDS
	netip.MustParseAddr("fd00:ec2::254"):   true, // AWS IPv6 IMDS
}

func isBlockedMetadataHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	return h == "metadata.google.internal" || h == "metadata.goog" || h == "instance-data"
}

// isAllowedShareIP reports whether addr is a local or private LAN address
// suitable as a share target: loopback (127.0.0.0/8, ::1), RFC 1918
// (10/8, 172.16/12, 192.168/16), IPv6 ULA (fc00::/7), or link-local LAN
// (169.254/16, fe80::/10) — always denying cloud metadata endpoints,
// unspecified/multicast addresses, and public internet IPs.
func isAllowedShareIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	ip := addr.Unmap()
	if addr.Zone() != "" && !ip.IsLinkLocalUnicast() {
		return false
	}
	if blockedShareMetadataIPs[ip] || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// isLoopbackShareIP reports whether addr is strictly a loopback address
// (127.0.0.0/8 or ::1). Used when --identity-headers is enabled so verified
// X-Hogman-* headers are never sent across a LAN hop.
func isLoopbackShareIP(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	return addr.Unmap().IsLoopback()
}

// validateIdentityTarget enforces that --identity-headers is only used with a
// local upstream target (unix:// socket, localhost, or loopback IP), never a
// static folder or a non-local LAN host.
func validateIdentityTarget(target string, folder bool) error {
	if folder {
		return errorf("--identity-headers cannot be used with a folder share")
	}
	if strings.HasPrefix(target, "unix://") {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return errorf("--identity-headers: invalid share target %q: %v", target, err)
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "localhost" {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil && isLoopbackShareIP(ip) {
		return nil
	}
	return errorf("--identity-headers requires a local target (localhost, 127.0.0.1, ::1, or unix:// socket), got %q", target)
}

// localOrLANDialContext enforces at dial time (after resolving DNS) that share
// reverse-proxy requests only ever connect to loopback or private LAN IPs,
// denying cloud metadata endpoints and public internet addresses.
func localOrLANDialContext(lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return shareDialContext(isAllowedShareIP, "only local and private LAN targets are allowed", lookup, dial)
}

// loopbackOnlyDialContext enforces at dial time that upstream connections only
// ever reach loopback addresses (127.0.0.0/8 or ::1).
func loopbackOnlyDialContext(lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return shareDialContext(isLoopbackShareIP, "--identity-headers requires a loopback target", lookup, dial)
}

func shareDialContext(allowIP func(netip.Addr) bool, reason string, lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	if dial == nil {
		d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		dial = d.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if isBlockedMetadataHost(host) {
			return nil, errorf("refusing to proxy to cloud metadata host %q", host)
		}
		var targets []string
		if ip, err := netip.ParseAddr(host); err == nil {
			if !allowIP(ip) {
				return nil, errorf("refusing to proxy to disallowed address %q (%s)", host, reason)
			}
			if ip.Zone() != "" {
				targets = []string{ip.String()}
			} else {
				targets = []string{ip.Unmap().String()}
			}
		} else {
			resolved, err := lookup(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(resolved) == 0 {
				return nil, errorf("host %q did not resolve to any address", host)
			}
			for _, r := range resolved {
				ip, ok := netip.AddrFromSlice(r.IP)
				if !ok {
					return nil, errorf("refusing to proxy to invalid resolved address for %q", host)
				}
				ip = ip.Unmap()
				if r.Zone != "" {
					ip = ip.WithZone(r.Zone)
				}
				if !allowIP(ip) {
					return nil, errorf("refusing to proxy to disallowed address %s resolved for %q (%s)", ip, host, reason)
				}
				targets = append(targets, ip.String())
			}
		}
		var lastErr error
		for _, ipStr := range targets {
			conn, err := dial(ctx, network, net.JoinHostPort(ipStr, port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

// shareTarget reads WHAT: a port, a local/LAN web address or a folder.
func shareTarget(what string) (target string, folder bool, err error) {
	if n, err := strconv.Atoi(what); err == nil {
		if n < 1 || n > 65535 {
			return "", false, errorf("%d is not a port number", n)
		}
		return "http://127.0.0.1:" + what, false, nil
	}
	if strings.HasPrefix(what, "unix://") {
		rawPath := strings.TrimPrefix(what, "unix://")
		clean, err := bridge.ValidateUnixSocketPath(rawPath)
		if err != nil {
			return "", false, err
		}
		return "unix://" + clean, false, nil
	}
	if strings.HasPrefix(what, "http://") || strings.HasPrefix(what, "https://") {
		u, err := url.Parse(what)
		if err != nil || u.Host == "" || u.Hostname() == "" {
			return "", false, errorf("%q is not a web address", what)
		}
		if u.User != nil {
			return "", false, errorf("the share target must not contain credentials")
		}
		host := u.Hostname()
		if isBlockedMetadataHost(host) {
			return "", false, errorf("%q is a cloud metadata address and cannot be shared", what)
		}
		if ip, err := netip.ParseAddr(host); err == nil && !isAllowedShareIP(ip) {
			return "", false, errorf("%q is not a local or private LAN address (public internet and cloud metadata addresses cannot be shared)", what)
		}
		if p := u.Port(); p != "" {
			n, perr := strconv.Atoi(p)
			if perr != nil || n < 1 || n > 65535 {
				return "", false, errorf("%q has an invalid port number %q", what, p)
			}
		}
		return strings.TrimSuffix(u.String(), "/"), false, nil
	}
	abs, err := filepath.Abs(what)
	if err != nil {
		return "", false, err
	}
	fi, err := os.Stat(abs)
	if err != nil || !fi.IsDir() {
		return "", false, errorf("%q is not a port, a web address (http://localhost:8080) or a folder", what)
	}
	return abs, true, nil
}

func resolveShareNote(old *state.ShareConfig, note string, noteSet bool) string {
	if noteSet {
		return strings.TrimSpace(note)
	}
	if old != nil {
		return old.Note
	}
	return ""
}

func shareStart(name, what, rawLink string, o options) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if o.privateName {
		if name != "" {
			return errorf("cannot pass both a share name (%q) and --private-name", name)
		}
	} else {
		if !shareNameRE.MatchString(name) || name == "list" || name == "stop" {
			return errorf("%q can't be a name: use lowercase letters, digits and dashes, like blog or my-notes", name)
		}
		if isReservedShareName(name) {
			return errorf("%q is reserved by the network and can't be used as a share name", name)
		}
	}
	target, folder, err := shareTarget(what)
	if err != nil {
		return err
	}

	if o.background && o.foreground {
		return errorf("cannot combine --background and --foreground")
	}
	if o.enrollOnly && o.background {
		return errorf("--enroll-only cannot be combined with --background")
	}

	var cfg *state.ShareConfig
	key := ""
	explicitDir := strings.TrimSpace(o.stateDir)
	if explicitDir != "" {
		absDir, err := filepath.Abs(explicitDir)
		if err != nil {
			return err
		}
		explicitDir = absDir
	}

	if explicitDir != "" && rawLink == "" {
		if old, err := state.LoadShare(explicitDir); err == nil {
			if o.privateName {
				if !old.PrivateName {
					return errorf("state directory %s is enrolled for share %q (not --private-name)", explicitDir, old.Name)
				}
				if old.Name == "" {
					return errorf("state directory %s has no assigned private name yet; re-enroll with a share link", explicitDir)
				}
				cfgCopy := *old
				cfg = &cfgCopy
				name = old.Name
			} else {
				if old.Name != "" && old.Name != name {
					return errorf("state directory %s is enrolled for share %q, not %q", explicitDir, old.Name, name)
				}
				cfgCopy := *old
				cfg = &cfgCopy
				cfg.Name = name
			}
		}
	}
	if cfg == nil {
		if rawLink != "" {
			cfg, key, err = shareFromLink(name, rawLink, o)
		} else if explicitDir != "" {
			if o.privateName {
				return errorf("state directory %s is not enrolled yet. Enroll once with a share link:\n  hogman share --private-name %s --state-dir %s --enroll-only --link-stdin", explicitDir, what, explicitDir)
			}
			return errorf("state directory %s is not enrolled yet. Enroll once with a share link:\n  hogman share %s %s --state-dir %s --enroll-only --link-stdin", explicitDir, name, what, explicitDir)
		} else {
			cfg, key, err = shareFromMembership(name, o)
		}
		if err != nil {
			return err
		}
	}
	if o.privateName {
		cfg.PrivateName = true
	}
	cfg.Target, cfg.Folder = target, folder
	cfg.IdentityHeaders = o.identityHeaders
	if cfg.IdentityHeaders {
		if err := validateIdentityTarget(cfg.Target, cfg.Folder); err != nil {
			return err
		}
	}
	if uh := strings.TrimSpace(o.upstreamHost); uh != "" {
		if strings.ContainsAny(uh, " \t\r\n/\\@") || strings.Contains(uh, "://") {
			return errorf("invalid --upstream-host %q (expected a bare hostname or host:port)", uh)
		}
		cfg.UpstreamHost = uh
	}

	var dir string
	var prev *state.ShareConfig
	fresh := true
	if o.privateName && explicitDir == "" && cfg.Name == "" {
		if key == "" {
			return errorf("no way to add a device for this share")
		}
		randHex, err := state.GenerateHexToken(4)
		if err != nil {
			return err
		}
		cfg.BootstrapHostname = "site-" + randHex
		cfg.Note = resolveShareNote(nil, o.note, o.noteSet)
		stagingDir := filepath.Join(state.SharesBase(), cfg.Zone, ".pending-"+randHex)
		if err := os.MkdirAll(stagingDir, 0o700); err != nil {
			return err
		}
		if err := cfg.Save(stagingDir); err != nil {
			_ = os.RemoveAll(stagingDir)
			return err
		}
		if err := os.WriteFile(filepath.Join(stagingDir, "authkey"), []byte(key), 0o600); err != nil {
			_ = os.RemoveAll(stagingDir)
			return err
		}
		if cfg.Note == "" {
			say("%s", formatSharePrivateNoteTip())
		}
		step("Claiming a private hostname on %s", cfg.Zone)
		bctx, bstop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = claimPrivateNameBootstrap(bctx, stagingDir, cfg)
		bstop()
		if err != nil {
			_ = os.RemoveAll(stagingDir)
			return err
		}
		dir = state.ShareDir(cfg.Zone, cfg.Name)
		if err := os.Rename(stagingDir, dir); err != nil {
			_ = os.RemoveAll(stagingDir)
			return errorf("could not move private share state into %s: %v", dir, err)
		}
		say("%s", formatSharePrivateNameNotice(cfg.FQDN()))
	} else {
		dir = state.ShareDir(cfg.Zone, cfg.Name)
		if explicitDir != "" {
			dir = explicitDir
		}
		if old, err := state.LoadShare(dir); err == nil {
			if explicitDir == "" {
				if pid := sharePID(dir); pid != 0 && pid != os.Getpid() {
					return errorf("%s is already being shared from this computer (process %d). Stop it first: hogman share stop %s", old.URL(), pid, cfg.Name)
				}
			}
			_, hasUnspentKey := os.Stat(filepath.Join(dir, "authkey"))
			st := state.ReadShareStatus(dir)
			staleDevice := hasUnspentKey == nil || (st.State == "error" && st.Error != "" && isPermanentNodeError(false, "", errors.New(st.Error)))
			if rawLink != "" && key != "" && staleDevice {
				// Replacing a dead/aborted share with a fresh server link.
				_ = os.RemoveAll(filepath.Join(dir, "node"))
				_ = os.RemoveAll(filepath.Join(dir, "acme"))
				_ = os.RemoveAll(filepath.Join(dir, "authkey"))
				if cfg.ControlCA == "" {
					cfg.ControlCA = old.ControlCA
				}
				prev = old
			} else {
				key = "" // this share already has its device; reuse it
				cfg.ControlCA = old.ControlCA
				if cfg.UpstreamHost == "" {
					cfg.UpstreamHost = old.UpstreamHost
				}
				if old.PrivateName {
					cfg.PrivateName = true
				}
				if cfg.Name == "" {
					cfg.Name = old.Name
				}
				prev = old
				fresh = false
			}
		} else if key == "" {
			return errorf("no way to add a device for this share")
		}
		if cfg.PrivateName && cfg.Name == "" && cfg.BootstrapHostname == "" {
			if randHex, rerr := state.GenerateHexToken(4); rerr == nil {
				cfg.BootstrapHostname = "site-" + randHex
			}
		}
		cfg.Note = resolveShareNote(prev, o.note, o.noteSet)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := cfg.Save(dir); err != nil {
			return err
		}
		if key != "" {
			if err := os.WriteFile(filepath.Join(dir, "authkey"), []byte(key), 0o600); err != nil {
				return err
			}
		}
		if fresh {
			if cfg.PrivateName {
				if cfg.Note == "" {
					say("%s", formatSharePrivateNoteTip())
				}
			} else {
				say("%s", formatShareCertLogNotice(cfg.FQDN()))
			}
		}
	}

	if o.enrollOnly {
		if cfg.Name != "" {
			step("Enrolling %s into %s", cfg.URL(), dir)
		} else {
			step("Enrolling a private-name share on %s into %s", cfg.Zone, dir)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancelReady := context.WithCancel(ctx)
		defer cancelReady()
		return serveShare(ctx, dir, func(c *state.ShareConfig) {
			say("\n✓ Enrolled %s in %s.", c.URL(), dir)
			cancelReady()
		})
	}
	if explicitDir != "" && o.background {
		return errorf("--background is not supported with --state-dir; run the container in the foreground")
	}
	if !o.foreground && explicitDir == "" {
		err := shareBackground(dir, cfg, o)
		if err != nil && fresh {
			// If undoFreshShare already removed share.json, also clean up leftover
			// copied binary/log/status files so failed shares leave no orphan dirs.
			if _, statErr := os.Stat(filepath.Join(dir, "share.json")); os.IsNotExist(statErr) {
				_ = os.RemoveAll(dir)
			}
		}
		return err
	}
	if explicitDir == "" {
		platform.StopShareService(cfg)
	}
	if cfg.Name != "" {
		step("Sharing %s as %s", cfg.Showing(), cfg.URL())
	} else {
		step("Sharing %s under a private hostname on %s", cfg.Showing(), cfg.Zone)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveShare(ctx, dir, func(c *state.ShareConfig) {
		shareReady(c, false, false)
		if c.PrivateName && explicitDir == "" {
			say("  Stop: Ctrl-C. The name stays yours: run 'hogman share %s %s --foreground' to bring it back.", c.Name, what)
		} else {
			say("  Stop: Ctrl-C. The name stays yours: run the same command to bring it back.")
		}
	})
}

func formatShareCertLogNotice(fqdn string) string {
	return fmt.Sprintf("• Note: %s will be publicly visible in certificate logs (contents stay private). Don't put anything sensitive in the name.", fqdn)
}

func formatSharePrivateNameNotice(fqdn string) string {
	return fmt.Sprintf("• Private name: %s (only this random name appears in certificate logs; the pen name, site count, and certificate timing are still visible).", fqdn)
}

func formatSharePrivateNoteTip() string {
	return `• Tip: pass --note "Label" so members see a readable name in the portal directory instead of the random hostname.`
}

func shareReady(c *state.ShareConfig, background, managed bool) {
	say("\n✓ %s is up.", c.URL())
	say("  Everyone in the pen can open it.")
	say("  It shows %s.", c.Showing())
	if background {
		if managed {
			say("  It runs in the background and starts by itself when you log in.")
		} else {
			say("  It runs in the background until this computer restarts.")
		}
	}
	if c.PrivateName {
		say("  Take it down and retire the private name: hogman share stop %s", c.Name)
	} else {
		say("  Take it down and give the name back: hogman share stop %s", c.Name)
	}
}

// shareFromLink sets up a share on a computer that only has a server link.
func shareFromLink(name, raw string, o options) (*state.ShareConfig, string, error) {
	l, err := link.Parse(raw)
	if err != nil {
		return nil, "", errorf("%v", err)
	}
	if l.DeviceKey == "" {
		return nil, "", errorf("that is an invite. Use a share link: on your pen's home page, press Get a share link")
	}
	client, err := penapi.ControlClient(o.controlCA)
	if err != nil {
		return nil, "", err
	}
	step("Checking the network at %s", l.Host)
	n, err := penapi.FetchNetwork(client, l.Host)
	if err != nil {
		return nil, "", err
	}
	if n.DNSServer == "" {
		return nil, "", errorf("this pen's server is too old to share from here (it does not publish its DNS address)")
	}
	cfg := &state.ShareConfig{Name: name, Zone: n.Zone, LoginServer: n.LoginServer, DNSServer: n.DNSServer}
	if o.controlCA != "" {
		b, err := os.ReadFile(o.controlCA)
		if err != nil {
			return nil, "", errorf("--control-ca: %v", err)
		}
		cfg.ControlCA = string(b)
	}
	return cfg, l.DeviceKey, nil
}

type penConn struct {
	zone        string
	proxy       string // side by side: the agent's proxy; empty for this computer's Tailscale
	controlCA   string
	loginServer string
}

// myPens finds the pens this computer is on (each has its own connection).
func myPens() []penConn {
	scanned := state.ScanInstalledPens(state.ConfigBase())
	out := make([]penConn, 0, len(scanned.Pens))
	for _, p := range scanned.Pens {
		out = append(out, penConn{
			zone:        p.Zone,
			proxy:       p.Config.ProxyURL(),
			controlCA:   p.Config.ControlCA,
			loginServer: p.Config.LoginServer,
		})
	}
	return out
}

func pickPen(want string) (*penConn, error) {
	return resolvePenConn(myPens(), want)
}

// memberClient talks to the pen's home page as this computer's member.
func (p *penConn) memberClient() (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	if p.proxy != "" {
		pu, err := url.Parse(p.proxy)
		if err != nil || pu == nil || pu.Host == "" {
			return nil, errorf("invalid local proxy URL %q", p.proxy)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	pool, err := penapi.TestACMECAPool()
	if err != nil {
		return nil, err
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	return &http.Client{Timeout: 20 * time.Second, Transport: tr}, nil
}

// shareFromMembership sets up a share using this computer's place on the pen:
// it asks the pen for a server key in the member's name.
func shareFromMembership(name string, o options) (*state.ShareConfig, string, error) {
	p, err := pickPen(o.pen)
	if err != nil {
		return nil, "", err
	}
	c, err := p.memberClient()
	if err != nil {
		return nil, "", err
	}
	var me penapi.MeView
	if _, err := penapi.HomeAPI(c, p.zone, "GET", "/me", nil, &me); err != nil {
		return nil, "", errorf("could not reach home.%s as you: %v", p.zone, err)
	}
	if me.Network == nil || me.Network.DNSServer == "" {
		return nil, "", errorf("this pen's server is too old for sharing; ask its keeper to upgrade it")
	}
	loginHost := strings.TrimPrefix(p.loginServer, "https://")
	if err := penapi.ValidateNetworkInfo(loginHost, me.Network); err != nil {
		return nil, "", err
	}
	if me.Network.Zone != p.zone || me.Network.LoginServer != p.loginServer {
		return nil, "", errorf("refusing: %s returned mismatched network identity (%s at %s)", p.zone, me.Network.Zone, me.Network.LoginServer)
	}
	cfg := &state.ShareConfig{Name: name, Zone: p.zone, LoginServer: me.Network.LoginServer,
		DNSServer: me.Network.DNSServer, ControlCA: p.controlCA}
	if name != "" {
		if old, err := state.LoadShare(state.ShareDir(p.zone, name)); err == nil && old.Zone == p.zone {
			return cfg, "", nil // already has its device
		}
	}
	if me.ThisDevice.Kind == "server" {
		return nil, "", errorf("this computer is one of your servers, so it can't add devices.\n  Share from a personal device, or with a server link: hogman share NAME WHAT '<server link>'")
	}
	if name == "" {
		step("Adding a server for a private-name share on %s to your devices (%s)", p.zone, me.Member.Handle)
	} else {
		step("Adding a server for %s.%s to your devices (%s)", name, p.zone, me.Member.Handle)
	}
	var dk struct {
		AuthKey string `json:"auth_key"`
	}
	if _, err := penapi.HomeAPI(c, p.zone, "POST", "/devices", map[string]string{"kind": "server"}, &dk); err != nil {
		return nil, "", errorf("the pen would not add a server: %v", err)
	}
	return cfg, dk.AuthKey, nil
}

// --------------------------------------------------------------- serving --

// permanentShareError marks failures where automatic restarts cannot help
// (such as a refused share name, removed device, or invalid config).
type permanentShareError struct{ err error }

func (e *permanentShareError) Error() string { return e.err.Error() }
func (e *permanentShareError) Unwrap() error { return e.err }

func permanentShare(err error) error {
	if err == nil {
		return nil
	}
	return &permanentShareError{err: err}
}

func isPermanentShareError(err error) bool {
	var p *permanentShareError
	return errors.As(err, &p)
}

func shareExitCode(err error) int {
	if err == nil || isPermanentShareError(err) {
		return 0
	}
	return 1
}

func isPermanentNameStatus(code int) bool {
	return code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests
}

func isPermanentNodeError(hasAuthKey bool, backendState string, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, mesh.ErrDeviceRemoved) {
		return true
	}
	if !hasAuthKey && backendState == "NeedsLogin" {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{"invalid authkey", "authkey expired", "auth key", "not authorized", "unauthorized", "node not found", "needslogin"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// shareNode brings a share's own device onto the pen and returns it with a
// client for reaching the pen through it.
func shareNode(ctx context.Context, dir string, c *state.ShareConfig) (*tsnet.Server, *agent.Agent, *http.Client, error) {
	ac := c.AgentConfig()
	ac.TrustControlCA()
	key, _ := os.ReadFile(filepath.Join(dir, "authkey"))
	authKey := strings.TrimSpace(string(key))
	node := mesh.NewNode(dir, ac, authKey)
	upCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	st, err := mesh.UpNode(upCtx, node, authKey != "")
	if err != nil {
		var backendState string
		if lc, lerr := node.LocalClient(); lerr == nil {
			sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
			if status, serr := lc.StatusWithoutPeers(sctx); serr == nil && status != nil {
				backendState = status.BackendState
			}
			scancel()
		}
		node.Close()
		out := errorf("the share could not join the pen: %v", err)
		if isPermanentNodeError(authKey != "", backendState, err) {
			return nil, nil, nil, permanentShare(out)
		}
		return nil, nil, nil, out
	}
	_ = os.Remove(filepath.Join(dir, "authkey")) // single use, and now spent
	server := false
	if st.Self != nil && st.Self.Tags != nil {
		for _, t := range st.Self.Tags.All() {
			server = server || t == "tag:server"
		}
	}
	if !server {
		node.Close()
		return nil, nil, nil, permanentShare(errorf("that link adds a personal device, which can't be visited. Use a share link (Get a share link on your home page)"))
	}
	a := agent.New(ac, node)
	pool, err := penapi.TestACMECAPool()
	if err != nil {
		node.Close()
		return nil, nil, nil, permanentShare(err)
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext:     func(ctx context.Context, _, addr string) (net.Conn, error) { return a.Dial(ctx, addr) },
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	return node, a, hc, nil
}

// untilOK retries fn while the pen is still catching up with a new device
// (its access rules follow a few seconds behind).
func untilOK(ctx context.Context, d time.Duration, fn func() (retry bool, err error)) error {
	deadline := time.Now().Add(d)
	for {
		retry, err := fn()
		if err == nil || !retry || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// claimShareName registers c's name on the pen (allocating a random private
// label via POST /api/names {"private": true} when c.PrivateName && c.Name == "").
func claimShareName(ctx context.Context, hc *http.Client, c *state.ShareConfig, dir string) (int, error) {
	var lastCode int
	err := untilOK(ctx, 90*time.Second, func() (bool, error) {
		if c.PrivateName && c.Name == "" {
			var resp struct {
				Name string `json:"name"`
			}
			body := map[string]any{"private": true, "note": c.Note}
			code, err := penapi.HomeAPI(hc, c.Zone, "POST", "/names", body, &resp)
			lastCode = code
			if err != nil {
				return code == 0 || strings.Contains(err.Error(), "not enrolled"), err
			}
			label := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(resp.Name)), "."+c.Zone)
			if !shareNameRE.MatchString(label) || isReservedShareName(label) {
				return false, fmt.Errorf("pen returned invalid private name %q", resp.Name)
			}
			c.Name = label
			if saveErr := c.Save(dir); saveErr != nil {
				return false, saveErr
			}
			return false, nil
		}
		code, err := penapi.HomeAPI(hc, c.Zone, "POST", "/names", map[string]string{"name": c.Name, "note": c.Note}, nil)
		lastCode = code
		if err == nil {
			return false, nil
		}
		// Not through the pen's rules yet, or not recorded yet: wait.
		return code == 0 || strings.Contains(err.Error(), "not enrolled"), err
	})
	return lastCode, err
}

// claimPrivateNameBootstrap enrolls a new --private-name server in a staging
// directory, claims its random label, saves share.json, and closes tsnet cleanly
// so the caller can move the directory to shareDir(zone, label) without renaming
// open state files.
func claimPrivateNameBootstrap(ctx context.Context, stagingDir string, c *state.ShareConfig) error {
	node, _, hc, err := shareNode(ctx, stagingDir, c)
	if err != nil {
		return err
	}
	lastCode, err := claimShareName(ctx, hc, c, stagingDir)
	if err != nil {
		cleanCtx, cleanCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		if derr := giveBackDeviceWith(cleanCtx, hc, c, 0, mesh.TsnetNeedsLogin(node)); derr != nil {
			fsutil.DaemonLogger().Warn("share bootstrap cleanup failed", "err", derr)
		}
		cleanCancel()
		_ = node.Close()
		out := errorf("could not claim a private name on %s: %v", c.Zone, err)
		if ctx.Err() == nil && isPermanentNameStatus(lastCode) {
			return permanentShare(out)
		}
		return out
	}
	_ = node.Close()
	return nil
}

// serveShare runs a share until ctx ends. ready is called once its name and
// certificate are in place.
func serveShare(ctx context.Context, dir string, ready func(*state.ShareConfig)) error {
	c, err := state.LoadShare(dir)
	if err != nil {
		state.WriteShareStatus(dir, "error", err.Error())
		return permanentShare(err)
	}
	unlock, err := fsutil.AcquireShareLock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	// Foreground or background, the pid file says a share is running, so
	// list, stop and a second start all see it. Refuse to clobber a live process
	// whose status indicates it is actively starting or up (ignoring stale PIDs
	// from a prior crash whose PID number may have been recycled by the OS).
	if existing := sharePID(dir); existing != 0 && existing != os.Getpid() {
		if st := state.ReadShareStatus(dir); st.State == "up" || st.State == "starting" {
			return errorf("%s is already running (process %d)", c.URL(), existing)
		}
	}
	pidFile := filepath.Join(dir, "share.pid")
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
	defer os.Remove(pidFile)
	state.WriteShareStatus(dir, "starting", "")
	fail := func(err error) error { state.WriteShareStatus(dir, "error", err.Error()); return err }

	certStateDir := filepath.Join(dir, "acme")
	_, statErr := os.Stat(certStateDir)
	fresh := os.IsNotExist(statErr) // never got as far as a certificate
	node, _, hc, err := shareNode(ctx, dir, c)
	if err != nil {
		return fail(err)
	}
	defer node.Close()

	// Name ourselves (allocating a private random label if needed).
	hadName := c.Name != ""
	lastCode, err := claimShareName(ctx, hc, c, dir)
	if err != nil {
		if fresh {
			// A brand-new share that can't have its name: take its device back
			// out, so nothing is left behind on the pen or here.
			cleanCtx, cleanCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			if derr := giveBackDeviceWith(cleanCtx, hc, c, 0, mesh.TsnetNeedsLogin(node)); derr != nil {
				fsutil.DaemonLogger().Warn("share cleanup failed", "fqdn", c.FQDN(), "err", derr)
			}
			cleanCancel()
			node.Close()
			_ = os.RemoveAll(filepath.Join(dir, "node"))
			_ = os.Remove(filepath.Join(dir, "share.json"))
		}
		targetName := c.FQDN()
		if !hadName && c.Name == "" {
			targetName = "a private name on " + c.Zone
		}
		out := errorf("could not claim %s: %v", targetName, err)
		if ctx.Err() == nil && isPermanentNameStatus(lastCode) {
			return fail(permanentShare(out))
		}
		return fail(out)
	}
	if !hadName && c.PrivateName {
		say("%s", formatSharePrivateNameNotice(c.FQDN()))
	}

	h, closeH, err := shareHandlerWithResolver(c, tsnetPeerResolver(node))
	if err != nil {
		if fresh {
			undoFreshShare(hc, node, dir, c)
		}
		return fail(err)
	}
	defer closeH()
	ln443, err := node.Listen("tcp", ":443")
	if err != nil {
		if fresh {
			undoFreshShare(hc, node, dir, c)
		}
		return fail(err)
	}
	quiet := slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)

	cm, err := newShareCertManager(shareACMEConfigFromEnv(c.Zone, c.FQDN(), certStateDir, hc))
	if err != nil {
		_ = ln443.Close()
		if fresh {
			undoFreshShare(hc, node, dir, c)
		}
		return fail(err)
	}
	defer cm.Close()
	if err := cm.EnsureWithBackoff(ctx); err != nil {
		_ = ln443.Close()
		permanent := isNonRetryableShareCertErr(err) && ctx.Err() == nil
		out := errorf("no certificate for %s: %v", c.FQDN(), err)
		// A brand-new share that never got a certificate leaves nothing behind:
		// its name goes back, so it isn't listed as a site that doesn't answer,
		// and its server leaves the pen. Foreground or --background alike: the
		// first start of a background share is stopped on its first error
		// anyway (waitShareBackground). Shares that have had a certificate keep
		// retrying with the persistent backoff instead.
		if fresh {
			cm.Close()
			clean := undoFreshShare(hc, node, dir, c)
			out = formatFreshShareCertError(c.FQDN(), c.Name, c.Zone, err, clean)
			return fail(permanentShare(out))
		}
		if permanent {
			return fail(permanentShare(out))
		}
		return fail(out)
	}
	go cm.RunFailoverLoop(ctx)
	tlsSrv := &http.Server{
		Handler:           h,
		TLSConfig:         cm.TLSConfig(),
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          quiet,
	}
	go func() { _ = tlsSrv.ServeTLS(ln443, "", "") }()
	defer tlsSrv.Close()
	state.WriteShareStatus(dir, "up", "")
	if ready != nil {
		ready(c)
	}
	<-ctx.Done()
	state.WriteShareStatus(dir, "stopped", "")
	return nil
}

func retryAfterHint(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	mins := int((d + time.Minute - 1) / time.Minute)
	if mins < 1 {
		mins = 1
	}
	if mins <= 120 {
		if mins == 1 {
			return "try again in about 1 minute"
		}
		return fmt.Sprintf("try again in about %d minutes", mins)
	}
	hours := int((d + time.Hour - 1) / time.Hour)
	if hours < 48 {
		return fmt.Sprintf("try again in about %d hours", hours)
	}
	days := int((d + 24*time.Hour - 1) / (24 * time.Hour))
	return fmt.Sprintf("try again in about %d days", days)
}

func formatFreshShareCertError(fqdn, name, zone string, err error, cleanRollback bool) error {
	var me *penapi.HomeAPIError
	rollbackNote := fmt.Sprintf("Nothing was left behind: the name %s is free again.", name)
	if !cleanRollback {
		rollbackNote = fmt.Sprintf("Cleanup could not be fully confirmed; check Sites and Devices on home.%s before sharing again.", zone)
	}
	if errors.As(err, &me) && me.Status == http.StatusTooManyRequests {
		if hint := retryAfterHint(me.RetryAfter); hint != "" {
			return errorf("no certificate for %s: %s (%s)\n  %s Wait and share again\n  (if you used a one-time server link, get a fresh one).", fqdn, me.Msg, hint, rollbackNote)
		}
		return errorf("no certificate for %s: %s\n  %s Wait and share again\n  (if you used a one-time server link, get a fresh one).", fqdn, me.Msg, rollbackNote)
	}
	return errorf("no certificate for %s: %v\n  %s Fix the problem above,\n  then share again with a fresh share link (this one is used up).", fqdn, err, rollbackNote)
}

// noDotfilesFS wraps a folder share's fs.FS to deny hidden dotfiles/directories
// (like .git, .env, .DS_Store) on both direct Open and directory listings,
// while allowing .well-known.
type noDotfilesFS struct{ inner fs.FS }

func isHiddenDotEntry(name string) bool {
	return strings.HasPrefix(name, ".") && name != "." && name != ".well-known"
}

func (f noDotfilesFS) Open(name string) (fs.File, error) {
	if name != "." {
		for _, seg := range strings.Split(name, "/") {
			if isHiddenDotEntry(seg) {
				return nil, fs.ErrNotExist
			}
		}
	}
	file, err := f.inner.Open(name)
	if err != nil {
		return nil, err
	}
	if rdf, ok := file.(fs.ReadDirFile); ok {
		return noDotfilesDir{ReadDirFile: rdf}, nil
	}
	return file, nil
}

type noDotfilesDir struct{ fs.ReadDirFile }

func (d noDotfilesDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if n <= 0 {
		all, err := d.ReadDirFile.ReadDir(n)
		return filterDotDirEntries(all), err
	}
	var out []fs.DirEntry
	for len(out) < n {
		batch, err := d.ReadDirFile.ReadDir(n - len(out))
		out = append(out, filterDotDirEntries(batch)...)
		if err != nil {
			if len(out) > 0 && errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
		if len(batch) == 0 {
			break
		}
	}
	return out, nil
}

func filterDotDirEntries(entries []fs.DirEntry) []fs.DirEntry {
	out := entries[:0]
	for _, e := range entries {
		if !isHiddenDotEntry(e.Name()) {
			out = append(out, e)
		}
	}
	return out
}

// hasPathTraversal reports whether a request's path or raw escaped path attempts
// to traverse out of a subpath-scoped reverse-proxy target using dot-segments,
// backslashes, or percent-encoded dots/backslashes (while allowing legitimate
// percent-encoded slashes like %2F inside non-traversal path parameters).
func hasPathTraversal(u *url.URL) bool {
	if u.Opaque != "" {
		return true
	}
	raw := strings.ToLower(u.EscapedPath())
	if strings.Contains(raw, "%2e") || strings.Contains(raw, "%5c") || strings.Contains(raw, "\\") {
		return true
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

var shareHandleRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)

// sharePeerIdentity holds the mesh-authenticated peer identity resolved from
// tsnet WhoIs for an incoming request to a shared local app.
type sharePeerIdentity struct {
	Handle string
	Node   string
	IP     string
	Tags   []string
}

type sharePeerResolver func(ctx context.Context, remoteAddr string) (*sharePeerIdentity, error)

func cleanHeaderToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f || r > 0x7e {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func peerIdentityFromWhoIs(remoteAddr string, who *apitype.WhoIsResponse) *sharePeerIdentity {
	if who == nil || who.Node == nil {
		return nil
	}
	rawIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		rawIP = host
	}
	ip := ""
	if addr, err := netip.ParseAddr(strings.TrimSpace(rawIP)); err == nil {
		ip = addr.Unmap().String()
	}

	var tags []string
	for _, t := range who.Node.Tags {
		clean := cleanHeaderToken(t)
		if clean == "" || strings.Contains(clean, ",") {
			continue
		}
		tags = append(tags, clean)
	}
	sort.Strings(tags)

	nodeName := cleanHeaderToken(who.Node.ComputedName)
	if nodeName == "" {
		rawName := strings.TrimSuffix(strings.TrimSpace(who.Node.Name), ".")
		if before, _, ok := strings.Cut(rawName, "."); ok {
			rawName = before
		}
		nodeName = cleanHeaderToken(rawName)
	}

	handle := ""
	// Tagged nodes (such as tag:server) are not personal users and must never
	// receive X-Hogman-Handle.
	if len(tags) == 0 && !who.Node.IsTagged() && who.UserProfile != nil {
		cand := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(who.UserProfile.LoginName)), "@")
		if shareHandleRE.MatchString(cand) {
			handle = cand
		}
	}

	return &sharePeerIdentity{
		Handle: handle,
		Node:   nodeName,
		IP:     ip,
		Tags:   tags,
	}
}

func tsnetPeerResolver(node *tsnet.Server) sharePeerResolver {
	return func(ctx context.Context, remoteAddr string) (*sharePeerIdentity, error) {
		if node == nil {
			return nil, errors.New("no mesh node")
		}
		lc, err := node.LocalClient()
		if err != nil {
			return nil, err
		}
		who, err := lc.WhoIs(ctx, remoteAddr)
		if err != nil {
			return nil, err
		}
		return peerIdentityFromWhoIs(remoteAddr, who), nil
	}
}

func isHogmanHeaderName(k string) bool {
	norm := strings.ReplaceAll(strings.ToLower(k), "_", "-")
	return strings.HasPrefix(norm, "x-hogman-")
}

func stripHogmanHeaders(h http.Header) {
	for k := range h {
		if isHogmanHeaderName(k) {
			delete(h, k)
		}
	}
}

func shareHandler(c *state.ShareConfig) (http.Handler, func(), error) {
	return shareHandlerWithResolver(c, nil)
}

func shareHandlerWithResolver(c *state.ShareConfig, resolve sharePeerResolver) (http.Handler, func(), error) {
	if c.IdentityHeaders {
		if err := validateIdentityTarget(c.Target, c.Folder); err != nil {
			return nil, nil, permanentShare(err)
		}
	}
	if c.Folder {
		// os.Root keeps every read inside the folder: a symlink pointing out
		// of it (to ~/.ssh, say) is refused, not followed; noDotfilesFS also
		// hides .git/.env and similar dotfiles.
		root, err := os.OpenRoot(c.Target)
		if err != nil {
			return nil, nil, errorf("cannot open the folder %s: %v", c.Target, err)
		}
		return http.FileServerFS(noDotfilesFS{inner: root.FS()}), func() { _ = root.Close() }, nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // always connect directly to the local/LAN or Unix socket share target
	tr.MaxResponseHeaderBytes = 64 << 10
	tr.MaxConnsPerHost = 128
	tr.MaxIdleConnsPerHost = 32

	var targetURL *url.URL
	var rewriteHost string
	if strings.HasPrefix(c.Target, "unix://") {
		sockPath, err := bridge.ValidateUnixSocketPath(strings.TrimPrefix(c.Target, "unix://"))
		if err != nil {
			return nil, nil, permanentShare(err)
		}
		tr.ResponseHeaderTimeout = 60 * time.Second
		tr.DialContext = bridge.UnixSocketDialContext(sockPath)
		rewriteHost = strings.TrimSpace(c.UpstreamHost)
		if rewriteHost == "" {
			rewriteHost = c.FQDN()
		}
		targetURL = &url.URL{Scheme: "http", Host: rewriteHost}
	} else {
		u, err := url.Parse(c.Target)
		if err != nil {
			return nil, nil, permanentShare(err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, nil, permanentShare(errorf("share target %q must use http://, https://, or unix://", c.Target))
		}
		if isBlockedMetadataHost(u.Hostname()) {
			return nil, nil, permanentShare(errorf("share target %q is a cloud metadata address and cannot be shared", c.Target))
		}
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !isAllowedShareIP(ip) {
			return nil, nil, permanentShare(errorf("share target %q is not a local or private LAN address", c.Target))
		}
		if c.IdentityHeaders {
			tr.DialContext = loopbackOnlyDialContext(nil, nil)
		} else {
			tr.DialContext = localOrLANDialContext(nil, nil)
		}
		targetURL = u
	}

	type shareIdentityCtxKey struct{}

	rp := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Opaque = ""
			pr.SetURL(targetURL)
			if rewriteHost != "" {
				pr.Out.Host = rewriteHost
			}
			// Never trust client-supplied forwarding or X-Hogman-* identity
			// headers: strip them unconditionally before setting fresh values
			// from the authenticated mesh connection.
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			stripHogmanHeaders(pr.Out.Header)
			stripHogmanHeaders(pr.Out.Trailer)
			if clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil && clientIP != "" {
				pr.Out.Header.Set("X-Forwarded-For", clientIP)
			}
			pr.Out.Header.Set("X-Forwarded-Host", c.FQDN())
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			if c.IdentityHeaders {
				if id, ok := pr.In.Context().Value(shareIdentityCtxKey{}).(*sharePeerIdentity); ok && id != nil {
					if id.Handle != "" {
						pr.Out.Header.Set("X-Hogman-Handle", id.Handle)
					}
					if id.Node != "" {
						pr.Out.Header.Set("X-Hogman-Node", id.Node)
					}
					if id.IP != "" {
						pr.Out.Header.Set("X-Hogman-IP", id.IP)
					}
					if len(id.Tags) > 0 {
						pr.Out.Header.Set("X-Hogman-Tags", strings.Join(id.Tags, ","))
					}
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "%s is shared from a computer where the app isn't answering right now.\n", c.FQDN())
		},
		ErrorLog: slog.NewLogLogger(slog.DiscardHandler, slog.LevelError),
	}
	subpath := targetURL.Path != "" && targetURL.Path != "/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Opaque != "" || (subpath && hasPathTraversal(r.URL)) {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		if c.IdentityHeaders {
			if resolve == nil {
				http.Error(w, "could not verify caller identity", http.StatusServiceUnavailable)
				return
			}
			whoCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			id, err := resolve(whoCtx, r.RemoteAddr)
			cancel()
			if err != nil || id == nil {
				http.Error(w, "could not verify caller identity", http.StatusServiceUnavailable)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), shareIdentityCtxKey{}, id))
		}
		rp.ServeHTTP(w, r)
	}), func() {}, nil
}

// ------------------------------------------------- background, status --

func startShareBackground(dir string, c *state.ShareConfig, o options) (bool, int, error) {
	bin, err := installedBinary(dir)
	if err != nil {
		return false, 0, err
	}
	if runtime.GOOS == "windows" {
		note("on Windows shares do not yet restart by themselves; run this command again after a restart")
		return platform.StartShareServiceWithBinary(bin, dir, c, true, note)
	}
	return platform.StartShareServiceWithBinary(bin, dir, c, o.noService, note)
}

// sharePID is the process serving a share in the background, or 0.
func sharePID(dir string) int {
	b, err := os.ReadFile(filepath.Join(dir, "share.pid"))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 || !platform.ProcessAlive(pid) {
		return 0
	}
	return pid
}

func shareBackground(dir string, c *state.ShareConfig, o options) error {
	_ = os.Remove(filepath.Join(dir, "status.json"))
	_ = os.Remove(filepath.Join(dir, "share.pid"))
	step("Sharing %s as %s, in the background", c.Showing(), c.URL())
	managed, pid, err := startShareBackground(dir, c, o)
	if err != nil {
		return err
	}
	return waitShareBackground(dir, c, managed, pid, 4*time.Minute, func() {
		stopShare(dir, c)
	})
}

func waitShareBackground(dir string, c *state.ShareConfig, managed bool, pid int, timeout time.Duration, stopFn func()) error {
	logPath := filepath.Join(dir, "share.log")
	poll := time.Second
	if timeout < poll {
		poll = max(10*time.Millisecond, timeout/2)
	}
	ctx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSig()
	start := time.Now()
	deadline := start.Add(timeout)
	warnedNoStatus := false
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			if stopFn != nil {
				stopFn()
			}
			return errorf("cancelled while starting %s", c.URL())
		case <-time.After(poll):
		}
		st := state.ReadShareStatus(dir)
		if !managed && st.State != "up" && st.State != "error" && !platform.ProcessAlive(pid) {
			if stopFn != nil {
				stopFn()
			}
			return errorf("the share stopped before it came up. Log: %s", logPath)
		}
		if managed && st.State == "" && !warnedNoStatus && time.Since(start) >= 15*time.Second {
			warnedNoStatus = true
			note("still waiting for the background service to start; check %s if it does not come up", logPath)
		}
		switch st.State {
		case "up":
			shareReady(c, true, managed)
			return nil
		case "error":
			if stopFn != nil {
				stopFn()
			}
			return errorf("%s", st.Error)
		}
	}
	if stopFn != nil {
		stopFn()
	}
	return errorf("the share did not come up in time. Log: %s", logPath)
}

// runShareProcess is the background process (`__share-run DIR`).
func runShareProcess(dir string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveShare(ctx, dir, func(c *state.ShareConfig) {
		fsutil.DaemonLogger().Info("share online", "url", c.URL(), "target", c.Showing())
	})
}

func stopShare(dir string, c *state.ShareConfig) {
	platform.StopShareService(c)
	stopShareProcess(dir)
}

func stopShareProcess(dir string) {
	pid := sharePID(dir)
	if pid == 0 {
		return
	}
	platform.StopProcess(pid, 5*time.Second)
	_ = os.Remove(filepath.Join(dir, "share.pid"))
}

// ------------------------------------------------------------ list, stop --

func shareListState(running, managed bool) string {
	switch {
	case running && managed:
		return "running in the background, starts at login"
	case running:
		return "running in the background"
	case managed:
		return "stopped (starts at login)"
	default:
		return "not running"
	}
}

type shareListItemJSON struct {
	Name    string `json:"name"`
	Zone    string `json:"zone"`
	URL     string `json:"url"`
	Target  string `json:"target"`
	Folder  bool   `json:"folder"`
	Note    string `json:"note,omitempty"`
	Private bool   `json:"private,omitempty"`
	Running bool   `json:"running"`
	Managed bool   `json:"managed"`
	State   string `json:"state"`
	Error   string `json:"error,omitempty"`
}

func collectShareListItems(dirs []string) []shareListItemJSON {
	items := make([]shareListItemJSON, 0, len(dirs))
	for _, d := range dirs {
		c, err := state.LoadShare(d)
		if err != nil {
			continue
		}
		running := sharePID(d) != 0
		managed := platform.ShareServiceConfigured(c)
		stateLabel := shareListState(running, managed)
		errMsg := ""
		if !running {
			if st := state.ReadShareStatus(d); st.State == "error" && st.Error != "" {
				errMsg = link.SingleLine(st.Error)
				stateLabel += ": " + errMsg
			}
		}
		items = append(items, shareListItemJSON{
			Name:    c.Name,
			Zone:    c.Zone,
			URL:     c.URL(),
			Target:  c.Target,
			Folder:  c.Folder,
			Note:    c.Note,
			Private: c.PrivateName,
			Running: running,
			Managed: managed,
			State:   stateLabel,
			Error:   errMsg,
		})
	}
	return items
}

func formatShareListTable(w io.Writer, items []shareListItemJSON) {
	hasNote := false
	for _, item := range items {
		if item.Note != "" {
			hasNote = true
			break
		}
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if hasNote {
		fmt.Fprintln(tw, "NAME\tPEN\tURL\tTARGET\tNOTE\tSTATUS")
	} else {
		fmt.Fprintln(tw, "NAME\tPEN\tURL\tTARGET\tSTATUS")
	}
	for _, item := range items {
		pen := link.ShortPenLabel(item.Zone)
		if hasNote {
			noteCol := item.Note
			if noteCol == "" {
				noteCol = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", item.Name, pen, item.URL, item.Target, noteCol, item.State)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", item.Name, pen, item.URL, item.Target, item.State)
		}
	}
	_ = tw.Flush()
}

func shareList(zone string, asJSON bool) error {
	all := state.AllShares("")
	resolvedZone, err := resolveShareZoneFilter(all, zone)
	if err != nil {
		return err
	}
	dirs := state.AllShares(resolvedZone)
	if asJSON {
		return writeJSON(os.Stdout, collectShareListItems(dirs))
	}
	if len(dirs) == 0 {
		if resolvedZone != "" {
			say("This computer shares nothing on %s.", resolvedZone)
		} else {
			say("This computer shares nothing. Start with: hogman share <name> <target>")
		}
		return nil
	}
	formatShareListTable(os.Stdout, collectShareListItems(dirs))
	return nil
}

func normalizeShareLookup(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

func shareMatchesLookup(shareName, shareZone, query string) bool {
	if query == "" {
		return false
	}
	sn := strings.ToLower(shareName)
	sz := strings.ToLower(shareZone)
	if query == sn || query == sn+"."+sz {
		return true
	}
	if pen := link.ShortPenLabel(sz); pen != "" && query == sn+"."+pen {
		return true
	}
	return false
}

func formatActiveSharesHint(dirs []string) string {
	if len(dirs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n  Active shares on this computer:")
	for _, d := range dirs {
		name := filepath.Base(d)
		zone := filepath.Base(filepath.Dir(d))
		fmt.Fprintf(&sb, "\n    hogman share stop %s   (%s)", name, link.ShortPenLabel(zone))
	}
	return sb.String()
}

func shareStopUsageError(zone string) error {
	all := state.AllShares("")
	dirs := all
	if resolvedZone, err := resolveShareZoneFilter(all, zone); err == nil {
		dirs = state.AllShares(resolvedZone)
	}
	if len(dirs) == 0 {
		return usageErrorf("usage: hogman share stop <name>\n  This computer currently shares nothing.")
	}
	return usageErrorf("usage: hogman share stop <name>%s", formatActiveSharesHint(dirs))
}

func findShare(name, zone string) (string, error) {
	query := normalizeShareLookup(name)
	all := state.AllShares("")
	resolvedZone, err := resolveShareZoneFilter(all, zone)
	if err != nil {
		return "", err
	}
	dirs := state.AllShares(resolvedZone)
	var hits []string
	for _, d := range dirs {
		if shareMatchesLookup(filepath.Base(d), filepath.Base(filepath.Dir(d)), query) {
			hits = append(hits, d)
		}
	}
	switch len(hits) {
	case 0:
		if len(dirs) > 0 {
			return "", errorf("this computer doesn't share anything called %s%s", strings.TrimSpace(name), formatActiveSharesHint(dirs))
		}
		return "", errorf("this computer doesn't share anything called %s (see: hogman share list)", strings.TrimSpace(name))
	case 1:
		return hits[0], nil
	}
	if isTerminalFn() {
		say("%s is shared on more than one pen:", query)
		for i, d := range hits {
			say("  %d) %s", i+1, filepath.Base(filepath.Dir(d)))
		}
		ans := strings.TrimSpace(askFn(fmt.Sprintf("  Choose a pen [1-%d]: ", len(hits))))
		idx, err := strconv.Atoi(ans)
		if err != nil || idx < 1 || idx > len(hits) {
			return "", errorf("cancelled: choose a number between 1 and %d (or pass --pen <zone>)", len(hits))
		}
		return hits[idx-1], nil
	}
	return "", errorf("%s is shared on more than one pen here; pick one with --pen <zone> or set HOGMAN_PEN", query)
}

func shareStop(name string, o options) error {
	dir, err := findShare(name, o.pen)
	if err != nil {
		return err
	}
	c, err := state.LoadShare(dir)
	if err != nil {
		return err
	}
	step("Taking down %s", c.URL())
	if err := removeShareWithOptions(dir, c, 30*time.Second, o.force); err != nil {
		return err
	}
	if c.PrivateName {
		say("\n✓ %s is down, and its private name is retired.", c.URL())
	} else {
		say("\n✓ %s is down, and the name is free again.", c.URL())
	}
	return nil
}

// removeShareForLeave tears down a share during `hogman leave`, bounding
// network wait and cleaning up local state even if the pen already removed it
// or is unreachable.
func removeShareForLeave(dir string, c *state.ShareConfig) error {
	return removeShareWithOptions(dir, c, 15*time.Second, true)
}

func removeShareWithOptions(dir string, c *state.ShareConfig, timeout time.Duration, cleanupOnUnreachable bool) error {
	stopShare(dir, c)
	// Never got as far as joining the pen (its one-time key is still unused,
	// or has expired): there's nothing on the pen to give back.
	if _, err := os.Stat(filepath.Join(dir, "authkey")); err == nil {
		note("%s never came up; removed it from this computer", c.URL())
		return os.RemoveAll(dir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	node, _, hc, err := shareNode(ctx, dir, c)
	if err != nil {
		if isPermanentShareError(err) {
			note("%s was already removed from the pen; cleaned up local files", c.URL())
			return os.RemoveAll(dir)
		}
		if cleanupOnUnreachable {
			note("could not reach the pen for %s (%v); cleaned up local files (check your home page to remove the server if it is still listed)", c.URL(), link.SingleLine(err.Error()))
			return os.RemoveAll(dir)
		}
		return errorf("could not reach the pen (%v).\n  Remove the server on your home page instead, then delete %s", err, dir)
	}
	err = giveBackWith(ctx, hc, c, mesh.TsnetNeedsLogin(node))
	node.Close()
	if err != nil {
		if cleanupOnUnreachable {
			note("could not give back %s (%v); cleaned up local files", c.URL(), link.SingleLine(err.Error()))
			return os.RemoveAll(dir)
		}
		return errorf("%v\n  Local files remain in %s; run 'hogman share stop %s --force' to remove them.", err, dir, c.Name)
	}
	return os.RemoveAll(dir)
}

func giveBackWith(ctx context.Context, hc *http.Client, c *state.ShareConfig, checkNeedsLogin func(context.Context) bool) error {
	var me penapi.MeView
	err := untilOK(ctx, 60*time.Second, func() (bool, error) {
		code, err := penapi.HomeAPICtx(ctx, hc, c.Zone, "GET", "/me", nil, &me)
		return code == 0, err
	})
	if err != nil {
		return errorf("could not reach home.%s from the share: %v", c.Zone, err)
	}
	if code, err := penapi.HomeAPICtx(ctx, hc, c.Zone, "DELETE", "/names/"+url.PathEscape(c.Name), nil, nil); err != nil && code != 404 {
		return errorf("could not give back %s: %v", c.FQDN(), err)
	}
	note("gave back the name %s", c.FQDN())
	if err := giveBackDeviceWith(ctx, hc, c, me.ThisDevice.ID, checkNeedsLogin); err != nil {
		return err
	}
	note("removed its server from your devices")
	return nil
}

// undoFreshShare gives a brand-new share's name back and takes its server out
// of the pen, then forgets it here. Best effort, on its own short clock: it
// also runs after Ctrl-C. Reports whether both server-side cleanup steps were
// confirmed so callers do not claim "nothing was left behind" on partial failure.
func undoFreshShare(hc *http.Client, node io.Closer, dir string, c *state.ShareConfig) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var checkNL func(context.Context) bool
	if ts, ok := node.(*tsnet.Server); ok {
		checkNL = mesh.TsnetNeedsLogin(ts)
	}
	logger := fsutil.DaemonLogger()
	nameOK := true
	if code, err := penapi.HomeAPICtx(ctx, hc, c.Zone, "DELETE", "/names/"+url.PathEscape(c.Name), nil, nil); err != nil && code != 404 {
		nameOK = false
		logger.Warn("could not release share name", "fqdn", c.FQDN(), "err", err)
	}
	devOK := true
	if err := giveBackDeviceWith(ctx, hc, c, 0, checkNL); err != nil {
		devOK = false
		logger.Warn("could not remove share device", "fqdn", c.FQDN(), "err", err)
	}
	_ = node.Close()
	for _, f := range []string{"node", "acme", "share.json", "authkey"} {
		_ = os.RemoveAll(filepath.Join(dir, f))
	}
	return nameOK && devOK
}

// giveBackDevice removes the share's own device from the pen.
func giveBackDevice(ctx context.Context, hc *http.Client, c *state.ShareConfig) error {
	return giveBackDeviceWith(ctx, hc, c, 0, nil)
}

func giveBackDeviceWith(ctx context.Context, hc *http.Client, c *state.ShareConfig, deviceID int64, checkNeedsLogin func(context.Context) bool) error {
	res := penapi.DeleteSelfDevice(ctx, hc, c.Zone, deviceID, checkNeedsLogin)
	switch res.Outcome {
	case penapi.SelfDeleteRemoved:
		return nil
	case penapi.SelfDeleteCanceled:
		return res.Err
	case penapi.SelfDeleteLookupFailed:
		return errorf("could not reach home.%s from the share: %v", c.Zone, res.Err)
	case penapi.SelfDeleteMissingID:
		return errorf("home.%s did not report this share's device ID", c.Zone)
	case penapi.SelfDeleteUnconfirmed:
		return errorf("could not confirm removal of the share's server on %s; check Devices on home.%s", c.Zone, c.Zone)
	default:
		return errorf("the pen would not remove the share's server: %v", res.Err)
	}
}
