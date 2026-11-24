package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netns"
	"tailscale.com/tsnet"
)

// Side-by-side mode.
//
// Instead of borrowing the computer's Tailscale app (which can only be on one
// network at a time), the agent carries its own connection to the pen and
// offers it to this computer as a local proxy that handles pen names only.
// Whatever else the computer is connected to, another Tailscale network
// included, is left alone.

type agentConfig struct {
	Zone        string `json:"zone"`
	LoginServer string `json:"login_server"`
	// RootFP is read and cleared solely to clean up legacy private-CA roots on
	// update or same-server re-join (D-22). Never newly populated or installed.
	RootFP    string `json:"root_fp,omitempty"`
	DNSServer string `json:"dns_server"` // mesh address of the pen's DNS
	Hostname  string `json:"hostname"`
	ProxyAddr string `json:"proxy_addr"` // 127.0.0.1:<port>
	// ControlCA is set only for test networks whose public control host has a
	// self-signed certificate (the --control-ca option). The agent then trusts
	// exactly this certificate for its connection to the control host.
	ControlCA string `json:"control_ca,omitempty"`
}

// trustControlCA makes this process trust the test network's control
// certificate, and nothing else, for TLS. Must run before any TLS is used.
func (c *agentConfig) trustControlCA() {
	if c.ControlCA == "" {
		return
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(c.ControlCA)) {
		return
	}
	gd := os.Getenv("GODEBUG")
	if gd != "" {
		gd += ","
	}
	os.Setenv("GODEBUG", gd+"x509usefallbackroots=1")
	x509.SetFallbackRoots(pool)
}

func loadAgentConfig(dir string) (*agentConfig, error) {
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, err
	}
	var c agentConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *agentConfig) save(dir string) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600)
}

func (c *agentConfig) proxyURL() string { return "http://" + c.ProxyAddr }
func (c *agentConfig) pacURL() string   { return "http://" + c.ProxyAddr + "/proxy.pac" }

// pac tells browsers: pen names go through the agent, everything else direct.
func (c *agentConfig) pac() string { return renderPAC([]*agentConfig{c}) }

func loadInstalledPenConfigs(configBase string) []*agentConfig {
	matches, err := filepath.Glob(filepath.Join(configBase, "*", "config.json"))
	if err != nil {
		return nil
	}
	var pens []*agentConfig
	for _, m := range matches {
		if cfg, err := loadAgentConfig(filepath.Dir(m)); err == nil {
			pens = append(pens, cfg)
		}
	}
	return normalizePenConfigs(pens, nil)
}

func (c *agentConfig) inZone(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == c.Zone || strings.HasSuffix(host, "."+c.Zone)
}

var meshRanges = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")}

func inMeshRanges(ip netip.Addr) bool {
	for _, r := range meshRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

func newNode(dir string, c *agentConfig, authKey string) *tsnet.Server {
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
		s.Logf = log.Printf
		s.UserLogf = log.Printf
	}
	return s
}

var errDeviceRemoved = errors.New("device is no longer authorized on this pen (NeedsLogin)")

// upNode brings node up and returns its status. For already-enrolled nodes
// (hasAuthKey == false), it fails fast with errDeviceRemoved if the control
// server rejects the device and requests interactive login, instead of
// blocking until ctx expires as tsnet.Server.Up does.
func upNode(ctx context.Context, node *tsnet.Server, hasAuthKey bool) (*ipnstate.Status, error) {
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
			return nil, errDeviceRemoved
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
				return nil, errDeviceRemoved
			}
			if st, err := lc.StatusWithoutPeers(ctx); err == nil && st != nil && st.AuthURL != "" {
				return nil, errDeviceRemoved
			}
		}
	}
}

func statusHasPeerIP(st *ipnstate.Status, want netip.Addr) bool {
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

func peerHasTag(p *ipnstate.PeerStatus, want string) bool {
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

// resolvePenDNSIP returns the mesh IP of the pen's DNS server from st.
// It prefers the configured DNSServer when that peer is still in the tailnet,
// and falls back to an active tag:infra peer (preferring online IPv4, then any
// IPv4, then IPv6, sorted deterministically) if the pen's core node moved IP.
// Only tag:infra peers are eligible as fallback — members and tag:server nodes
// can never claim tag:infra.
func resolvePenDNSIP(st *ipnstate.Status, configured string) (netip.Addr, bool) {
	if st == nil {
		return netip.Addr{}, false
	}
	if configured != "" {
		if ip, err := netip.ParseAddr(configured); err == nil && statusHasPeerIP(st, ip) {
			return ip.Unmap(), true
		}
	}
	var onlineV4, anyV4, onlineV6, anyV6 []netip.Addr
	for _, p := range st.Peer {
		if !peerHasTag(p, "tag:infra") {
			continue
		}
		for _, raw := range p.TailscaleIPs {
			ip := raw.Unmap()
			switch {
			case ip.Is4() && p.Online:
				onlineV4 = append(onlineV4, ip)
			case ip.Is4():
				anyV4 = append(anyV4, ip)
			case ip.Is6() && p.Online:
				onlineV6 = append(onlineV6, ip)
			case ip.Is6():
				anyV6 = append(anyV6, ip)
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
	for _, bucket := range [][]netip.Addr{onlineV4, anyV4, onlineV6, anyV6} {
		if ip, ok := pick(bucket); ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// evaluateLiveNodeStatus translates a running tsnet node's current Status into
// (up, needsLogin, reason). needsLogin is true only when the control plane
// explicitly reports BackendState == "NeedsLogin"; missing peers or other
// transient states report down without claiming the device was removed.
func evaluateLiveNodeStatus(st *ipnstate.Status, dnsServer string) (up bool, needsLogin bool, reason string) {
	if st == nil {
		return false, false, "no node status"
	}
	switch st.BackendState {
	case "Running":
		if st.Self != nil && st.Self.Expired {
			return false, false, "device session expired"
		}
		if dnsServer != "" {
			if _, ok := resolvePenDNSIP(st, dnsServer); !ok {
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

// writeStatusToken atomically writes a fresh 128-bit status authentication
// token to dir/status.token (mode 0600) so the file is never missing or
// half-written across agent restarts.
func writeStatusToken(dir string) (string, error) {
	tok, err := generateHexToken(16)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".status.token.*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if _, err := f.WriteString(tok); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, filepath.Join(dir, statusTokenFilename)); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tok, nil
}

// runAgent is the long-running process: connect to the pen, serve the proxy.
func runAgent(dir string) error {
	c, err := loadAgentConfig(dir)
	if err != nil {
		return fmt.Errorf("agent config: %w", err)
	}
	c.trustControlCA()

	// Bind the proxy port BEFORE writing agent.pid or rotating status.token so
	// a duplicate agent that fails to bind never invalidates a running agent's
	// status.token or deletes its PID file.
	ln, err := net.Listen("tcp", c.ProxyAddr)
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	defer ln.Close()

	_ = os.WriteFile(filepath.Join(dir, "agent.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600)
	defer os.Remove(filepath.Join(dir, "agent.pid"))

	// Rotate status.token atomically on startup and intentionally keep it on
	// exit so a crashed or stopped agent never leaves status.token missing.
	statusTok, err := writeStatusToken(dir)
	if err != nil {
		return fmt.Errorf("status token: %w", err)
	}

	keyFile := filepath.Join(dir, "authkey")
	key, _ := os.ReadFile(keyFile)
	authKey := strings.TrimSpace(string(key))
	node := newNode(dir, c, authKey)
	defer node.Close()

	a := newAgent(c, node)
	a.configBase = filepath.Dir(dir)
	a.statusToken = statusTok

	// Serve the proxy straight away, so the setup step can watch us come up.
	srv := &http.Server{Handler: a, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		st, err := upNode(ctx, node, authKey != "")
		a.mu.Lock()
		defer a.mu.Unlock()
		if err != nil {
			a.err = err.Error()
			log.Printf("could not join the pen: %v", err)
			return
		}
		_ = os.Remove(keyFile) // single use, and now spent
		for _, ip := range st.TailscaleIPs {
			a.ips = append(a.ips, ip.String())
		}
		a.up = true
		log.Printf("on %s as %s", c.Zone, strings.Join(a.ips, ", "))
		// A computer joins as a personal device only. Things that serve the pen
		// are shares, each a device of its own (D-11): nothing on this computer
		// is ever exposed to the pen. If the pen made this a server (an old,
		// unmarked server link), report it; joinAlongside refuses and leaves.
		if st.Self != nil && st.Self.Tags != nil {
			for _, t := range st.Self.Tags.All() {
				if t == "tag:server" {
					a.server = true
				}
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shut)
	return nil
}

type agent struct {
	cfg         *agentConfig
	configBase  string
	statusToken string
	node        *tsnet.Server
	resolver    *net.Resolver
	dialMesh    func(ctx context.Context, network, addr string) (net.Conn, error)
	lookupDNS   func(ctx context.Context, host string) ([]string, error)
	peerLookup  func(ctx context.Context, host string) ([]string, error)
	// isPeer reports whether ip belongs to a device this pen's node knows.
	// Only those may be dialed: tsnet's Dial quietly uses the computer's own
	// network for anything else, so a pen whose DNS answered 127.0.0.1, a LAN
	// address or another tailnet's 100.x address would otherwise reach it.
	isPeer     func(ctx context.Context, ip netip.Addr) bool
	liveStatus func(ctx context.Context) (up bool, needsLogin bool, reason string, ok bool)

	mu     sync.Mutex
	up     bool
	err    string
	ips    []string
	server bool
}

func newAgent(c *agentConfig, node *tsnet.Server) *agent {
	a := &agent{cfg: c, node: node}
	if node != nil {
		a.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The pen's DNS server is a dial like any other: only to a device
			// this pen's node knows. Prefer the configured DNSServer; if the
			// pen's core node moved IP, follow the live tag:infra peer instead.
			ip, err := netip.ParseAddr(c.DNSServer)
			if err != nil || !a.allowed(ctx, ip) {
				lc, lerr := node.LocalClient()
				if lerr != nil {
					return nil, errOutside
				}
				st, serr := lc.Status(ctx)
				if serr != nil {
					return nil, errOutside
				}
				found, ok := resolvePenDNSIP(st, c.DNSServer)
				if !ok || !a.allowed(ctx, found) {
					return nil, errOutside
				}
				ip = found
			}
			return node.Dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), "53"))
		}}
		a.dialMesh = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return node.Dial(ctx, network, addr)
		}
		a.lookupDNS = func(ctx context.Context, host string) ([]string, error) {
			return a.resolver.LookupHost(ctx, host)
		}
		a.isPeer = func(ctx context.Context, ip netip.Addr) bool {
			lc, err := node.LocalClient()
			if err != nil {
				return false
			}
			_, err = lc.WhoIs(ctx, ip.String())
			return err == nil
		}
		a.peerLookup = func(ctx context.Context, host string) ([]string, error) {
			lc, err := node.LocalClient()
			if err != nil {
				return nil, err
			}
			st, err := lc.Status(ctx)
			if err != nil {
				return nil, err
			}
			return peerIPsForHost(st, host), nil
		}
		a.liveStatus = func(ctx context.Context) (bool, bool, string, bool) {
			lc, err := node.LocalClient()
			if err != nil {
				return false, false, "", false
			}
			st, err := lc.Status(ctx)
			if err != nil {
				return false, false, "", false
			}
			up, needsLogin, reason := evaluateLiveNodeStatus(st, c.DNSServer)
			return up, needsLogin, reason, true
		}
	}
	return a
}

func peerIPsForHost(st *ipnstate.Status, host string) []string {
	if st == nil {
		return nil
	}
	want := strings.ToLower(strings.TrimSuffix(host, ".")) + "."
	match := func(p *ipnstate.PeerStatus) []string {
		if p == nil || strings.ToLower(p.DNSName) != want {
			return nil
		}
		out := make([]string, 0, len(p.TailscaleIPs))
		for _, ip := range p.TailscaleIPs {
			out = append(out, ip.String())
		}
		return out
	}
	if ips := match(st.Self); len(ips) > 0 {
		return ips
	}
	for _, p := range st.Peer {
		if ips := match(p); len(ips) > 0 {
			return ips
		}
	}
	return nil
}

func orderIPs(ips []string) []string {
	var v4, v6 []string
	for _, raw := range ips {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if addr.Is4() {
			v4 = append(v4, raw)
		} else {
			v6 = append(v6, raw)
		}
	}
	return append(v4, v6...)
}

type agentStatus struct {
	Zone       string   `json:"zone"`
	Up         bool     `json:"up"`
	NeedsLogin bool     `json:"needs_login,omitempty"`
	Error      string   `json:"error,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	Server     bool     `json:"server,omitempty"` // the pen tagged this device a server (refused)
}

// dial opens a connection to a pen host. Anything outside the pen is refused:
// this is not a general-purpose proxy.
func (a *agent) dial(ctx context.Context, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if a.allowed(ctx, ip) {
			// Dial the unmapped form: tsnet looks peers up by the exact
			// address, so ::ffff:<peer> would miss and fall back to the host.
			return a.dialMesh(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
		}
		return nil, errOutside
	}
	if !a.cfg.inZone(host) {
		return nil, errOutside
	}
	var ips []string
	if a.lookupDNS != nil {
		ips, _ = a.lookupDNS(ctx, host)
	}
	norm := strings.ToLower(strings.TrimSuffix(host, "."))
	if len(ips) == 0 && strings.HasSuffix(norm, ".nodes."+a.cfg.Zone) && a.peerLookup != nil {
		if pips, perr := a.peerLookup(ctx, host); perr == nil {
			ips = pips
		}
	}
	// Whatever the pen's DNS answered, dial only its own devices.
	var ordered []string
	for _, raw := range orderIPs(ips) {
		if ip, err := netip.ParseAddr(raw); err == nil && a.allowed(ctx, ip) {
			ordered = append(ordered, ip.Unmap().String())
		}
	}
	if len(ordered) == 0 {
		return nil, fmt.Errorf("no such name in the pen: %s", host)
	}
	var lastErr error
	for _, ip := range ordered {
		conn, derr := a.dialMesh(ctx, "tcp", net.JoinHostPort(ip, port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

var errOutside = fmt.Errorf("this proxy only serves the pen")

var errPort = fmt.Errorf("this proxy only carries HTTPS (port 443) to the pen")

// webPort: Hogman carries HTTPS to pen names and nothing else (D-11).
func webPort(hostport string) bool {
	_, port, err := net.SplitHostPort(hostport)
	return err == nil && port == "443"
}

// allowed: a mesh address of a device this pen's node knows (with no node,
// as in tests, the mesh ranges alone).
func (a *agent) allowed(ctx context.Context, ip netip.Addr) bool {
	ip = ip.Unmap()
	if !inMeshRanges(ip) {
		return false
	}
	if a.isPeer == nil {
		return true
	}
	return a.isPeer(ctx, ip)
}

func (a *agent) pac() string {
	if a.configBase != "" {
		return renderPAC(normalizePenConfigs(loadInstalledPenConfigs(a.configBase), a.cfg))
	}
	return a.cfg.pac()
}

// rejectBrowserProbe applies Fetch Metadata resource isolation to the local
// agent's control endpoints (/proxy.pac, /status). Non-browser callers (OS PAC
// fetchers, hogman, native host) send no Fetch Metadata headers, and
// Firefox's internal PAC loader sends Sec-Fetch-Site: none (with Dest: empty).
// Cross-site/same-site web requests and subresource loads (<script>, <img>,
// <iframe>) are rejected with 403.
func rejectBrowserProbe(w http.ResponseWriter, r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("Origin")) != "" || strings.TrimSpace(r.Header.Get("Referer")) != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return true
	}
	site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	dest := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")))
	mode := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode")))
	if site != "" {
		if site != "none" && site != "same-origin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return true
		}
	} else if dest != "" || mode != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return true
	}
	switch dest {
	case "script", "image", "iframe", "embed", "object", "style", "media", "font":
		http.Error(w, "forbidden", http.StatusForbidden)
		return true
	}
	return false
}

func (a *agent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		a.connect(w, r)
	case r.URL.IsAbs():
		a.forward(w, r)
	case !a.localHost(r.Host):
		// Only this computer's own requests, by name: a web page that rebinds
		// some DNS name to 127.0.0.1 gets nothing here.
		http.NotFound(w, r)
	case r.URL.Path == "/proxy.pac":
		if rejectBrowserProbe(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, a.pac())
	case r.URL.Path == "/status":
		if rejectBrowserProbe(w, r) {
			return
		}
		a.mu.Lock()
		st := agentStatus{Zone: a.cfg.Zone, Up: a.up, Error: a.err, IPs: a.ips, Server: a.server}
		a.mu.Unlock()
		if st.Up && a.liveStatus != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			liveUp, needsLogin, liveErr, ok := a.liveStatus(ctx)
			cancel()
			if ok && !liveUp {
				st.Up = false
				st.NeedsLogin = needsLogin
				st.Error = liveErr
			}
		}
		if a.statusToken != "" {
			if nonce := strings.TrimSpace(r.Header.Get("X-Hogman-Challenge")); nonce != "" && len(nonce) <= 128 {
				w.Header().Set("X-Hogman-Proof", computeStatusProof(a.statusToken, nonce, a.cfg.Zone))
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(st)
	default:
		http.NotFound(w, r)
	}
}

type closeWriter interface{ CloseWrite() error }

// localHost: the agent's own pages (/status, /proxy.pac) answer only requests
// addressed to its loopback address by number or as localhost.
func (a *agent) localHost(host string) bool {
	_, port, err := net.SplitHostPort(a.cfg.ProxyAddr)
	if err != nil {
		return false
	}
	return host == a.cfg.ProxyAddr || host == "localhost:"+port || host == "[::1]:"+port
}

// connect handles "CONNECT host:443", which is how browsers reach HTTPS sites
// through a proxy. The proxy only moves bytes; TLS stays end to end.
func (a *agent) connect(w http.ResponseWriter, r *http.Request) {
	if !webPort(r.Host) {
		http.Error(w, errPort.Error(), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	up, err := a.dial(ctx, r.Host)
	cancel()
	if err != nil {
		status := http.StatusBadGateway
		if err == errOutside {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	defer up.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot tunnel", http.StatusInternalServerError)
		return
	}
	down, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer down.Close()
	_, _ = io.WriteString(down, "HTTP/1.1 200 Connection established\r\n\r\n")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, buf)
		if cw, ok := up.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = up.Close()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(down, up)
		if cw, ok := down.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = down.Close()
		}
	}()
	wg.Wait()
}

// forward answers plain-HTTP requests for pen names itself, with a redirect
// to HTTPS. Nothing is sent over the network: the pen carries HTTPS only.
func (a *agent) forward(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.URL.Scheme, "http") {
		http.Error(w, "use CONNECT for HTTPS", http.StatusForbidden)
		return
	}
	host := r.URL.Hostname()
	if !a.cfg.inZone(host) {
		http.Error(w, errOutside.Error(), http.StatusForbidden)
		return
	}
	if port := r.URL.Port(); port != "" && port != "80" {
		http.Error(w, errPort.Error(), http.StatusForbidden)
		return
	}
	u := *r.URL
	u.Scheme, u.Host = "https", host
	http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
}

// agentLogout tells the pen this device is leaving. Best effort. Runs in its
// own process (see main) so trustControlCA can take effect.
func agentLogout(dir string) {
	c, err := loadAgentConfig(dir)
	if err != nil {
		return
	}
	c.trustControlCA()
	node := newNode(dir, c, "")
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := upNode(ctx, node, false); err != nil {
		return
	}
	if lc, err := node.LocalClient(); err == nil {
		_ = lc.Logout(ctx)
	}
}
