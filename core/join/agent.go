package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"

	"hogman/join/internal/fsutil"
	"hogman/join/internal/link"
	"hogman/join/internal/mesh"
	"hogman/join/internal/state"
)

// runAgent is the long-running process: connect to the pen, serve the proxy.
func runAgent(dir string) error {
	c, err := state.LoadAgentConfig(dir)
	if err != nil {
		return fmt.Errorf("agent config: %w", err)
	}
	c.TrustControlCA()

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
	statusTok, err := state.WriteStatusToken(dir)
	if err != nil {
		return fmt.Errorf("status token: %w", err)
	}

	keyFile := filepath.Join(dir, "authkey")
	key, _ := os.ReadFile(keyFile)
	authKey := strings.TrimSpace(string(key))
	node := mesh.NewNode(dir, c, authKey)
	defer node.Close()

	a := newAgent(c, node)
	a.configBase = filepath.Dir(dir)
	a.statusToken = statusTok
	if exe, err := fsutil.ResolvedExePath(); err == nil {
		a.binSHA256, _ = fsutil.FileSHA256(exe)
	}

	// Serve the proxy straight away, so the setup step can watch us come up.
	srv := &http.Server{Handler: a, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	logger := fsutil.DaemonLogger()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		st, err := mesh.UpNode(ctx, node, authKey != "")
		a.mu.Lock()
		defer a.mu.Unlock()
		if err != nil {
			a.err = err.Error()
			logger.Error("could not join pen", "zone", c.Zone, "err", err)
			return
		}
		_ = os.Remove(keyFile) // single use, and now spent
		for _, ip := range st.TailscaleIPs {
			a.ips = append(a.ips, ip.String())
		}
		a.up = true
		logger.Info("agent online", "zone", c.Zone, "ips", strings.Join(a.ips, ", "))
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
	cfg         *state.AgentConfig
	configBase  string
	statusToken string
	binSHA256   string
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

func newAgent(c *state.AgentConfig, node *tsnet.Server) *agent {
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
				found, ok := mesh.ResolvePenDNSIP(st, c.DNSServer)
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
			// Mesh policy and authoritative pen DNS are IPv4-only; request A
			// records directly so every dial does not send a wasted AAAA query.
			ips, err := a.resolver.LookupIP(ctx, "ip4", host)
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(ips))
			for _, ip := range ips {
				if addr, ok := netip.AddrFromSlice(ip); ok {
					addr = addr.Unmap()
					if addr.Is4() {
						out = append(out, addr.String())
					}
				}
			}
			return out, nil
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
			up, needsLogin, reason := mesh.EvaluateLiveNodeStatus(st, c.DNSServer)
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
		for _, raw := range p.TailscaleIPs {
			ip := raw.Unmap()
			if ip.Is4() {
				out = append(out, ip.String())
			}
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
	Enrolled   bool     `json:"enrolled,omitempty"` // true once upNode succeeded on the control plane
	NeedsLogin bool     `json:"needs_login,omitempty"`
	Error      string   `json:"error,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	Server     bool     `json:"server,omitempty"` // the pen tagged this device a server (refused)
	BinSHA256  string   `json:"bin_sha256,omitempty"`
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
	if !a.cfg.InZone(host) {
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
	if !link.InMeshRanges(ip) {
		return false
	}
	if a.isPeer == nil {
		return true
	}
	return a.isPeer(ctx, ip)
}

func (a *agent) pac() string {
	if a.configBase != "" {
		return state.RenderPAC(state.NormalizePenConfigs(state.LoadInstalledPenConfigs(a.configBase), a.cfg))
	}
	return a.cfg.PAC()
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
		st := agentStatus{Zone: a.cfg.Zone, Up: a.up, Enrolled: a.up, Error: a.err, IPs: a.ips, Server: a.server, BinSHA256: a.binSHA256}
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
				w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(a.statusToken, nonce, a.cfg.Zone))
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
	if !a.cfg.InZone(host) {
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
// own process (see main) so TrustControlCA can take effect.
func agentLogout(dir string) {
	c, err := state.LoadAgentConfig(dir)
	if err != nil {
		return
	}
	c.TrustControlCA()
	node := mesh.NewNode(dir, c, "")
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := mesh.UpNode(ctx, node, false); err != nil {
		return
	}
	if lc, err := node.LocalClient(); err == nil {
		_ = lc.Logout(ctx)
	}
}
