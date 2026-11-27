package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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

// Status is the JSON payload served by the local agent's /status endpoint.
type Status struct {
	Zone       string   `json:"zone"`
	Up         bool     `json:"up"`
	Enrolled   bool     `json:"enrolled,omitempty"` // true once UpNode succeeded on the control plane
	NeedsLogin bool     `json:"needs_login,omitempty"`
	Error      string   `json:"error,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	Server     bool     `json:"server,omitempty"` // the pen tagged this device a server (refused)
	BinSHA256  string   `json:"bin_sha256,omitempty"`
}

// JoinError marks a fatal startup or NeedsLogin error reported by a running agent.
type JoinError struct{ Msg string }

func (e *JoinError) Error() string { return e.Msg }

// Run is the long-running pen agent process: connect to the pen, serve the
// local HTTPS proxy, /proxy.pac, and authenticated /status endpoint.
func Run(dir string) error {
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

	a := New(c, node)
	a.ConfigBase = filepath.Dir(dir)
	a.StatusToken = statusTok
	if exe, err := fsutil.ResolvedExePath(); err == nil {
		a.BinSHA256, _ = fsutil.FileSHA256(exe)
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

// Agent serves the per-pen loopback HTTPS CONNECT proxy, /proxy.pac, and /status.
type Agent struct {
	Cfg         *state.AgentConfig
	ConfigBase  string
	StatusToken string
	BinSHA256   string
	Node        *tsnet.Server
	resolver    *net.Resolver
	DialMesh    func(ctx context.Context, network, addr string) (net.Conn, error)
	LookupDNS   func(ctx context.Context, host string) ([]string, error)
	PeerLookup  func(ctx context.Context, host string) ([]string, error)
	// IsPeer reports whether ip belongs to a device this pen's node knows.
	// Only those may be dialed: tsnet's Dial quietly uses the computer's own
	// network for anything else, so a pen whose DNS answered 127.0.0.1, a LAN
	// address or another tailnet's 100.x address would otherwise reach it.
	IsPeer     func(ctx context.Context, ip netip.Addr) bool
	LiveStatus func(ctx context.Context) (up bool, needsLogin bool, reason string, ok bool)

	mu     sync.Mutex
	up     bool
	err    string
	ips    []string
	server bool
}

// New constructs an Agent backed by node (node may be nil in unit tests).
func New(c *state.AgentConfig, node *tsnet.Server) *Agent {
	a := &Agent{Cfg: c, Node: node}
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
		a.DialMesh = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return node.Dial(ctx, network, addr)
		}
		a.LookupDNS = func(ctx context.Context, host string) ([]string, error) {
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
		a.IsPeer = func(ctx context.Context, ip netip.Addr) bool {
			lc, err := node.LocalClient()
			if err != nil {
				return false
			}
			_, err = lc.WhoIs(ctx, ip.String())
			return err == nil
		}
		a.PeerLookup = func(ctx context.Context, host string) ([]string, error) {
			lc, err := node.LocalClient()
			if err != nil {
				return nil, err
			}
			st, err := lc.Status(ctx)
			if err != nil {
				return nil, err
			}
			return PeerIPsForHost(st, host), nil
		}
		a.LiveStatus = func(ctx context.Context) (bool, bool, string, bool) {
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

// SetReady sets the agent's latched ready state and IPs (used by tests).
func (a *Agent) SetReady(up bool, ips []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.up = up
	a.ips = append([]string(nil), ips...)
}

// PeerIPsForHost returns IPv4 tailnet addresses for the peer matching host.
func PeerIPsForHost(st *ipnstate.Status, host string) []string {
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

// Dial opens a connection to a pen host. Anything outside the pen is refused:
// this is not a general-purpose proxy.
func (a *Agent) Dial(ctx context.Context, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if a.allowed(ctx, ip) {
			// Dial the unmapped form: tsnet looks peers up by the exact
			// address, so ::ffff:<peer> would miss and fall back to the host.
			return a.DialMesh(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
		}
		return nil, errOutside
	}
	if !a.Cfg.InZone(host) {
		return nil, errOutside
	}
	var ips []string
	if a.LookupDNS != nil {
		ips, _ = a.LookupDNS(ctx, host)
	}
	norm := strings.ToLower(strings.TrimSuffix(host, "."))
	if len(ips) == 0 && strings.HasSuffix(norm, ".nodes."+a.Cfg.Zone) && a.PeerLookup != nil {
		if pips, perr := a.PeerLookup(ctx, host); perr == nil {
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
		conn, derr := a.DialMesh(ctx, "tcp", net.JoinHostPort(ip, port))
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
func (a *Agent) allowed(ctx context.Context, ip netip.Addr) bool {
	ip = ip.Unmap()
	if !link.InMeshRanges(ip) {
		return false
	}
	if a.IsPeer == nil {
		return true
	}
	return a.IsPeer(ctx, ip)
}

func (a *Agent) pac() string {
	if a.ConfigBase != "" {
		return state.RenderPAC(state.NormalizePenConfigs(state.LoadInstalledPenConfigs(a.ConfigBase), a.Cfg))
	}
	return a.Cfg.PAC()
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

func (a *Agent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		st := Status{Zone: a.Cfg.Zone, Up: a.up, Enrolled: a.up, Error: a.err, IPs: a.ips, Server: a.server, BinSHA256: a.BinSHA256}
		a.mu.Unlock()
		if st.Up && a.LiveStatus != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			liveUp, needsLogin, liveErr, ok := a.LiveStatus(ctx)
			cancel()
			if ok && !liveUp {
				st.Up = false
				st.NeedsLogin = needsLogin
				st.Error = liveErr
			}
		}
		if a.StatusToken != "" {
			if nonce := strings.TrimSpace(r.Header.Get("X-Hogman-Challenge")); nonce != "" && len(nonce) <= 128 {
				w.Header().Set("X-Hogman-Proof", state.ComputeStatusProof(a.StatusToken, nonce, a.Cfg.Zone))
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
func (a *Agent) localHost(host string) bool {
	_, port, err := net.SplitHostPort(a.Cfg.ProxyAddr)
	if err != nil {
		return false
	}
	return host == a.Cfg.ProxyAddr || host == "localhost:"+port || host == "[::1]:"+port
}

// connect handles "CONNECT host:443", which is how browsers reach HTTPS sites
// through a proxy. The proxy only moves bytes; TLS stays end to end.
func (a *Agent) connect(w http.ResponseWriter, r *http.Request) {
	if !webPort(r.Host) {
		http.Error(w, errPort.Error(), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	up, err := a.Dial(ctx, r.Host)
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
func (a *Agent) forward(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.URL.Scheme, "http") {
		http.Error(w, "use CONNECT for HTTPS", http.StatusForbidden)
		return
	}
	host := r.URL.Hostname()
	if !a.Cfg.InZone(host) {
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

// Logout tells the pen this device is leaving. Best effort. Runs in its
// own process so TrustControlCA can take effect.
func Logout(dir string) {
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

// PickLocalAddr chooses a random port outside the OS ephemeral range
// (17000-26999), scanning forward if that port is in use, so remote web pages
// cannot predict a pen's loopback proxy port from its zone name.
func PickLocalAddr(_ string) (string, error) {
	const basePort = state.PortMin
	const span = state.PortMax - state.PortMin + 1
	var rb [4]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return "", fmt.Errorf("pick local port: %w", err)
	}
	start := int(binary.BigEndian.Uint32(rb[:]) % span)
	for i := 0; i < span; i++ {
		port := basePort + (start+i)%span
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		_ = l.Close()
		return l.Addr().String(), nil
	}
	return "", fmt.Errorf("no free local port in %d-%d", basePort, basePort+span-1)
}

// PickPACHost picks the best pen agent to serve the combined /proxy.pac URL,
// preferring an up agent, then any verified responding agent, then remaining[0].
func PickPACHost(remaining []*state.AgentConfig) *state.AgentConfig {
	if len(remaining) == 0 {
		return nil
	}
	for _, p := range remaining {
		if st, err := State(p); err == nil && st.Up {
			return p
		}
	}
	for _, p := range remaining {
		if _, err := State(p); err == nil {
			return p
		}
	}
	return remaining[0]
}

// HasLegacyPenBinary reports whether dir still holds a legacy per-pen hogman-join copy.
func HasLegacyPenBinary(dir string) bool {
	p := filepath.Join(dir, state.LegacyBinaryName(runtime.GOOS))
	_, err := os.Stat(p)
	return err == nil
}

// CurrentHealthy reports whether the pen's agent is already up, passes HMAC
// status verification, and is NOT accompanied by a legacy per-pen hogman-join
// copy that still needs replacing.
func CurrentHealthy(dir string, c *state.AgentConfig) bool {
	if c == nil || HasLegacyPenBinary(dir) {
		return false
	}
	st, err := StateInDir(dir, c)
	return err == nil && st.Up
}

// WaitUp polls the agent's authenticated /status endpoint until it reports Up
// or fails with a JoinError or timeout.
func WaitUp(c *state.AgentConfig, d time.Duration) (*Status, error) {
	return WaitUpCtx(context.Background(), c, d)
}

// WaitUpCtx polls the agent's authenticated /status endpoint until it reports
// Up, fails fatally, ctx is cancelled, or d elapses.
func WaitUpCtx(ctx context.Context, c *state.AgentConfig, d time.Duration) (*Status, error) {
	deadline := time.Now().Add(d)
	lastStatusErr := ""
	for {
		st, err := State(c)
		if err == nil && st.Up {
			return st, nil
		}
		if err == nil && st.Error != "" {
			// Only abort immediately on a fatal startup error (!Enrolled, e.g.
			// rejected authkey) or an explicit NeedsLogin rejection. Once the
			// device has enrolled (st.Enrolled), "not connected to pen" is a
			// transient state while the registrar's Sync loop adds this device's
			// IP to Headscale's ACL policy.
			if !st.Enrolled || st.NeedsLogin {
				return nil, &JoinError{Msg: fmt.Sprintf("could not join the pen: %s", st.Error)}
			}
			lastStatusErr = st.Error
		}
		if err := ctx.Err(); err != nil {
			return nil, link.Errorf("cancelled before the pen connection came up (saved credentials were kept; re-run the same command to resume)")
		}
		if time.Now().After(deadline) {
			if lastStatusErr != "" {
				return nil, link.Errorf("enrolled on %s, but the pen connection did not come up within %s (last status: %s).\n  Saved credentials were kept so this device is not orphaned; re-run hogman to retry, or run 'hogman leave %s' to remove it.\n  Log: %s", c.Zone, d, lastStatusErr, c.Zone, filepath.Join(state.StateDir(c.Zone), "agent.log"))
			}
			return nil, link.Errorf("the pen connection did not come up within %s. Log: %s", d, filepath.Join(state.StateDir(c.Zone), "agent.log"))
		}
		select {
		case <-ctx.Done():
			return nil, link.Errorf("cancelled before the pen connection came up (saved credentials were kept; re-run the same command to resume)")
		case <-time.After(time.Second):
		}
	}
}
