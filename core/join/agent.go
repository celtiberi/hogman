package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
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
	DNSServer   string `json:"dns_server"` // mesh address of the pen's DNS
	Hostname    string `json:"hostname"`
	ProxyAddr   string `json:"proxy_addr"` // 127.0.0.1:<port>
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
func (c *agentConfig) pac() string {
	return fmt.Sprintf(`// Hogman: only names in %[1]s use the pen. Everything else is untouched.
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (host === "%[1]s" || dnsDomainIs(host, ".%[1]s")) return "PROXY %[2]s";
  return "DIRECT";
}
`, c.Zone, c.ProxyAddr)
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

// runAgent is the long-running process: connect to the pen, serve the proxy.
func runAgent(dir string) error {
	c, err := loadAgentConfig(dir)
	if err != nil {
		return fmt.Errorf("agent config: %w", err)
	}
	c.trustControlCA()
	_ = os.WriteFile(filepath.Join(dir, "agent.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600)
	defer os.Remove(filepath.Join(dir, "agent.pid"))

	keyFile := filepath.Join(dir, "authkey")
	key, _ := os.ReadFile(keyFile)
	node := newNode(dir, c, strings.TrimSpace(string(key)))
	defer node.Close()

	a := newAgent(c, node)

	// Serve the proxy straight away, so the setup step can watch us come up.
	ln, err := net.Listen("tcp", c.ProxyAddr)
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	srv := &http.Server{Handler: a, ReadHeaderTimeout: 15 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		st, err := node.Up(ctx)
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
		// A server hosts sites: pass the pen's web ports to this computer, where
		// Caddy (or anything else) listens. Personal devices get no visitors
		// (the pen's access rules refuse them), so they don't need it.
		if st.Self != nil && st.Self.Tags != nil {
			for _, t := range st.Self.Tags.All() {
				if t == "tag:server" {
					a.server = true
				}
			}
		}
		if a.server {
			for _, port := range []string{"80", "443"} {
				go forwardPort(node, port)
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

// forwardPort passes connections to the pen's port to the same port on this
// computer, untouched (TLS stays end to end, so Caddy here gets its HTTP-01
// and TLS-ALPN challenges and its visitors as if it were on the mesh itself).
func forwardPort(node *tsnet.Server, port string) {
	ln, err := node.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("cannot take the pen's port %s: %v", port, err)
		return
	}
	for {
		in, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer in.Close()
			out, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
			if err != nil {
				log.Printf("a visitor came to port %s, but nothing listens on 127.0.0.1:%s", port, port)
				return
			}
			defer out.Close()
			done := make(chan struct{}, 2)
			pipe := func(dst, src net.Conn) {
				_, _ = io.Copy(dst, src)
				if cw, ok := dst.(closeWriter); ok {
					_ = cw.CloseWrite()
				}
				done <- struct{}{}
			}
			go pipe(out, in)
			go pipe(in, out)
			<-done
			<-done
		}()
	}
}

type agent struct {
	cfg        *agentConfig
	node       *tsnet.Server
	resolver   *net.Resolver
	rp         *httputil.ReverseProxy
	dialMesh   func(ctx context.Context, network, addr string) (net.Conn, error)
	lookupDNS  func(ctx context.Context, host string) ([]string, error)
	peerLookup func(ctx context.Context, host string) ([]string, error)

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
			return node.Dial(ctx, network, net.JoinHostPort(c.DNSServer, "53"))
		}}
		a.dialMesh = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return node.Dial(ctx, network, addr)
		}
		a.lookupDNS = func(ctx context.Context, host string) ([]string, error) {
			return a.resolver.LookupHost(ctx, host)
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
	}
	a.rp = &httputil.ReverseProxy{
		Director: func(*http.Request) {},
		Transport: &http.Transport{
			DialContext:     func(ctx context.Context, _, addr string) (net.Conn, error) { return a.dial(ctx, addr) },
			IdleConnTimeout: 30 * time.Second,
		},
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
	Zone   string   `json:"zone"`
	Up     bool     `json:"up"`
	Error  string   `json:"error,omitempty"`
	IPs    []string `json:"ips,omitempty"`
	Server bool     `json:"server,omitempty"` // a server: the pen's 80/443 reach this computer
}

// dial opens a connection to a pen host. Anything outside the pen is refused:
// this is not a general-purpose proxy.
func (a *agent) dial(ctx context.Context, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if inMeshRanges(ip) {
			return a.dialMesh(ctx, "tcp", hostport)
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
	ordered := orderIPs(ips)
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

func (a *agent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		a.connect(w, r)
	case r.URL.IsAbs():
		a.forward(w, r)
	case r.URL.Path == "/proxy.pac":
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		_, _ = io.WriteString(w, a.cfg.pac())
	case r.URL.Path == "/status":
		a.mu.Lock()
		st := agentStatus{Zone: a.cfg.Zone, Up: a.up, Error: a.err, IPs: a.ips, Server: a.server}
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st)
	default:
		http.NotFound(w, r)
	}
}

type closeWriter interface{ CloseWrite() error }

// connect handles "CONNECT host:443", which is how browsers reach HTTPS sites
// through a proxy. The proxy only moves bytes; TLS stays end to end.
func (a *agent) connect(w http.ResponseWriter, r *http.Request) {
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

// forward handles plain-HTTP requests sent through the proxy.
func (a *agent) forward(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.URL.Scheme, "http") {
		http.Error(w, "use CONNECT for HTTPS", http.StatusForbidden)
		return
	}
	host := r.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}
	if h, _, _ := net.SplitHostPort(host); !a.cfg.inZone(h) {
		if ip, err := netip.ParseAddr(h); err != nil || !inMeshRanges(ip) {
			http.Error(w, errOutside.Error(), http.StatusForbidden)
			return
		}
	}
	a.rp.ServeHTTP(w, r)
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := node.Up(ctx); err != nil {
		return
	}
	if lc, err := node.LocalClient(); err == nil {
		_ = lc.Logout(ctx)
	}
}
