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

	a := &agent{cfg: c, node: node}
	a.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return node.Dial(ctx, network, net.JoinHostPort(c.DNSServer, "53"))
	}}

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
	cfg      *agentConfig
	node     *tsnet.Server
	resolver *net.Resolver

	mu  sync.Mutex
	up  bool
	err string
	ips []string
}

type agentStatus struct {
	Zone  string   `json:"zone"`
	Up    bool     `json:"up"`
	Error string   `json:"error,omitempty"`
	IPs   []string `json:"ips,omitempty"`
}

// dial opens a connection to a pen host. Anything outside the pen is refused:
// this is not a general-purpose proxy.
func (a *agent) dial(ctx context.Context, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		for _, r := range meshRanges {
			if r.Contains(ip) {
				return a.node.Dial(ctx, "tcp", hostport)
			}
		}
		return nil, errOutside
	}
	if !a.cfg.inZone(host) {
		return nil, errOutside
	}
	ips, err := a.resolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("no such name in the pen: %s", host)
	}
	return a.node.Dial(ctx, "tcp", net.JoinHostPort(ips[0], port))
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
		st := agentStatus{Zone: a.cfg.Zone, Up: a.up, Error: a.err, IPs: a.ips}
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st)
	default:
		http.NotFound(w, r)
	}
}

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
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, buf); done <- struct{}{} }()
	go func() { _, _ = io.Copy(down, up); done <- struct{}{} }()
	<-done
}

// forward handles plain-HTTP requests sent through the proxy.
func (a *agent) forward(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}
	if h, _, _ := net.SplitHostPort(host); !a.cfg.inZone(h) {
		if ip, err := netip.ParseAddr(h); err != nil || !(meshRanges[0].Contains(ip) || meshRanges[1].Contains(ip)) {
			http.Error(w, errOutside.Error(), http.StatusForbidden)
			return
		}
	}
	rp := &httputil.ReverseProxy{
		Director: func(*http.Request) {},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return a.dial(ctx, addr) },
		},
	}
	rp.ServeHTTP(w, r)
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
