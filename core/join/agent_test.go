package main

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"

	"hogman/join/internal/link"
	"hogman/join/internal/mesh"
	"hogman/join/internal/penapi"
	"hogman/join/internal/state"
)

func TestPickLocalAddr(t *testing.T) {
	seen := map[string]bool{}
	var a1 string
	for i := 0; i < 8; i++ {
		addr, err := pickLocalAddr("bobo.hogman")
		if err != nil {
			t.Fatal(err)
		}
		if a1 == "" {
			a1 = addr
		}
		seen[addr] = true
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 17000 || port >= 27000 {
			t.Fatalf("port %d out of [17000, 27000)", port)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("pickLocalAddr should randomize ports per install, got only %v", seen)
	}

	// Occupy one port and verify pickLocalAddr returns a different free port in range.
	ln, err := net.Listen("tcp", a1)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	a3, err := pickLocalAddr("bobo.hogman")
	if err != nil {
		t.Fatal(err)
	}
	if a3 == a1 {
		t.Fatalf("expected fallback port when %s is occupied", a1)
	}
	_, portStr3, _ := net.SplitHostPort(a3)
	port3, _ := strconv.Atoi(portStr3)
	if port3 < 17000 || port3 >= 27000 {
		t.Fatalf("fallback port %d out of [17000, 27000)", port3)
	}
}

func TestAgentConnectHalfClose(t *testing.T) {
	// Target TCP server reads until client half-closes (EOF), then sends its reply.
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, _ := io.ReadAll(c)
				_, _ = io.WriteString(c, "reply:"+string(req))
			}(c)
		}
	}()

	cfg := &state.AgentConfig{Zone: "bobo.hogman"}
	a := newAgent(cfg, nil)
	a.lookupDNS = func(context.Context, string) ([]string, error) {
		return []string{"100.64.0.50"}, nil
	}
	a.dialMesh = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "100.64.0.50:443" {
			t.Errorf("unexpected mesh target %q", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, targetLn.Addr().String())
	}

	proxySrv := httptest.NewServer(a)
	defer proxySrv.Close()

	rawConn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()

	_, err = io.WriteString(rawConn, "CONNECT alice.bobo.hogman:443 HTTP/1.1\r\nHost: alice.bobo.hogman:443\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	if _, err := io.WriteString(rawConn, "hello-half-close"); err != nil {
		t.Fatal(err)
	}
	if err := rawConn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "reply:hello-half-close" {
		t.Fatalf("got %q, want %q", string(got), "reply:hello-half-close")
	}
}

func TestAgentConnectAndForwardZoneGuards(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok:"+r.Host)
	}))
	defer backend.Close()

	cfg := &state.AgentConfig{Zone: "bobo.hogman"}
	a := newAgent(cfg, nil)
	a.lookupDNS = func(_ context.Context, host string) ([]string, error) {
		if host == "alice.bobo.hogman" {
			return []string{"100.64.0.51"}, nil
		}
		return nil, io.EOF
	}
	a.dialMesh = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
	}

	proxySrv := httptest.NewServer(a)
	defer proxySrv.Close()
	pu, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}

	// Outside domains and public IPs must be refused with 403 on both CONNECT and HTTP forward.
	for _, target := range []string{"http://example.com/", "http://8.8.8.8/"} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GET %s status=%d want 403", target, resp.StatusCode)
		}
	}

	for _, target := range []string{"example.com:443", "8.8.8.8:443"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodConnect, target, nil)
		req.Host = target
		a.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("CONNECT %s status=%d want 403", target, rec.Code)
		}
	}

	// HTTPS only (D-11): pen names on any port but 443 are refused, :80 included.
	for _, target := range []string{"alice.bobo.hogman:22", "alice.bobo.hogman:80", "alice.bobo.hogman:8080", "alice.bobo.hogman:9000"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodConnect, target, nil)
		req.Host = target
		a.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("CONNECT %s status=%d want 403", target, rec.Code)
		}
	}

	// Plain HTTP to a pen name is answered by the agent itself with a redirect
	// to HTTPS; nothing is dialed.
	dialled := false
	a.dialMesh = func(context.Context, string, string) (net.Conn, error) { dialled = true; return nil, io.EOF }
	noFollow := &http.Client{
		Transport:     &http.Transport{Proxy: http.ProxyURL(pu)},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noFollow.Get("http://alice.bobo.hogman/photos?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "https://alice.bobo.hogman/photos?x=1" {
		t.Fatalf("http:// status=%d location=%q, want 308 to https", resp.StatusCode, resp.Header.Get("Location"))
	}
	if dialled {
		t.Fatal("plain HTTP was dialed into the pen")
	}
	if resp, err := noFollow.Get("http://alice.bobo.hogman:8080/"); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GET :8080 status=%d want 403", resp.StatusCode)
		}
	}
}

func TestAgentDialNodesMagicDNSFallback(t *testing.T) {
	cfg := &state.AgentConfig{Zone: "bobo.hogman"}
	a := newAgent(cfg, nil)

	st := &ipnstate.Status{
		Self: &ipnstate.PeerStatus{
			DNSName:      "dave-laptop.nodes.bobo.hogman.",
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.99")},
		},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			{}: {
				DNSName: "alice-server.nodes.bobo.hogman.",
				TailscaleIPs: []netip.Addr{
					netip.MustParseAddr("fd7a:115c:a1e0::12"),
					netip.MustParseAddr("100.64.0.12"),
				},
			},
		},
	}

	a.lookupDNS = func(context.Context, string) ([]string, error) {
		return nil, io.EOF // CoreDNS does not serve .nodes.<zone>
	}
	a.peerLookup = func(_ context.Context, host string) ([]string, error) {
		return peerIPsForHost(st, host), nil
	}
	var dialed string
	a.dialMesh = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}

	conn, err := a.dial(context.Background(), "alice-server.nodes.bobo.hogman:8080")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if dialed != "100.64.0.12:8080" {
		t.Fatalf("dialed %q, want IPv4 peer 100.64.0.12:8080", dialed)
	}
	if ips := peerIPsForHost(st, "alice-server.nodes.bobo.hogman"); len(ips) != 1 || ips[0] != "100.64.0.12" {
		t.Fatalf("peerIPsForHost returned %v, want IPv4-only [100.64.0.12]", ips)
	}
}

func TestParseAutoProxyOutput(t *testing.T) {
	cases := []struct {
		in      string
		wantURL string
		wantOn  bool
	}{
		{"URL: http://127.0.0.1:18123/proxy.pac\nEnabled: Yes\n", "http://127.0.0.1:18123/proxy.pac", true},
		{"URL: http://127.0.0.1:18123/proxy.pac\nEnabled: No\n", "http://127.0.0.1:18123/proxy.pac", false},
		{"URL: (null)\nEnabled: No\n", "", false},
	}
	for _, tc := range cases {
		u, on := parseAutoProxyOutput(tc.in)
		if u != tc.wantURL || on != tc.wantOn {
			t.Fatalf("parseAutoProxyOutput(%q) = (%q, %v), want (%q, %v)", tc.in, u, on, tc.wantURL, tc.wantOn)
		}
	}
}

func TestValidPACProxyAddrLoopbackOnly(t *testing.T) {
	for _, valid := range []string{
		"127.0.0.1:18123",
		"127.0.0.2:18123",
		"[::1]:18123",
		"localhost:18123",
	} {
		if !state.ValidPACProxyAddr(valid) {
			t.Fatalf("state.ValidPACProxyAddr(%q) = false, want true", valid)
		}
	}
	for _, bad := range []string{
		"10.0.0.5:18123",
		"192.168.1.10:18123",
		"100.64.0.5:18123",
		"198.51.100.1:8080",
		"[2001:db8::1]:8080",
		"0.0.0.0:18123",
		"[::]:18123",
		"[::1%lo0]:18123",
		"evil.example:8080",
		"127.0.0.1:0",
		"127.0.0.1:65536",
	} {
		if state.ValidPACProxyAddr(bad) {
			t.Fatalf("state.ValidPACProxyAddr(%q) = true, want false", bad)
		}
	}
}

func TestShouldLeaveAutoProxy(t *testing.T) {
	p1 := &state.AgentConfig{Zone: "bobo.hogman", ProxyAddr: "127.0.0.1:18123"}
	p2 := &state.AgentConfig{Zone: "zebra.hogman", ProxyAddr: "127.0.0.1:18124"}
	tampered := &state.AgentConfig{Zone: "evil.hogman", ProxyAddr: "198.51.100.1:8080"}
	known := []*state.AgentConfig{p1, p2, tampered}
	if !shouldLeaveAutoProxy("http://corp.example/proxy.pac", true, known) {
		t.Fatal("must leave active corporate /proxy.pac alone")
	}
	if !shouldLeaveAutoProxy("http://198.51.100.1:8080/proxy.pac", true, known) {
		t.Fatal("must not claim non-loopback proxy as Hogman")
	}
	if !shouldLeaveAutoProxy("http://127.0.0.1:19999/proxy.pac", true, known) {
		t.Fatal("must leave unknown local port /proxy.pac alone")
	}
	if !shouldLeaveAutoProxy("https://127.0.0.1:18123/proxy.pac", true, known) {
		t.Fatal("must leave non-http scheme PAC alone")
	}
	if !shouldLeaveAutoProxy("http://127.0.0.1:18123/other.pac", true, known) {
		t.Fatal("must leave non-/proxy.pac path alone")
	}
	if shouldLeaveAutoProxy("http://127.0.0.1:19999/proxy.pac", false, known) {
		t.Fatal("disabled leftover PAC should not block setup")
	}
	if shouldLeaveAutoProxy(p1.PACURL(), true, known) {
		t.Fatal("legacy Hogman pen PAC should not be flagged as foreign")
	}
	if shouldLeaveAutoProxy(p2.PACURL()+"?v=deadbeef", true, known) {
		t.Fatal("versioned Hogman pen PAC should not be flagged as foreign")
	}
}

func TestRenderLaunchPlist(t *testing.T) {
	p, err := renderLaunchPlist(
		"network.hogman.bobo.hogman",
		"/tmp/a&b<c>/hogman",
		"/tmp/dir&1/bobo.hogman",
		"/tmp/dir&1/bobo.hogman/agent.log",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, "/tmp/a&amp;b&lt;c&gt;/hogman") {
		t.Fatalf("expected XML-escaped path in plist:\n%s", p)
	}
	var parsed any
	if err := xml.Unmarshal([]byte(p), &parsed); err != nil {
		t.Fatalf("rendered plist is not valid XML: %v\n%s", err, p)
	}
}

func TestFetchNetworkValidation(t *testing.T) {
	var payload penapi.NetworkInfo
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()
	host := "bobo.gate.example.com"
	baseTransport := srv.Client().Transport
	srvAddr := strings.TrimPrefix(srv.URL, "https://")
	c := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			r2 := req.Clone(req.Context())
			r2.URL.Host = srvAddr
			return baseTransport.RoundTrip(r2)
		}),
	}

	baseValid := penapi.NetworkInfo{
		Zone:        "bobo.pens.example.com",
		LoginServer: "https://" + host,
		CertMode:    "public",
		Portal:      "https://home.bobo.pens.example.com",
		DNSServer:   "100.64.0.2",
	}
	payload = baseValid
	if _, err := penapi.FetchNetwork(c, host); err != nil {
		t.Fatalf("valid public networkInfo rejected: %v", err)
	}
	payload.CertMode = ""
	if _, err := penapi.FetchNetwork(c, host); err != nil {
		t.Fatalf("public networkInfo with omitted cert_mode rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*penapi.NetworkInfo)
	}{
		{"private cert_mode", func(n *penapi.NetworkInfo) { n.CertMode = "private" }},
		{"unknown cert_mode", func(n *penapi.NetworkInfo) { n.CertMode = "bogus" }},
		{"cross-pen zone", func(n *penapi.NetworkInfo) {
			n.Zone = "alice.pens.example.com"
			n.Portal = "https://home.alice.pens.example.com"
		}},
		{"non-public zone", func(n *penapi.NetworkInfo) { n.Zone = "bobo.hogman"; n.Portal = "https://home.bobo.hogman" }},
		{"mismatched login_server", func(n *penapi.NetworkInfo) { n.LoginServer = "https://evil.example" }},
		{"foreign portal", func(n *penapi.NetworkInfo) { n.Portal = "https://evil.example/phish" }},
		{"non-mesh dns_server", func(n *penapi.NetworkInfo) { n.DNSServer = "8.8.8.8" }},
	}
	for _, tc := range cases {
		bad := baseValid
		tc.mutate(&bad)
		payload = bad
		if _, err := penapi.FetchNetwork(c, host); err == nil {
			t.Errorf("%s: expected fetchNetwork to reject payload", tc.name)
		}
		payload = baseValid
	}
}

func TestValidatePublicZoneAndNetworkInfo(t *testing.T) {
	hostedOK := []struct {
		host string
		zone string
	}{
		{"bobo.gate.example.com", "bobo.pens.example.com"},
		{"bobo.gate.example.com:8443", "bobo.pens.example.com"},
		{"bobo.gate.hogman.test", "bobo.pens.hogman.test"},
		{"hs.example.com", "bobo.example.com"},
		{"gate.hogman.test", "bobo.pens.hogman.test"},
		{"login.corp.example.co.uk", "bobo.example.co.uk"},
	}
	for _, tc := range hostedOK {
		if err := link.ValidatePublicZone(tc.host, tc.zone); err != nil {
			t.Errorf("link.ValidatePublicZone(%q, %q) unexpected error: %v", tc.host, tc.zone, err)
		}
	}

	hostedBad := []struct {
		host string
		zone string
	}{
		{"bobo.gate.example.com", "alice.pens.example.com"},
		{"bobo.gate.example.com", "bobo.other.example.com"},
		{"bobo.gate.example.com", "bobo.example.com"},
		{"bobo.gate.example.com", "example.com"},
		{"bobo.gate.example.com", "bobo.hogman"},
		{"evil.gate.co.uk", "evil.pens.co.uk"},
		{"hs.example.com", "example.com"},
		{"hs.example.com", "bobo.other.com"},
		{"hs.example.com", "bobo.hogman"},
		{"hs.example.com", "Bobo.example.com"},
		{"hs.example.com", "bobo.example.com."},
		{"127.0.0.1:8443", "bobo.example.com"},
	}
	for _, tc := range hostedBad {
		if err := link.ValidatePublicZone(tc.host, tc.zone); err == nil {
			t.Errorf("link.ValidatePublicZone(%q, %q) expected error, got nil", tc.host, tc.zone)
		}
	}
}

func TestAgentForwardRejectsHTTPSScheme(t *testing.T) {
	a := newAgent(&state.AgentConfig{Zone: "bobo.hogman"}, nil)
	req := httptest.NewRequest(http.MethodGet, "https://alice.bobo.hogman/", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET https:// through forward proxy: status=%d want 403", rec.Code)
	}
}

func TestRenderSystemdUnitQuotesSpaces(t *testing.T) {
	u := renderSystemdUnit("bobo.hogman", `/opt/my bin/hogman`, `/home/a user/.config/hogman/bobo.hogman`)
	want := `ExecStart="/opt/my bin/hogman" agent "/home/a user/.config/hogman/bobo.hogman"`
	if !strings.Contains(u, want) {
		t.Fatalf("unit missing quoted ExecStart %q:\n%s", want, u)
	}
}

// A hostile pen's DNS can answer anything. Only the pen's own devices may be
// dialed: never loopback, the LAN, or a 100.x address of another tailnet
// (tsnet's Dial would reach those through the computer's own network).
func TestAgentDialsOnlyPenDevices(t *testing.T) {
	a := newAgent(&state.AgentConfig{Zone: "bobo.hogman"}, nil)
	peer := netip.MustParseAddr("100.70.0.5")
	a.isPeer = func(_ context.Context, ip netip.Addr) bool { return ip == peer }
	answers := map[string][]string{
		"evil.bobo.hogman":  {"127.0.0.1", "192.168.1.1", "::ffff:127.0.0.1", "100.99.0.9", "100.70.0.5"},
		"local.bobo.hogman": {"127.0.0.1", "::ffff:127.0.0.1"},
		"work.bobo.hogman":  {"100.99.0.9"},
	}
	a.lookupDNS = func(_ context.Context, host string) ([]string, error) { return answers[host], nil }
	var dialed []string
	a.dialMesh = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		c1, c2 := net.Pipe()
		go c2.Close()
		return c1, nil
	}
	ctx := context.Background()

	if c, err := a.dial(ctx, "evil.bobo.hogman:443"); err != nil {
		t.Fatalf("evil: %v", err)
	} else {
		c.Close()
	}
	if len(dialed) != 1 || dialed[0] != "100.70.0.5:443" {
		t.Fatalf("dialed %v, want only the pen's own device 100.70.0.5:443", dialed)
	}
	for _, target := range []string{"local.bobo.hogman:80", "work.bobo.hogman:80", "100.99.0.9:22", "127.0.0.1:22", "[::ffff:127.0.0.1]:22"} {
		dialed = nil
		if c, err := a.dial(ctx, target); err == nil {
			c.Close()
			t.Fatalf("%s: dial allowed, dialed %v", target, dialed)
		}
		if len(dialed) != 0 {
			t.Fatalf("%s: dialed %v", target, dialed)
		}
	}
}

// An IPv4-mapped form of a real peer must be dialed unmapped: tsnet looks
// peers up by the exact address, and the mapped form would miss and fall
// back to the host network.
func TestAgentDialsUnmapped(t *testing.T) {
	a := newAgent(&state.AgentConfig{Zone: "bobo.hogman"}, nil)
	peer := netip.MustParseAddr("100.70.0.5")
	a.isPeer = func(_ context.Context, ip netip.Addr) bool { return ip == peer }
	a.lookupDNS = func(context.Context, string) ([]string, error) { return []string{"::ffff:100.70.0.5"}, nil }
	var dialed []string
	a.dialMesh = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		c1, c2 := net.Pipe()
		go c2.Close()
		return c1, nil
	}
	for _, target := range []string{"[::ffff:100.70.0.5]:443", "mapped.bobo.hogman:443"} {
		dialed = nil
		c, err := a.dial(context.Background(), target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		c.Close()
		if len(dialed) != 1 || dialed[0] != "100.70.0.5:443" {
			t.Fatalf("%s: dialed %v, want 100.70.0.5:443", target, dialed)
		}
	}
}

// The agent's own pages answer only requests addressed to it by its loopback
// address (or localhost), so a page that rebinds a DNS name to 127.0.0.1
// can't read /status or /proxy.pac.
func TestAgentOwnPagesCheckHost(t *testing.T) {
	a := newAgent(&state.AgentConfig{Zone: "bobo.hogman", ProxyAddr: "127.0.0.1:18123"}, nil)
	for host, want := range map[string]int{
		"127.0.0.1:18123":         http.StatusOK,
		"localhost:18123":         http.StatusOK,
		"evil.example:18123":      http.StatusNotFound,
		"rebind.attacker.example": http.StatusNotFound,
	} {
		for _, path := range []string{"/status", "/proxy.pac"} {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Host = host
			a.ServeHTTP(rec, req)
			if rec.Code != want {
				t.Fatalf("GET %s with Host %s: %d, want %d", path, host, rec.Code, want)
			}
		}
	}
}

func TestRenderPACSingleAndMulti(t *testing.T) {
	p1 := &state.AgentConfig{Zone: "bobo.hogman", ProxyAddr: "127.0.0.1:18123"}
	single := state.RenderPAC([]*state.AgentConfig{p1})
	if !strings.Contains(single, "only names in bobo.hogman use the pen") {
		t.Fatalf("unexpected single-pen PAC header:\n%s", single)
	}
	if !strings.Contains(single, `if (host === "bobo.hogman" || dnsDomainIs(host, ".bobo.hogman")) return "PROXY 127.0.0.1:18123";`) {
		t.Fatalf("missing single-pen rule:\n%s", single)
	}

	nested := &state.AgentConfig{Zone: "team.bobo.hogman", ProxyAddr: "127.0.0.1:18125"}
	p2 := &state.AgentConfig{Zone: "a.hogman", ProxyAddr: "127.0.0.1:18124"}
	p3 := &state.AgentConfig{Zone: "b.hogman", ProxyAddr: "127.0.0.1:18126"}
	badZone := &state.AgentConfig{Zone: "bad\";return \"PROXY evil", ProxyAddr: "127.0.0.1:18127"}
	badDot := &state.AgentConfig{Zone: ".bobo.hogman", ProxyAddr: "127.0.0.1:18128"}
	badAddr := &state.AgentConfig{Zone: "z.hogman", ProxyAddr: "evil.example:8080"}
	badRemote := &state.AgentConfig{Zone: "remote.hogman", ProxyAddr: "198.51.100.1:8080"}
	badPort := &state.AgentConfig{Zone: "z2.hogman", ProxyAddr: "127.0.0.1:99999"}
	override := &state.AgentConfig{Zone: "bobo.hogman", ProxyAddr: "127.0.0.1:19123"}

	multi := state.RenderPAC(state.NormalizePenConfigs(
		[]*state.AgentConfig{p1, p3, p2, nested, badZone, badDot, badAddr, badRemote, badPort},
		override,
	))
	if !strings.Contains(multi, "only pen names use their pen's proxy") {
		t.Fatalf("unexpected multi-pen PAC header:\n%s", multi)
	}
	for _, want := range []string{
		`if (host === "team.bobo.hogman" || dnsDomainIs(host, ".team.bobo.hogman")) return "PROXY 127.0.0.1:18125";`,
		`if (host === "bobo.hogman" || dnsDomainIs(host, ".bobo.hogman")) return "PROXY 127.0.0.1:19123";`,
		`if (host === "a.hogman" || dnsDomainIs(host, ".a.hogman")) return "PROXY 127.0.0.1:18124";`,
		`if (host === "b.hogman" || dnsDomainIs(host, ".b.hogman")) return "PROXY 127.0.0.1:18126";`,
	} {
		if !strings.Contains(multi, want) {
			t.Fatalf("multi PAC missing %q:\n%s", want, multi)
		}
	}
	if strings.Contains(multi, "18123") || strings.Contains(multi, "evil") || strings.Contains(multi, "198.51.100.1") || strings.Contains(multi, "99999") {
		t.Fatalf("multi PAC kept invalid or overridden entry:\n%s", multi)
	}
	idxNested := strings.Index(multi, `"team.bobo.hogman"`)
	idxParent := strings.Index(multi, `"bobo.hogman"`)
	idxA := strings.Index(multi, `"a.hogman"`)
	idxB := strings.Index(multi, `"b.hogman"`)
	if !(idxNested < idxParent && idxParent < idxA && idxA < idxB) {
		t.Fatalf("multi PAC rules not deterministically ordered by longest zone then name:\n%s", multi)
	}
}

func TestAgentServesCombinedPAC(t *testing.T) {
	base := t.TempDir()
	bobo := &state.AgentConfig{Zone: "bobo.hogman", ProxyAddr: "127.0.0.1:18123"}
	zebra := &state.AgentConfig{Zone: "zebra.hogman", ProxyAddr: "127.0.0.1:18124"}
	for _, c := range []*state.AgentConfig{bobo, zebra} {
		dir := filepath.Join(base, c.Zone)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := c.Save(dir); err != nil {
			t.Fatal(err)
		}
	}
	badDir := filepath.Join(base, "bad.hogman")
	if err := os.MkdirAll(badDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&state.AgentConfig{Zone: "bad zone", ProxyAddr: "127.0.0.1:18125"}).Save(badDir); err != nil {
		t.Fatal(err)
	}

	a := newAgent(bobo, nil)
	a.configBase = base

	for _, path := range []string{"/proxy.pac", "/proxy.pac?v=deadbeef"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = bobo.ProxyAddr
		a.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, rec.Code)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("GET %s: Cache-Control=%q, want no-store", path, cc)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/x-ns-proxy-autoconfig" {
			t.Fatalf("GET %s: Content-Type=%q", path, ct)
		}
		body := rec.Body.String()
		if !strings.Contains(body, ".bobo.hogman") || !strings.Contains(body, ".zebra.hogman") {
			t.Fatalf("GET %s missing both pens:\n%s", path, body)
		}
		if strings.Contains(body, "bad zone") {
			t.Fatalf("GET %s included malformed config:\n%s", path, body)
		}
	}

	if err := os.RemoveAll(filepath.Join(base, zebra.Zone)); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/proxy.pac", nil)
	req.Host = bobo.ProxyAddr
	a.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, ".bobo.hogman") || strings.Contains(body, ".zebra.hogman") {
		t.Fatalf("after removing zebra config, /proxy.pac body:\n%s", body)
	}
}

func TestHogmanPACMatchingAndClearSystemProxyNilLeaving(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)

	p1 := &state.AgentConfig{Zone: "bobo.hogman", ProxyAddr: "127.0.0.1:18123"}
	p2 := &state.AgentConfig{Zone: "zebra.hogman", ProxyAddr: "127.0.0.1:18124"}
	known := []*state.AgentConfig{p1, p2}

	if !state.IsHogmanPACURL(p1.PACURL(), known) {
		t.Fatalf("expected %s to match known pens", p1.PACURL())
	}
	if !state.IsHogmanPACURL(p2.PACURL()+"?v=deadbeef", known) {
		t.Fatalf("expected versioned legacy PAC URL to still match known pens")
	}
	if state.IsHogmanPACURL("http://corp.example/proxy.pac", known) {
		t.Fatal("corporate PAC URL must not match Hogman pens")
	}

	// clearSystemProxy must handle leaving == nil cleanly without panicking.
	if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		if got := clearSystemProxy(nil, nil); got != "" {
			t.Fatalf("clearSystemProxy(nil, nil) = %q, want empty", got)
		}
		got := clearSystemProxy(nil, []*state.AgentConfig{p2})
		if !strings.Contains(got, p2.PACURL()) || !strings.Contains(got, p2.Zone) {
			t.Fatalf("clearSystemProxy(nil, [p2]) = %q, want %s and %s", got, p2.PACURL(), p2.Zone)
		}
	}
}

func TestEvaluateLiveNodeStatus(t *testing.T) {
	dnsIP := netip.MustParseAddr("100.64.0.1")
	peerKey := key.NewNode().Public()

	running := &ipnstate.Status{
		BackendState: "Running",
		Self:         &ipnstate.PeerStatus{TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			peerKey: {TailscaleIPs: []netip.Addr{dnsIP}},
		},
	}
	if up, nl, reason := mesh.EvaluateLiveNodeStatus(running, dnsIP.String()); !up || nl || reason != "" {
		t.Fatalf("running with DNS peer: got (%v, %v, %q), want (true, false, \"\")", up, nl, reason)
	}

	needsLogin := &ipnstate.Status{BackendState: "NeedsLogin"}
	if up, nl, reason := mesh.EvaluateLiveNodeStatus(needsLogin, dnsIP.String()); up || !nl || !strings.Contains(reason, "removed") {
		t.Fatalf("NeedsLogin: got (%v, %v, %q), want (false, true, removed)", up, nl, reason)
	}

	expired := &ipnstate.Status{
		BackendState: "Running",
		Self:         &ipnstate.PeerStatus{Expired: true},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			peerKey: {TailscaleIPs: []netip.Addr{dnsIP}},
		},
	}
	if up, nl, reason := mesh.EvaluateLiveNodeStatus(expired, dnsIP.String()); up || nl || !strings.Contains(reason, "expired") {
		t.Fatalf("expired self: got (%v, %v, %q), want (false, false, expired)", up, nl, reason)
	}

	noDNSPeer := &ipnstate.Status{
		BackendState: "Running",
		Self:         &ipnstate.PeerStatus{TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}},
		Peer:         map[key.NodePublic]*ipnstate.PeerStatus{},
	}
	if up, nl, reason := mesh.EvaluateLiveNodeStatus(noDNSPeer, dnsIP.String()); up || nl || strings.Contains(reason, "removed") || reason != "not connected to pen" {
		t.Fatalf("missing DNS peer: got (%v, %v, %q), want (false, false, 'not connected to pen')", up, nl, reason)
	}

	stopped := &ipnstate.Status{BackendState: "Stopped"}
	if up, nl, reason := mesh.EvaluateLiveNodeStatus(stopped, dnsIP.String()); up || nl || !strings.Contains(reason, "Stopped") {
		t.Fatalf("Stopped: got (%v, %v, %q), want (false, false, Stopped)", up, nl, reason)
	}
}

func TestAgentStatusReflectsPostKickRevocation(t *testing.T) {
	cfg := &state.AgentConfig{Zone: "bobo.pens.example", ProxyAddr: "127.0.0.1:18125", DNSServer: "100.64.0.1"}
	a := newAgent(cfg, nil)
	a.up = true
	a.ips = []string{"100.64.0.2"}

	mode := "up"
	a.liveStatus = func(context.Context) (bool, bool, string, bool) {
		switch mode {
		case "timeout":
			return false, false, "", false
		case "kicked":
			return false, true, "device removed from pen", true
		default:
			return true, false, "", true
		}
	}

	getStatus := func() agentStatus {
		req := httptest.NewRequest("GET", "/status", nil)
		req.Host = cfg.ProxyAddr
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /status = %d, want 200", rec.Code)
		}
		var st agentStatus
		if err := json.NewDecoder(rec.Body).Decode(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}

	if st := getStatus(); !st.Up || st.NeedsLogin || st.Error != "" {
		t.Fatalf("before kick: got %+v, want Up=true", st)
	}
	// A transient liveStatus error/timeout must keep the latched Up=true state.
	mode = "timeout"
	if st := getStatus(); !st.Up || st.NeedsLogin || st.Error != "" {
		t.Fatalf("on liveStatus timeout: got %+v, want latched Up=true", st)
	}
	mode = "kicked"
	if st := getStatus(); st.Up || !st.NeedsLogin || st.Error != "device removed from pen" {
		t.Fatalf("after kick: got %+v, want Up=false NeedsLogin=true Error='device removed from pen'", st)
	}
}
