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
	"strconv"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func TestPickLocalAddr(t *testing.T) {
	a1, err := pickLocalAddr("bobo.hogman")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := pickLocalAddr("bobo.hogman")
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 {
		t.Fatalf("pickLocalAddr not deterministic: %q != %q", a1, a2)
	}
	_, portStr, err := net.SplitHostPort(a1)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 17000 || port >= 27000 {
		t.Fatalf("port %d out of [17000, 27000)", port)
	}

	// Occupy the preferred port and verify it picks the next free port in range.
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

	cfg := &agentConfig{Zone: "bobo.hogman"}
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

	cfg := &agentConfig{Zone: "bobo.hogman"}
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

	// HTTPS only (D-11): pen names on any port but 443 (CONNECT) or 80 (HTTP) are refused.
	for _, target := range []string{"alice.bobo.hogman:22", "alice.bobo.hogman:8080", "alice.bobo.hogman:9000"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodConnect, target, nil)
		req.Host = target
		a.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("CONNECT %s status=%d want 403", target, rec.Code)
		}
	}
	if resp, err := client.Get("http://alice.bobo.hogman:8080/"); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GET :8080 status=%d want 403", resp.StatusCode)
		}
	}

	// Plain HTTP forward to alice.bobo.hogman succeeds and reuses the single Transport on a.rp.
	trBefore := a.rp.Transport
	for i := 0; i < 2; i++ {
		resp, err := client.Get("http://alice.bobo.hogman/")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok:alice.bobo.hogman" {
			t.Fatalf("forward #%d: status=%d body=%q", i, resp.StatusCode, string(body))
		}
		if a.rp.Transport != trBefore {
			t.Fatal("agent reverse proxy transport changed across requests")
		}
	}
}

func TestAgentDialNodesMagicDNSFallback(t *testing.T) {
	cfg := &agentConfig{Zone: "bobo.hogman"}
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

func TestShouldLeaveAutoProxy(t *testing.T) {
	want := "http://127.0.0.1:18123/proxy.pac"
	if !shouldLeaveAutoProxy("http://corp.example/proxy.pac", true, want) {
		t.Fatal("must leave active corporate /proxy.pac alone")
	}
	if !shouldLeaveAutoProxy("http://127.0.0.1:19999/proxy.pac", true, want) {
		t.Fatal("must leave another pen's active PAC alone")
	}
	if shouldLeaveAutoProxy("http://127.0.0.1:19999/proxy.pac", false, want) {
		t.Fatal("disabled leftover PAC should not block setup")
	}
	if shouldLeaveAutoProxy(want, true, want) {
		t.Fatal("matching active PAC should not be flagged as foreign")
	}
}

func TestRenderLaunchPlist(t *testing.T) {
	p, err := renderLaunchPlist(
		"network.hogman.bobo.hogman",
		"/tmp/a&b<c>/hogman-join",
		"/tmp/dir&1/bobo.hogman",
		"/tmp/dir&1/bobo.hogman/agent.log",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, "/tmp/a&amp;b&lt;c&gt;/hogman-join") {
		t.Fatalf("expected XML-escaped path in plist:\n%s", p)
	}
	var parsed any
	if err := xml.Unmarshal([]byte(p), &parsed); err != nil {
		t.Fatalf("rendered plist is not valid XML: %v\n%s", err, p)
	}
}

func TestFetchNetworkValidation(t *testing.T) {
	var payload networkInfo
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	c := srv.Client()

	payload = networkInfo{
		Zone:        "bobo.hogman",
		LoginServer: "https://" + host,
		Portal:      "https://home.bobo.hogman",
		DNSServer:   "100.64.0.2",
	}
	if _, err := fetchNetwork(c, host); err != nil {
		t.Fatalf("valid networkInfo rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*networkInfo)
	}{
		{"mismatched login_server", func(n *networkInfo) { n.LoginServer = "https://evil.example" }},
		{"foreign portal", func(n *networkInfo) { n.Portal = "https://evil.example/phish" }},
		{"non-mesh dns_server", func(n *networkInfo) { n.DNSServer = "8.8.8.8" }},
	}
	for _, tc := range cases {
		bad := payload
		tc.mutate(&bad)
		payload = bad
		if _, err := fetchNetwork(c, host); err == nil {
			t.Errorf("%s: expected fetchNetwork to reject payload", tc.name)
		}
		payload = networkInfo{
			Zone:        "bobo.hogman",
			LoginServer: "https://" + host,
			Portal:      "https://home.bobo.hogman",
			DNSServer:   "100.64.0.2",
		}
	}
}

func TestAgentForwardRejectsHTTPSScheme(t *testing.T) {
	a := newAgent(&agentConfig{Zone: "bobo.hogman"}, nil)
	req := httptest.NewRequest(http.MethodGet, "https://alice.bobo.hogman/", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET https:// through forward proxy: status=%d want 403", rec.Code)
	}
}

func TestWriteTempCertPermissions(t *testing.T) {
	path, cleanup, err := writeTempCert("PEMDATA")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	dInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dInfo.Mode().Perm() != 0o700 {
		t.Fatalf("temp cert dir mode = %o, want 0700", dInfo.Mode().Perm())
	}
	fInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fInfo.Mode().Perm() != 0o600 {
		t.Fatalf("temp cert file mode = %o, want 0600", fInfo.Mode().Perm())
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("cleanup did not remove %s", dir)
	}
}

func TestRenderSystemdUnitQuotesSpaces(t *testing.T) {
	u := renderSystemdUnit("bobo.hogman", `/opt/my bin/hogman-join`, `/home/a user/.config/hogman/bobo.hogman`)
	want := `ExecStart="/opt/my bin/hogman-join" agent "/home/a user/.config/hogman/bobo.hogman"`
	if !strings.Contains(u, want) {
		t.Fatalf("unit missing quoted ExecStart %q:\n%s", want, u)
	}
}

// A hostile pen's DNS can answer anything. Only the pen's own devices may be
// dialed: never loopback, the LAN, or a 100.x address of another tailnet
// (tsnet's Dial would reach those through the computer's own network).
func TestAgentDialsOnlyPenDevices(t *testing.T) {
	a := newAgent(&agentConfig{Zone: "bobo.hogman"}, nil)
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
	a := newAgent(&agentConfig{Zone: "bobo.hogman"}, nil)
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
