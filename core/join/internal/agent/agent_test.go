package agent

import (
	"bufio"
	"context"
	"encoding/json"
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

	"hogman/join/internal/mesh"
	"hogman/join/internal/state"
)

func TestPickLocalAddr(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	var a1 string
	for i := 0; i < 8; i++ {
		addr, err := PickLocalAddr("bobo.hogman")
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
		if err != nil || port < state.PortMin || port > state.PortMax {
			t.Fatalf("port %d out of [%d, %d]", port, state.PortMin, state.PortMax)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("PickLocalAddr should randomize ports per install, got only %v", seen)
	}

	ln, err := net.Listen("tcp", a1)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	a3, err := PickLocalAddr("bobo.hogman")
	if err != nil {
		t.Fatal(err)
	}
	if a3 == a1 {
		t.Fatalf("expected fallback port when %s is occupied", a1)
	}
	_, portStr3, _ := net.SplitHostPort(a3)
	port3, _ := strconv.Atoi(portStr3)
	if port3 < state.PortMin || port3 > state.PortMax {
		t.Fatalf("fallback port %d out of [%d, %d]", port3, state.PortMin, state.PortMax)
	}
}

func TestAgentConnectHalfClose(t *testing.T) {
	t.Parallel()
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
	a := New(cfg, nil)
	a.LookupDNS = func(context.Context, string) ([]string, error) {
		return []string{"100.64.0.50"}, nil
	}
	a.DialMesh = func(ctx context.Context, network, addr string) (net.Conn, error) {
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
	t.Parallel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok:"+r.Host)
	}))
	defer backend.Close()

	cfg := &state.AgentConfig{Zone: "bobo.hogman"}
	a := New(cfg, nil)
	a.LookupDNS = func(_ context.Context, host string) ([]string, error) {
		if host == "alice.bobo.hogman" {
			return []string{"100.64.0.51"}, nil
		}
		return nil, io.EOF
	}
	a.DialMesh = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backend.Listener.Addr().String())
	}

	proxySrv := httptest.NewServer(a)
	defer proxySrv.Close()
	pu, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}

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

	for _, target := range []string{"alice.bobo.hogman:22", "alice.bobo.hogman:80", "alice.bobo.hogman:8080", "alice.bobo.hogman:9000"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodConnect, target, nil)
		req.Host = target
		a.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("CONNECT %s status=%d want 403", target, rec.Code)
		}
	}

	dialled := false
	a.DialMesh = func(context.Context, string, string) (net.Conn, error) { dialled = true; return nil, io.EOF }
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
	t.Parallel()
	cfg := &state.AgentConfig{Zone: "bobo.hogman"}
	a := New(cfg, nil)

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

	a.LookupDNS = func(context.Context, string) ([]string, error) {
		return nil, io.EOF
	}
	a.PeerLookup = func(_ context.Context, host string) ([]string, error) {
		return PeerIPsForHost(st, host), nil
	}
	var dialed string
	a.DialMesh = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}

	conn, err := a.Dial(context.Background(), "alice-server.nodes.bobo.hogman:8080")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if dialed != "100.64.0.12:8080" {
		t.Fatalf("dialed %q, want IPv4 peer 100.64.0.12:8080", dialed)
	}
	if ips := PeerIPsForHost(st, "alice-server.nodes.bobo.hogman"); len(ips) != 1 || ips[0] != "100.64.0.12" {
		t.Fatalf("PeerIPsForHost returned %v, want IPv4-only [100.64.0.12]", ips)
	}
}

func TestAgentForwardRejectsHTTPSScheme(t *testing.T) {
	t.Parallel()
	a := New(&state.AgentConfig{Zone: "bobo.hogman"}, nil)
	req := httptest.NewRequest(http.MethodGet, "https://alice.bobo.hogman/", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET https:// through forward proxy: status=%d want 403", rec.Code)
	}
}

func TestAgentDialsOnlyPenDevices(t *testing.T) {
	t.Parallel()
	a := New(&state.AgentConfig{Zone: "bobo.hogman"}, nil)
	peer := netip.MustParseAddr("100.70.0.5")
	a.IsPeer = func(_ context.Context, ip netip.Addr) bool { return ip == peer }
	answers := map[string][]string{
		"evil.bobo.hogman":  {"127.0.0.1", "192.168.1.1", "::ffff:127.0.0.1", "100.99.0.9", "100.70.0.5"},
		"local.bobo.hogman": {"127.0.0.1", "::ffff:127.0.0.1"},
		"work.bobo.hogman":  {"100.99.0.9"},
	}
	a.LookupDNS = func(_ context.Context, host string) ([]string, error) { return answers[host], nil }
	var dialed []string
	a.DialMesh = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		c1, c2 := net.Pipe()
		go c2.Close()
		return c1, nil
	}
	ctx := context.Background()

	if c, err := a.Dial(ctx, "evil.bobo.hogman:443"); err != nil {
		t.Fatalf("evil: %v", err)
	} else {
		c.Close()
	}
	if len(dialed) != 1 || dialed[0] != "100.70.0.5:443" {
		t.Fatalf("dialed %v, want only the pen's own device 100.70.0.5:443", dialed)
	}
	for _, target := range []string{"local.bobo.hogman:80", "work.bobo.hogman:80", "100.99.0.9:22", "127.0.0.1:22", "[::ffff:127.0.0.1]:22"} {
		dialed = nil
		if c, err := a.Dial(ctx, target); err == nil {
			c.Close()
			t.Fatalf("%s: dial allowed, dialed %v", target, dialed)
		}
		if len(dialed) != 0 {
			t.Fatalf("%s: dialed %v", target, dialed)
		}
	}
}

func TestAgentDialsUnmapped(t *testing.T) {
	t.Parallel()
	a := New(&state.AgentConfig{Zone: "bobo.hogman"}, nil)
	peer := netip.MustParseAddr("100.70.0.5")
	a.IsPeer = func(_ context.Context, ip netip.Addr) bool { return ip == peer }
	a.LookupDNS = func(context.Context, string) ([]string, error) { return []string{"::ffff:100.70.0.5"}, nil }
	var dialed []string
	a.DialMesh = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		c1, c2 := net.Pipe()
		go c2.Close()
		return c1, nil
	}
	for _, target := range []string{"[::ffff:100.70.0.5]:443", "mapped.bobo.hogman:443"} {
		dialed = nil
		c, err := a.Dial(context.Background(), target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		c.Close()
		if len(dialed) != 1 || dialed[0] != "100.70.0.5:443" {
			t.Fatalf("%s: dialed %v, want 100.70.0.5:443", target, dialed)
		}
	}
}

func TestAgentOwnPagesCheckHost(t *testing.T) {
	t.Parallel()
	a := New(&state.AgentConfig{Zone: "bobo.hogman", ProxyAddr: "127.0.0.1:18123"}, nil)
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

func TestAgentServesCombinedPAC(t *testing.T) {
	t.Parallel()
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

	a := New(bobo, nil)
	a.ConfigBase = base

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

func TestEvaluateLiveNodeStatus(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	cfg := &state.AgentConfig{Zone: "bobo.pens.example", ProxyAddr: "127.0.0.1:18125", DNSServer: "100.64.0.1"}
	a := New(cfg, nil)
	a.SetReady(true, []string{"100.64.0.2"})

	mode := "up"
	a.LiveStatus = func(context.Context) (bool, bool, string, bool) {
		switch mode {
		case "timeout":
			return false, false, "", false
		case "kicked":
			return false, true, "device removed from pen", true
		default:
			return true, false, "", true
		}
	}

	getStatus := func() Status {
		req := httptest.NewRequest("GET", "/status", nil)
		req.Host = cfg.ProxyAddr
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /status = %d, want 200", rec.Code)
		}
		var st Status
		if err := json.NewDecoder(rec.Body).Decode(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}

	if st := getStatus(); !st.Up || st.NeedsLogin || st.Error != "" {
		t.Fatalf("before kick: got %+v, want Up=true", st)
	}
	mode = "timeout"
	if st := getStatus(); !st.Up || st.NeedsLogin || st.Error != "" {
		t.Fatalf("on LiveStatus timeout: got %+v, want latched Up=true", st)
	}
	mode = "kicked"
	if st := getStatus(); st.Up || !st.NeedsLogin || st.Error != "device removed from pen" {
		t.Fatalf("after kick: got %+v, want Up=false NeedsLogin=true Error='device removed from pen'", st)
	}
}

func TestAgentStatusSetsEnrolledOnLiveStatusOverride(t *testing.T) {
	t.Parallel()
	a := New(&state.AgentConfig{Zone: "bobo.pens.example.com", DNSServer: "100.64.0.1", ProxyAddr: "127.0.0.1:18123"}, nil)
	a.SetReady(true, []string{"100.64.0.9"})
	a.LiveStatus = func(context.Context) (bool, bool, string, bool) {
		return false, false, "not connected to pen", true
	}
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Host = "127.0.0.1:18123"
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/status = %d, want 200", rec.Code)
	}
	var st Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Up || !st.Enrolled || st.NeedsLogin || st.Error != "not connected to pen" {
		t.Fatalf("unexpected /status payload: %+v", st)
	}
}
