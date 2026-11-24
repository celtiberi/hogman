package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Other tests reason about pure rules; keep them off the network. Tests here
// put the real check back where they need it.
var realStaleHogmanPAC = staleHogmanPAC

func init() { staleHogmanPAC = func(string) bool { return false } }

func TestHogmanShapedPACURL(t *testing.T) {
	for u, want := range map[string]bool{
		"http://127.0.0.1:20441/proxy.pac":            true,
		"http://127.0.0.1:20441/proxy.pac?v=49a9aa23": true,
		"http://127.0.0.1:20441/proxy.pac?x=1":        false,
		"https://127.0.0.1:20441/proxy.pac":           false,
		"http://localhost:20441/proxy.pac":            false,
		"http://10.0.0.1:20441/proxy.pac":             false,
		"http://corp.example/proxy.pac":               false,
		"http://127.0.0.1:20441/other.pac":            false,
		"http://127.0.0.1:80/proxy.pac":               false,
		"http://127.0.0.1:8080/proxy.pac":             false, // outside Hogman's 17000-26999
		"http://127.0.0.1:27000/proxy.pac":            false,
		"http://user@127.0.0.1:20441/proxy.pac":       false,
	} {
		if got := hogmanShapedPACURL(u); got != want {
			t.Errorf("hogmanShapedPACURL(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestStaleHogmanPAC(t *testing.T) {
	// Nothing listens: a dead setting a removed pen left behind.
	l := listenHogmanPort(t)
	dead := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if !realStaleHogmanPAC("http://127.0.0.1:" + strconv.Itoa(dead) + "/proxy.pac?v=1") {
		t.Error("a dead Hogman-shaped PAC should count as ours")
	}

	serve := func(body string) string {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		srv.Listener.Close()
		srv.Listener = listenHogmanPort(t)
		srv.Start()
		t.Cleanup(srv.Close)
		return srv.URL + "/proxy.pac"
	}
	// Every header renderPAC writes, for 0, 1 and 2 pens.
	p1 := &agentConfig{Zone: "farm2.pens.hogman.network", ProxyAddr: "127.0.0.1:17464"}
	p2 := &agentConfig{Zone: "qa-piggy5.pens.hogman.network", ProxyAddr: "127.0.0.1:25148"}
	for _, pens := range [][]*agentConfig{nil, {p1}, {p1, p2}} {
		if !realStaleHogmanPAC(serve(renderPAC(pens))) {
			t.Errorf("a live Hogman agent's PAC for %d pen(s) should count as ours", len(pens))
		}
	}
	// A redirect is judged as it stands, never followed.
	redir := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, serve(renderPAC([]*agentConfig{p1})), http.StatusFound)
	}))
	redir.Listener.Close()
	redir.Listener = listenHogmanPort(t)
	redir.Start()
	t.Cleanup(redir.Close)
	if realStaleHogmanPAC(redir.URL + "/proxy.pac") {
		t.Error("a redirect to a Hogman PAC must not count as ours")
	}
	if realStaleHogmanPAC(serve("function FindProxyForURL(u,h){return \"PROXY corp:8080\"}")) {
		t.Error("another local tool's PAC must be left alone")
	}
	if realStaleHogmanPAC("http://corp.example/proxy.pac") {
		t.Error("a company PAC must never count as ours")
	}
}

// The case from the operator's laptop: Thunderbolt Bridge and ProtonVPN still
// pointed at a removed pen's dead port, so a new join left every connection
// alone and leaving never cleared them.
func TestStalePACIsReplacedAndCleared(t *testing.T) {
	staleHogmanPAC = func(u string) bool { return u == "http://127.0.0.1:20441/proxy.pac" }
	t.Cleanup(func() { staleHogmanPAC = func(string) bool { return false } })
	p := &agentConfig{Zone: "qa-piggy5.pens.hogman.network", ProxyAddr: "127.0.0.1:25148"}
	want := pacURLWithVersion(p, []*agentConfig{p})
	if got := planAutoProxyAction("http://127.0.0.1:20441/proxy.pac", true, []*agentConfig{p}, want); got != "set" {
		t.Errorf("join over a stale Hogman PAC: got %q, want set", got)
	}
	if got := planClearAutoProxyAction("http://127.0.0.1:20441/proxy.pac", true, nil, ""); got != "off" {
		t.Errorf("leave with a stale Hogman PAC: got %q, want off", got)
	}
	if got := planAutoProxyAction("http://corp.example/proxy.pac", true, []*agentConfig{p}, want); got != "leave" {
		t.Errorf("join over a company PAC: got %q, want leave", got)
	}
}

// listenHogmanPort listens on a free 127.0.0.1 port in the range Hogman's
// agents use (17000-26999), so stale-PAC checks treat it as Hogman-shaped.
func listenHogmanPort(t *testing.T) net.Listener {
	t.Helper()
	for p := hogmanPortMin + 7919%1000; p <= hogmanPortMax; p += 37 {
		if l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
			return l
		}
	}
	t.Fatal("no free port in Hogman's range")
	return nil
}
