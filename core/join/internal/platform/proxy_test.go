package platform

import (
	"encoding/xml"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"hogman/join/internal/state"
)

// Other tests in this package reason about pure rules; keep them off the
// network. Tests that exercise live probing use realStaleHogmanPAC directly.
var realStaleHogmanPAC = StaleHogmanPAC

func init() { StaleHogmanPAC = func(string) bool { return false } }

func TestParseAutoProxyOutput(t *testing.T) {
	t.Parallel()
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
		u, on := ParseAutoProxyOutput(tc.in)
		if u != tc.wantURL || on != tc.wantOn {
			t.Fatalf("ParseAutoProxyOutput(%q) = (%q, %v), want (%q, %v)", tc.in, u, on, tc.wantURL, tc.wantOn)
		}
	}
}

func TestShouldLeaveAutoProxy(t *testing.T) {
	p1 := &state.AgentConfig{Zone: "bobo.hogman", ProxyAddr: "127.0.0.1:18123"}
	p2 := &state.AgentConfig{Zone: "zebra.hogman", ProxyAddr: "127.0.0.1:18124"}
	tampered := &state.AgentConfig{Zone: "evil.hogman", ProxyAddr: "198.51.100.1:8080"}
	known := []*state.AgentConfig{p1, p2, tampered}
	if !ShouldLeaveAutoProxy("http://corp.example/proxy.pac", true, known) {
		t.Fatal("must leave active corporate /proxy.pac alone")
	}
	if !ShouldLeaveAutoProxy("http://198.51.100.1:8080/proxy.pac", true, known) {
		t.Fatal("must not claim non-loopback proxy as Hogman")
	}
	if !ShouldLeaveAutoProxy("http://127.0.0.1:19999/proxy.pac", true, known) {
		t.Fatal("must leave unknown local port /proxy.pac alone")
	}
	if !ShouldLeaveAutoProxy("https://127.0.0.1:18123/proxy.pac", true, known) {
		t.Fatal("must leave non-http scheme PAC alone")
	}
	if !ShouldLeaveAutoProxy("http://127.0.0.1:18123/other.pac", true, known) {
		t.Fatal("must leave non-/proxy.pac path alone")
	}
	if ShouldLeaveAutoProxy("http://127.0.0.1:19999/proxy.pac", false, known) {
		t.Fatal("disabled leftover PAC should not block setup")
	}
	if ShouldLeaveAutoProxy(p1.PACURL(), true, known) {
		t.Fatal("legacy Hogman pen PAC should not be flagged as foreign")
	}
	if ShouldLeaveAutoProxy(p2.PACURL()+"?v=deadbeef", true, known) {
		t.Fatal("versioned Hogman pen PAC should not be flagged as foreign")
	}
}

func TestHogmanShapedPACURL(t *testing.T) {
	t.Parallel()
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
		"http://127.0.0.1:8080/proxy.pac":             false,
		"http://127.0.0.1:27000/proxy.pac":            false,
		"http://user@127.0.0.1:20441/proxy.pac":       false,
	} {
		if got := HogmanShapedPACURL(u); got != want {
			t.Errorf("HogmanShapedPACURL(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestStaleHogmanPAC(t *testing.T) {
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
	p1 := &state.AgentConfig{Zone: "home.pens.example.com", ProxyAddr: "127.0.0.1:17464"}
	p2 := &state.AgentConfig{Zone: "work.pens.example.com", ProxyAddr: "127.0.0.1:25148"}
	for _, pens := range [][]*state.AgentConfig{nil, {p1}, {p1, p2}} {
		if !realStaleHogmanPAC(serve(state.RenderPAC(pens))) {
			t.Errorf("a live Hogman agent's PAC for %d pen(s) should count as ours", len(pens))
		}
	}
	redir := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, serve(state.RenderPAC([]*state.AgentConfig{p1})), http.StatusFound)
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

func TestStalePACIsRecognizedAsOurs(t *testing.T) {
	StaleHogmanPAC = func(u string) bool { return u == "http://127.0.0.1:20441/proxy.pac" }
	t.Cleanup(func() { StaleHogmanPAC = func(string) bool { return false } })
	p := &state.AgentConfig{Zone: "work.pens.example.com", ProxyAddr: "127.0.0.1:25148"}
	if !IsOurPAC("http://127.0.0.1:20441/proxy.pac", []*state.AgentConfig{p}) {
		t.Error("stale Hogman PAC should be recognized by IsOurPAC")
	}
	if ShouldLeaveAutoProxy("http://127.0.0.1:20441/proxy.pac", true, []*state.AgentConfig{p}) {
		t.Error("stale Hogman PAC should not be treated as a foreign proxy to leave untouched")
	}
	if !ShouldLeaveAutoProxy("http://corp.example/proxy.pac", true, []*state.AgentConfig{p}) {
		t.Error("company PAC must be left untouched")
	}
}

func TestClearSystemProxyNilLeaving(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)

	p2 := &state.AgentConfig{Zone: "zebra.hogman", ProxyAddr: "127.0.0.1:18124"}
	if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		if got := ClearSystemProxy(nil, nil); got != "" {
			t.Fatalf("ClearSystemProxy(nil, nil) = %q, want empty", got)
		}
		got := ClearSystemProxy(nil, []*state.AgentConfig{p2})
		if !strings.Contains(got, p2.PACURL()) || !strings.Contains(got, p2.Zone) {
			t.Fatalf("ClearSystemProxy(nil, [p2]) = %q, want %s and %s", got, p2.PACURL(), p2.Zone)
		}
	}
}

func TestParseNetworkServiceOrderAndInstructions(t *testing.T) {
	t.Parallel()
	raw := `An asterisk (*) denotes that a network service is disabled.
(1) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(3) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)

(4) ProtonVPN
(Hardware Port: ch.protonvpn.mac, Device: )

(*) Disabled Ethernet
(Hardware Port: Ethernet, Device: en1)

(5) Corporate Tunnel
(Hardware Port: VPN, Device: utun4)
`
	got := HardwareServiceNamesFromOrder(raw)
	want := []string{"Wi-Fi", "USB 10/100/1000 LAN"}
	if !slices.Equal(got, want) {
		t.Fatalf("HardwareServiceNamesFromOrder = %v, want %v", got, want)
	}

	if got := FormatServiceList(nil); got != "Wi-Fi (or Ethernet)" {
		t.Fatalf("0 services = %q", got)
	}
	if got := FormatServiceList([]string{"Wi-Fi"}); got != "Wi-Fi" {
		t.Fatalf("1 service = %q", got)
	}
	if got := FormatServiceList([]string{"Wi-Fi", "USB 10/100/1000 LAN"}); got != "Wi-Fi and USB 10/100/1000 LAN" {
		t.Fatalf("2 services = %q", got)
	}
	if got := FormatServiceList([]string{"Wi-Fi", "USB 10/100/1000 LAN", "iPhone USB"}); got != "Wi-Fi, USB 10/100/1000 LAN, and iPhone USB" {
		t.Fatalf("3 services = %q", got)
	}

	pac := "http://127.0.0.1:18123/proxy.pac"
	macMulti := FormatBrowserProxyInstructions("darwin", pac, "acme.pens.example", []string{"acme.pens.example"}, []string{"Wi-Fi", "USB 10/100/1000 LAN"})
	const extLead = "Using Chrome, Brave, Edge, Arc, or Vivaldi? Install the Hogman browser extension, then open its popup and turn on acme.pens.example. No proxy settings needed."
	if !strings.HasPrefix(macMulti, extLead) {
		t.Fatalf("darwin instructions should open with extension lead:\n%s", macMulti)
	}
	for _, want := range []string{
		ChromeExtensionStoreURL,
		"Firefox: coming soon",
		"Other browsers (Safari, or no extension)",
		"never asks for your Mac password",
		"System Settings → Network → Wi-Fi and USB 10/100/1000 LAN → Details… → Proxies (set it on each one)",
		"Automatic proxy configuration",
		pac,
		"https://home.acme.pens.example",
	} {
		if !strings.Contains(macMulti, want) {
			t.Fatalf("darwin multi-service instructions missing %q:\n%s", want, macMulti)
		}
	}
	if strings.Contains(macMulti, "Tip:") || strings.Contains(macMulti, "?v=") || strings.Contains(macMulti, "nothing else to set") {
		t.Fatalf("unexpected text in darwin instructions:\n%s", macMulti)
	}

	lin := FormatBrowserProxyInstructions("linux", pac, "acme.pens.example", []string{"acme.pens.example", "ops.pens.example"}, nil)
	if !strings.HasPrefix(lin, extLead) || !strings.Contains(lin, "covers all 2 pens: acme.pens.example, ops.pens.example") {
		t.Fatalf("unexpected linux instructions:\n%s", lin)
	}

	win := FormatBrowserProxyInstructions("windows", pac, "acme.pens.example", []string{"acme.pens.example"}, nil)
	if !strings.HasPrefix(win, extLead) || !strings.Contains(win, "Use setup script") {
		t.Fatalf("unexpected windows instructions:\n%s", win)
	}

	partial := FormatDarwinProxySummary([]string{"Wi-Fi"}, []string{"USB 10/100/1000 LAN"}, pac, pac, "acme.pens.example", []string{"acme.pens.example"})
	if !strings.Contains(partial, "Automatic proxy configuration is not set on USB 10/100/1000 LAN yet") {
		t.Fatalf("partial summary missing warning:\n%s", partial)
	}
}

func TestEvaluateDarwinProxyState(t *testing.T) {
	known := []*state.AgentConfig{{Zone: "farm2.pens.hogman.network", ProxyAddr: "127.0.0.1:25148"}}

	pVPN := ParseScutilProxy("<dictionary> {\n  HTTPEnable : 0\n  ProxyAutoConfigEnable : 0\n}\n")
	iface := ParseScutilPrimaryInterface("<dictionary> {\n  PrimaryInterface : utun4\n}\n")
	st := EvaluateDarwinProxyState(pVPN, iface, true, known)
	if !st.VPNOverride || st.VPNInterface != "utun4" || st.OSProxyConflict {
		t.Fatalf("ProtonVPN case: got %+v, want VPNOverride=true utun4 OSProxyConflict=false", st)
	}

	stNoVPN := EvaluateDarwinProxyState(pVPN, "en0", true, known)
	if stNoVPN.VPNOverride {
		t.Fatalf("non-tunnel interface should not report VPNOverride: %+v", stNoVPN)
	}

	pOK := ParseScutilProxy("<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://127.0.0.1:25148/proxy.pac?v=abcd1234\n}\n")
	stOK := EvaluateDarwinProxyState(pOK, "utun4", true, known)
	if stOK.VPNOverride || stOK.OSProxyConflict {
		t.Fatalf("active Hogman PAC case: got %+v, want clean", stOK)
	}

	pCorp := ParseScutilProxy("<dictionary> {\n  HTTPEnable : 1\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://proxy.corp.example/wpad.dat\n}\n")
	stCorp := EvaluateDarwinProxyState(pCorp, "en0", false, known)
	if !stCorp.OSProxyConflict || stCorp.OSProxyKind != "http,pac" || !strings.Contains(stCorp.OSProxyDetail, "wpad.dat") {
		t.Fatalf("corporate proxy case: got %+v", stCorp)
	}
}

func TestServiceTemplates(t *testing.T) {
	t.Parallel()
	p, err := RenderLaunchPlist(
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

	u := RenderSystemdUnit("bobo.hogman", `/opt/my bin/hogman`, `/home/a user/.config/hogman/bobo.hogman`)
	want := `ExecStart="/opt/my bin/hogman" agent "/home/a user/.config/hogman/bobo.hogman"`
	if !strings.Contains(u, want) {
		t.Fatalf("unit missing quoted ExecStart %q:\n%s", want, u)
	}

	c := &state.ShareConfig{Name: "blog", Zone: "bobo.hogman"}
	if got, pen := ShareLaunchLabel(c), LaunchLabel(c.Zone); got == pen || got != "network.hogman.share.blog.bobo.hogman" {
		t.Fatalf("ShareLaunchLabel = %q, pen label = %q", got, pen)
	}
	if got, pen := ShareUnitName(c), UnitName(c.Zone); got == pen || got != "hogman-share-blog.bobo.hogman.service" {
		t.Fatalf("ShareUnitName = %q, pen unit = %q", got, pen)
	}
	sp, err := RenderShareLaunchPlist(c, "/tmp/a & b/hogman", "/tmp/dir <1> & 2/shares/blog")
	if err != nil {
		t.Fatal(err)
	}
	if err := xml.Unmarshal([]byte(sp), &parsed); err != nil {
		t.Fatalf("share plist invalid XML: %v", err)
	}
	su := RenderShareSystemdUnit(c, `/tmp/bin "q"`, `/tmp/dir "x"\y`)
	if !strings.Contains(su, `ExecStart="/tmp/bin \"q\"" __share-run "/tmp/dir \"x\"\\y"`) || strings.Contains(su, "Restart=always") {
		t.Fatalf("unexpected share systemd unit:\n%s", su)
	}
}

func listenHogmanPort(t *testing.T) net.Listener {
	t.Helper()
	for p := state.PortMin + 7919%1000; p <= state.PortMax; p += 37 {
		if l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
			return l
		}
	}
	t.Fatal("no free port in Hogman's range")
	return nil
}
