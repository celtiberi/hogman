package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func listenInHogmanRange(t *testing.T) (net.Listener, int) {
	t.Helper()
	for port := hogmanPortMin + 500; port <= hogmanPortMax; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			t.Cleanup(func() { _ = ln.Close() })
			return ln, port
		}
	}
	t.Fatal("no free port in Hogman range")
	return nil, 0
}

func TestIsNativeHostBinary(t *testing.T) {
	if !isNativeHostBinary("/opt/hogman/bin/hogman-native-host") {
		t.Fatal("expected hogman-native-host to match")
	}
	if !isNativeHostBinary(`hogman-native-host.exe`) {
		t.Fatal("expected hogman-native-host.exe to match")
	}
	if isNativeHostBinary("/usr/local/bin/hogman-join") {
		t.Fatal("hogman-join must not dispatch as native host")
	}
}

func TestParseStrictHogmanPort(t *testing.T) {
	good := []struct {
		addr string
		want int
	}{
		{"127.0.0.1:17000", 17000},
		{"127.0.0.1:25148", 25148},
		{"127.0.0.1:26999", 26999},
	}
	for _, tc := range good {
		got, ok := parseStrictHogmanPort(tc.addr)
		if !ok || got != tc.want {
			t.Fatalf("parseStrictHogmanPort(%q) = (%d, %v), want (%d, true)", tc.addr, got, ok, tc.want)
		}
	}
	bad := []string{
		"localhost:17000",
		"[::1]:17000",
		"192.168.1.5:17000",
		"127.0.0.1:8080",
		"127.0.0.1:16999",
		"127.0.0.1:27000",
		"127.0.0.1:017000",
		"127.0.0.1:0",
		"not-a-host",
	}
	for _, addr := range bad {
		if port, ok := parseStrictHogmanPort(addr); ok {
			t.Fatalf("parseStrictHogmanPort(%q) = (%d, true), want rejected", addr, port)
		}
	}
}

func TestNativeFrameLimits(t *testing.T) {
	var buf bytes.Buffer
	if err := writeNativeFrame(&buf, nativeRequest{Op: "list_pens"}); err != nil {
		t.Fatalf("writeNativeFrame: %v", err)
	}
	raw, err := readNativeFrame(&buf)
	if err != nil {
		t.Fatalf("readNativeFrame: %v", err)
	}
	var got nativeRequest
	if err := json.Unmarshal(raw, &got); err != nil || got.Op != "list_pens" {
		t.Fatalf("decoded %+v (err=%v), want list_pens", got, err)
	}

	// Reject zero-length and oversized frames.
	for _, badLen := range []uint32{0, maxNativeFrameBytes + 1} {
		var bad bytes.Buffer
		_ = binary.Write(&bad, binary.NativeEndian, badLen)
		if _, err := readNativeFrame(&bad); err == nil {
			t.Fatalf("readNativeFrame accepted invalid length %d", badLen)
		}
	}
}

func TestCollectNativePensStrictValidationLegacyAndSquatDetection(t *testing.T) {
	base := t.TempDir()

	// 1. Legitimate running Hogman agent with matching status.token HMAC proof.
	ln1, port1 := listenInHogmanRange(t)
	zone1 := "farm2.pens.hogman.network"
	dir1 := filepath.Join(base, zone1)
	if err := os.MkdirAll(dir1, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg1 := &agentConfig{Zone: zone1, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port1)}
	if err := cfg1.save(dir1); err != nil {
		t.Fatal(err)
	}
	tok1 := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(dir1, statusTokenFilename), []byte(tok1), 0o600); err != nil {
		t.Fatal(err)
	}
	a1 := newAgent(cfg1, nil)
	a1.up = true
	a1.statusToken = tok1
	srv1 := &httptest.Server{Listener: ln1, Config: &http.Server{Handler: a1}}
	srv1.Start()
	defer srv1.Close()

	// 2. Squatted port: status.token exists, foreign listener fails HMAC proof.
	ln2, port2 := listenInHogmanRange(t)
	zone2 := "squat2.pens.hogman.network"
	dir2 := filepath.Join(base, zone2)
	if err := os.MkdirAll(dir2, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg2 := &agentConfig{Zone: zone2, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port2)}
	if err := cfg2.save(dir2); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, statusTokenFilename), []byte("real-secret-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeSrv := &httptest.Server{
		Listener: ln2,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Hogman-Proof", "forged")
			_ = json.NewEncoder(w).Encode(agentStatus{Zone: zone2, Up: true})
		})},
	}
	fakeSrv.Start()
	defer fakeSrv.Close()

	// 3. Missing status.token on disk: listener answers /status with matching
	// zone JSON but cannot prove ownership -> fail closed as Squatted.
	lnLeg, portLeg := listenInHogmanRange(t)
	zoneLeg := "legacy2.pens.hogman.network"
	dirLeg := filepath.Join(base, zoneLeg)
	if err := os.MkdirAll(dirLeg, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgLeg := &agentConfig{Zone: zoneLeg, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", portLeg)}
	if err := cfgLeg.save(dirLeg); err != nil {
		t.Fatal(err)
	}
	legAgent := newAgent(cfgLeg, nil)
	legAgent.up = true
	legSrv := &httptest.Server{Listener: lnLeg, Config: &http.Server{Handler: legAgent}}
	legSrv.Start()
	defer legSrv.Close()

	// 4. Stopped agent (no listener on port) + custom non-hosted zone.
	ln3, port3 := listenInHogmanRange(t)
	_ = ln3.Close()
	zone3 := "club.example.org"
	dir3 := filepath.Join(base, zone3)
	if err := os.MkdirAll(dir3, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&agentConfig{Zone: zone3, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port3)}).save(dir3); err != nil {
		t.Fatal(err)
	}

	// 5. Spoofed directory name mismatch (must be ignored).
	spoofDir := filepath.Join(base, "zzz-spoof")
	if err := os.MkdirAll(spoofDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&agentConfig{Zone: zone1, ProxyAddr: "127.0.0.1:26000"}).save(spoofDir); err != nil {
		t.Fatal(err)
	}

	// 6. Out-of-range port (must be ignored).
	badPortDir := filepath.Join(base, "badport.pens.hogman.network")
	if err := os.MkdirAll(badPortDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&agentConfig{Zone: "badport.pens.hogman.network", ProxyAddr: "127.0.0.1:8080"}).save(badPortDir); err != nil {
		t.Fatal(err)
	}

	pens, _ := collectNativePens(base)
	byZone := map[string]nativePenEntry{}
	for _, p := range pens {
		byZone[p.Zone] = p
	}
	if len(byZone) != 4 {
		t.Fatalf("got %d pens (%+v), want 4", len(byZone), pens)
	}
	if p := byZone[zone1]; !p.Up || p.Port != port1 || !p.Hosted || p.Squatted || p.Legacy {
		t.Fatalf("zone1 entry = %+v, want Up=true Port=%d Hosted=true Squatted=false Legacy=false", p, port1)
	}
	if p := byZone[zone2]; p.Up || p.Port != 0 || !p.Squatted {
		t.Fatalf("zone2 squatted entry = %+v, want Up=false Port=0 Squatted=true", p)
	}
	if p := byZone[zoneLeg]; p.Up || p.Port != 0 || !p.Hosted || p.Legacy || !p.Squatted {
		t.Fatalf("zoneLeg missing-token entry = %+v, want Up=false Port=0 Hosted=true Legacy=false Squatted=true", p)
	}
	if p := byZone[zone3]; p.Up || p.Port != port3 || p.Hosted || p.Squatted || p.Legacy {
		t.Fatalf("zone3 stopped entry = %+v, want Up=false Port=%d Hosted=false Squatted=false", p, port3)
	}
}

func TestServeNativeHostListWatchCachingAndPrivacy(t *testing.T) {
	base := t.TempDir()

	// 1. list_pens + unknown op; verify PAC URL is NEVER sent over Native Messaging.
	var proxyCalls atomic.Int32
	sess := &nativeHostSession{
		configBase: base,
		now:        time.Now,
		detectProxy: func(_ []*agentConfig) systemProxyState {
			proxyCalls.Add(1)
			return systemProxyState{
				OSProxyConflict: true,
				OSProxyKind:     "http,pac",
				OSProxyDetail:   "HTTP proxy, PAC (http://secret-corp.example/wpad.dat?token=xyz)",
			}
		},
	}
	var inBuf, outBuf bytes.Buffer
	_ = writeNativeFrame(&inBuf, nativeRequest{Op: "list_pens"})
	_ = writeNativeFrame(&inBuf, nativeRequest{Op: "exec"})
	if err := serveNativeHostWithSession(&inBuf, &outBuf, sess, 25*time.Millisecond); err != nil {
		t.Fatalf("serveNativeHostWithSession: %v", err)
	}
	raw1, err := readNativeFrame(&outBuf)
	if err != nil {
		t.Fatalf("read first frame: %v", err)
	}
	if strings.Contains(string(raw1), "secret-corp.example") || strings.Contains(string(raw1), "wpad.dat") {
		t.Fatalf("native response leaked OS PAC URL: %s", raw1)
	}
	var resp1 nativeResponse
	if err := json.Unmarshal(raw1, &resp1); err != nil || !resp1.OK || !resp1.OSProxyConflict || resp1.OSProxyKind != "http,pac" {
		t.Fatalf("resp1 = %+v (err=%v)", resp1, err)
	}
	if !extensionRecentlySeen(base, time.Minute) {
		t.Fatal("expected extension heartbeat to be recorded")
	}
	raw2, err := readNativeFrame(&outBuf)
	if err != nil {
		t.Fatalf("read second frame: %v", err)
	}
	var resp2 nativeResponse
	if err := json.Unmarshal(raw2, &resp2); err != nil || resp2.OK || resp2.Error != "unsupported op" {
		t.Fatalf("resp2 = %+v (err=%v), want unsupported op", resp2, err)
	}

	// 2. watch mode pushes automatically when a new pen appears, caches detectProxy across 1s ticks, and exits on EOF.
	var watchProxyCalls atomic.Int32
	watchSess := &nativeHostSession{
		configBase: base,
		now:        time.Now,
		detectProxy: func(_ []*agentConfig) systemProxyState {
			watchProxyCalls.Add(1)
			return systemProxyState{}
		},
	}
	pr, pw := io.Pipe()
	or, ow := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- serveNativeHostWithSession(pr, ow, watchSess, 20*time.Millisecond)
		_ = ow.Close()
	}()
	if err := writeNativeFrame(pw, nativeRequest{Op: "watch"}); err != nil {
		t.Fatal(err)
	}
	initRaw, err := readNativeFrame(or)
	if err != nil {
		t.Fatalf("watch initial frame: %v", err)
	}
	var initResp nativeResponse
	if err := json.Unmarshal(initRaw, &initResp); err != nil || len(initResp.Pens) != 0 {
		t.Fatalf("initial watch = %+v (err=%v), want 0 pens", initResp, err)
	}

	// Let several poll ticks elapse, then add a pen directory.
	time.Sleep(100 * time.Millisecond)
	ln, port := listenInHogmanRange(t)
	_ = ln.Close()
	newZone := "newpen.pens.hogman.network"
	newDir := filepath.Join(base, newZone)
	if err := os.MkdirAll(newDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&agentConfig{Zone: newZone, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port)}).save(newDir); err != nil {
		t.Fatal(err)
	}

	updRaw, err := readNativeFrame(or)
	if err != nil {
		t.Fatalf("watch update frame: %v", err)
	}
	var updResp nativeResponse
	if err := json.Unmarshal(updRaw, &updResp); err != nil || len(updResp.Pens) != 1 || updResp.Pens[0].Zone != newZone {
		t.Fatalf("updated watch = %+v (err=%v), want %s", updResp, err, newZone)
	}
	if got := watchProxyCalls.Load(); got != 1 {
		t.Fatalf("detectProxy called %d times across multiple watch ticks, want 1 (cached for 30s)", got)
	}
	_ = pw.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("watch exit err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not exit after stdin EOF")
	}
}

func TestRenderNativeManifestsAndFirefoxIDValidation(t *testing.T) {
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cb, err := renderChromeNativeManifest("/abs/path/hogman-native-host", []string{id})
	if err != nil {
		t.Fatalf("renderChromeNativeManifest: %v", err)
	}
	if strings.Contains(string(cb), "allowed_extensions") || !strings.Contains(string(cb), `"chrome-extension://`+id+`/"`) {
		t.Fatalf("unexpected chrome manifest:\n%s", cb)
	}
	if _, err := renderChromeNativeManifest("relative/path", []string{id}); err == nil {
		t.Fatal("expected relative path rejection")
	}
	if _, err := renderChromeNativeManifest("/abs/path", []string{"not-valid-id"}); err == nil {
		t.Fatal("expected invalid chrome ID rejection")
	}

	ffID := "hogman-browser@hogman.network"
	fb, err := renderFirefoxNativeManifest("/abs/path/hogman-native-host", []string{ffID})
	if err != nil {
		t.Fatalf("renderFirefoxNativeManifest: %v", err)
	}
	if strings.Contains(string(fb), "allowed_origins") || !strings.Contains(string(fb), ffID) {
		t.Fatalf("unexpected firefox manifest:\n%s", fb)
	}
	if !validFirefoxExtID("{12345678-1234-1234-1234-1234567890ab}") {
		t.Fatal("expected UUID Gecko ID to be valid")
	}
	if validFirefoxExtID("bad id with spaces") || validFirefoxExtID("") {
		t.Fatal("expected invalid Gecko ID to be rejected")
	}
	if len(defaultChromeExtIDs) != 1 || !validChromeExtID(defaultChromeExtIDs[0]) {
		t.Fatalf("defaultChromeExtIDs = %v, want 1 valid Chrome Web Store ID", defaultChromeExtIDs)
	}
	if len(defaultFirefoxExtIDs) != 1 || !validFirefoxExtID(defaultFirefoxExtIDs[0]) {
		t.Fatalf("defaultFirefoxExtIDs = %v, want 1 valid Firefox AMO ID", defaultFirefoxExtIDs)
	}
}

func TestSavedBrowserIDsPersistence(t *testing.T) {
	base := t.TempDir()
	want := savedBrowserIDs{
		ChromeIDs:  []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		FirefoxIDs: []string{"hogman-browser@hogman.network"},
	}
	if err := saveBrowserIDs(base, want); err != nil {
		t.Fatalf("saveBrowserIDs: %v", err)
	}
	got := loadSavedBrowserIDs(base)
	if len(got.ChromeIDs) != 1 || got.ChromeIDs[0] != want.ChromeIDs[0] || len(got.FirefoxIDs) != 1 || got.FirefoxIDs[0] != want.FirefoxIDs[0] {
		t.Fatalf("loadSavedBrowserIDs = %+v, want %+v", got, want)
	}
}

func TestEvaluateDarwinProxyState(t *testing.T) {
	known := []*agentConfig{{Zone: "farm2.pens.hogman.network", ProxyAddr: "127.0.0.1:25148"}}

	// ProtonVPN active: utun4 primary interface, scutil --proxy has no PAC, Wi-Fi service has Hogman PAC.
	pVPN := parseScutilProxy("<dictionary> {\n  HTTPEnable : 0\n  ProxyAutoConfigEnable : 0\n}\n")
	iface := parseScutilPrimaryInterface("<dictionary> {\n  PrimaryInterface : utun4\n}\n")
	st := evaluateDarwinProxyState(pVPN, iface, true, known)
	if !st.VPNOverride || st.VPNInterface != "utun4" || st.OSProxyConflict {
		t.Fatalf("ProtonVPN case: got %+v, want VPNOverride=true utun4 OSProxyConflict=false", st)
	}

	// Wi-Fi disconnected or new dongle (non-tunnel interface): not a VPN override.
	stNoVPN := evaluateDarwinProxyState(pVPN, "en0", true, known)
	if stNoVPN.VPNOverride {
		t.Fatalf("non-tunnel interface should not report VPNOverride: %+v", stNoVPN)
	}

	// Hogman PAC active in scutil --proxy: no override, no conflict.
	pOK := parseScutilProxy("<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://127.0.0.1:25148/proxy.pac?v=abcd1234\n}\n")
	stOK := evaluateDarwinProxyState(pOK, "utun4", true, known)
	if stOK.VPNOverride || stOK.OSProxyConflict {
		t.Fatalf("active Hogman PAC case: got %+v, want clean", stOK)
	}

	// Corporate HTTP proxy + non-Hogman PAC: OSProxyConflict reported, kind has no URL.
	pCorp := parseScutilProxy("<dictionary> {\n  HTTPEnable : 1\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://proxy.corp.example/wpad.dat\n}\n")
	stCorp := evaluateDarwinProxyState(pCorp, "en0", false, known)
	if !stCorp.OSProxyConflict || stCorp.OSProxyKind != "http,pac" || !strings.Contains(stCorp.OSProxyDetail, "wpad.dat") {
		t.Fatalf("corporate proxy case: got %+v", stCorp)
	}
}

func TestRenderPACNormalizesTrailingDots(t *testing.T) {
	single := renderPAC([]*agentConfig{{Zone: "farm2.pens.hogman.network", ProxyAddr: "127.0.0.1:25148"}})
	if !strings.Contains(single, `.replace(/\.+$/, "")`) {
		t.Fatalf("single-pen PAC missing trailing-dot normalization:\n%s", single)
	}
	multi := renderPAC([]*agentConfig{
		{Zone: "farm2.pens.hogman.network", ProxyAddr: "127.0.0.1:25148"},
		{Zone: "qa-piggy5.pens.hogman.network", ProxyAddr: "127.0.0.1:25149"},
	})
	if !strings.Contains(multi, `.replace(/\.+$/, "")`) {
		t.Fatalf("multi-pen PAC missing trailing-dot normalization:\n%s", multi)
	}
}

func TestVerifyAgentEndpointReportsRemovedReason(t *testing.T) {
	base := t.TempDir()
	ln, port := listenInHogmanRange(t)
	zone := "kicked1.pens.hogman.network"
	dir := filepath.Join(base, zone)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &agentConfig{Zone: zone, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port)}
	if err := cfg.save(dir); err != nil {
		t.Fatal(err)
	}
	tok := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(dir, statusTokenFilename), []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newAgent(cfg, nil)
	a.up = true
	a.statusToken = tok
	a.liveStatus = func(context.Context) (bool, bool, string, bool) {
		return false, true, "device removed from pen", true
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: a}}
	srv.Start()
	defer srv.Close()

	state, detail := verifyAgentEndpointDetail(dir, cfg)
	if state != agentEndpointDown || !detail.verified || !detail.needsLogin || detail.reason != "device removed from pen" {
		t.Fatalf("verifyAgentEndpointDetail = (%v, %+v), want (down, verified=true, needsLogin=true)", state, detail)
	}
	pens, _ := collectNativePens(base)
	if len(pens) != 1 || pens[0].Up || pens[0].Squatted || pens[0].statusReason != "device removed from pen" {
		t.Fatalf("collectNativePens = %+v, want Up=false Squatted=false statusReason='device removed from pen'", pens)
	}

	// Unverified/forged listener claiming NeedsLogin must be flagged squatted (verified=false).
	lnBad, portBad := listenInHogmanRange(t)
	zoneBad := "forged1.pens.hogman.network"
	dirBad := filepath.Join(base, zoneBad)
	if err := os.MkdirAll(dirBad, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgBad := &agentConfig{Zone: zoneBad, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", portBad)}
	if err := cfgBad.save(dirBad); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirBad, statusTokenFilename), []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	badSrv := &httptest.Server{
		Listener: lnBad,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(agentStatus{Zone: zoneBad, Up: false, NeedsLogin: true, Error: "device removed from pen"})
		})},
	}
	badSrv.Start()
	defer badSrv.Close()

	badState, badDetail := verifyAgentEndpointDetail(dirBad, cfgBad)
	if badState != agentEndpointSquatted || badDetail.verified || badDetail.needsLogin {
		t.Fatalf("forged NeedsLogin: got (%v, %+v), want (squatted, verified=false, needsLogin=false)", badState, badDetail)
	}
}
