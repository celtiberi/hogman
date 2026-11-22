package main

import (
	"bytes"
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

func TestCollectNativePensStrictValidationAndSquatDetection(t *testing.T) {
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

	// 2. Squatted port: foreign listener pretends to be a Hogman agent without status.token.
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

	// 3. Stopped agent (no listener on port) + custom non-hosted zone.
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

	// 4. Spoofed directory name mismatch (must be ignored).
	spoofDir := filepath.Join(base, "zzz-spoof")
	if err := os.MkdirAll(spoofDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&agentConfig{Zone: zone1, ProxyAddr: "127.0.0.1:26000"}).save(spoofDir); err != nil {
		t.Fatal(err)
	}

	// 5. Out-of-range port (must be ignored).
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
	if len(byZone) != 3 {
		t.Fatalf("got %d pens (%+v), want 3", len(byZone), pens)
	}
	if p := byZone[zone1]; !p.Up || p.Port != port1 || !p.Hosted || p.Squatted {
		t.Fatalf("zone1 entry = %+v, want Up=true Port=%d Hosted=true Squatted=false", p, port1)
	}
	if p := byZone[zone2]; p.Up || p.Port != 0 || !p.Squatted {
		t.Fatalf("zone2 squatted entry = %+v, want Up=false Port=0 Squatted=true", p)
	}
	if p := byZone[zone3]; p.Up || p.Port != port3 || p.Hosted || p.Squatted {
		t.Fatalf("zone3 stopped entry = %+v, want Up=false Port=%d Hosted=false Squatted=false", p, port3)
	}
}

func TestServeNativeHostListWatchAndRejectUnknownOp(t *testing.T) {
	base := t.TempDir()

	// 1. list_pens + unknown op.
	var inBuf, outBuf bytes.Buffer
	_ = writeNativeFrame(&inBuf, nativeRequest{Op: "list_pens"})
	_ = writeNativeFrame(&inBuf, nativeRequest{Op: "exec"})
	if err := serveNativeHost(&inBuf, &outBuf, base, 50*time.Millisecond); err != nil {
		t.Fatalf("serveNativeHost: %v", err)
	}
	raw1, err := readNativeFrame(&outBuf)
	if err != nil {
		t.Fatalf("read first frame: %v", err)
	}
	var resp1 nativeResponse
	if err := json.Unmarshal(raw1, &resp1); err != nil || !resp1.OK || resp1.Version != nativeHostProtocolVer {
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

	// 2. watch mode pushes automatically when a new pen appears and exits on EOF.
	pr, pw := io.Pipe()
	or, ow := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- serveNativeHost(pr, ow, base, 30*time.Millisecond)
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

	// Add a pen directory while watch is active.
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

func TestRenderNativeManifests(t *testing.T) {
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

	fb, err := renderFirefoxNativeManifest("/abs/path/hogman-native-host", []string{defaultFirefoxExtID})
	if err != nil {
		t.Fatalf("renderFirefoxNativeManifest: %v", err)
	}
	if strings.Contains(string(fb), "allowed_origins") || !strings.Contains(string(fb), defaultFirefoxExtID) {
		t.Fatalf("unexpected firefox manifest:\n%s", fb)
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

	// Corporate HTTP proxy + non-Hogman PAC: OSProxyConflict reported.
	pCorp := parseScutilProxy("<dictionary> {\n  HTTPEnable : 1\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://proxy.corp.example/wpad.dat\n}\n")
	stCorp := evaluateDarwinProxyState(pCorp, "en0", false, known)
	if !stCorp.OSProxyConflict || !strings.Contains(stCorp.OSProxyDetail, "HTTP proxy") || !strings.Contains(stCorp.OSProxyDetail, "wpad.dat") {
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
