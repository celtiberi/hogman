package nativehost

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

	"hogman/join/internal/agent"
	"hogman/join/internal/platform"
	"hogman/join/internal/state"
)

func listenInHogmanRange(t *testing.T) (net.Listener, int) {
	t.Helper()
	for port := state.PortMin + 500; port <= state.PortMax; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			t.Cleanup(func() { _ = ln.Close() })
			return ln, port
		}
	}
	t.Fatal("no free port in Hogman range")
	return nil, 0
}

func TestIsBinary(t *testing.T) {
	t.Parallel()
	if !IsBinary("/opt/hogman/bin/hogman-native-host") {
		t.Fatal("expected hogman-native-host to match")
	}
	if !IsBinary(`hogman-native-host.exe`) {
		t.Fatal("expected hogman-native-host.exe to match")
	}
	if IsBinary("/usr/local/bin/hogman") {
		t.Fatal("hogman must not dispatch as native host")
	}
}

func TestNativeFrameLimits(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Request{Op: "list_pens"}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	raw, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	var got Request
	if err := json.Unmarshal(raw, &got); err != nil || got.Op != "list_pens" {
		t.Fatalf("decoded %+v (err=%v), want list_pens", got, err)
	}

	for _, badLen := range []uint32{0, MaxFrameBytes + 1} {
		var bad bytes.Buffer
		_ = binary.Write(&bad, binary.NativeEndian, badLen)
		if _, err := ReadFrame(&bad); err == nil {
			t.Fatalf("ReadFrame accepted invalid length %d", badLen)
		}
	}
}

func TestCollectPensStrictValidationAndSquatDetection(t *testing.T) {
	t.Parallel()
	base := t.TempDir()

	// 1. Legitimate running Hogman agent with matching status.token HMAC proof.
	ln1, port1 := listenInHogmanRange(t)
	zone1 := "farm2.pens.hogman.network"
	dir1 := filepath.Join(base, zone1)
	if err := os.MkdirAll(dir1, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg1 := &state.AgentConfig{Zone: zone1, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port1)}
	if err := cfg1.Save(dir1); err != nil {
		t.Fatal(err)
	}
	tok1 := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(dir1, state.StatusTokenFilename), []byte(tok1), 0o600); err != nil {
		t.Fatal(err)
	}
	a1 := agent.New(cfg1, nil)
	a1.SetReady(true, nil)
	a1.StatusToken = tok1
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
	cfg2 := &state.AgentConfig{Zone: zone2, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port2)}
	if err := cfg2.Save(dir2); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, state.StatusTokenFilename), []byte("real-secret-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeSrv := &httptest.Server{
		Listener: ln2,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Hogman-Proof", "forged")
			_ = json.NewEncoder(w).Encode(agent.Status{Zone: zone2, Up: true})
		})},
	}
	fakeSrv.Start()
	defer fakeSrv.Close()

	// 3. Missing status.token on disk: fails closed as Squatted.
	lnLeg, portLeg := listenInHogmanRange(t)
	zoneLeg := "legacy2.pens.hogman.network"
	dirLeg := filepath.Join(base, zoneLeg)
	if err := os.MkdirAll(dirLeg, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgLeg := &state.AgentConfig{Zone: zoneLeg, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", portLeg)}
	if err := cfgLeg.Save(dirLeg); err != nil {
		t.Fatal(err)
	}
	legAgent := agent.New(cfgLeg, nil)
	legAgent.SetReady(true, nil)
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
	if err := (&state.AgentConfig{Zone: zone3, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port3)}).Save(dir3); err != nil {
		t.Fatal(err)
	}

	// 5. Spoofed directory name mismatch (must be ignored).
	spoofDir := filepath.Join(base, "zzz-spoof")
	if err := os.MkdirAll(spoofDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&state.AgentConfig{Zone: zone1, ProxyAddr: "127.0.0.1:26000"}).Save(spoofDir); err != nil {
		t.Fatal(err)
	}

	// 6. Out-of-range port (must be ignored).
	badPortDir := filepath.Join(base, "badport.pens.hogman.network")
	if err := os.MkdirAll(badPortDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&state.AgentConfig{Zone: "badport.pens.hogman.network", ProxyAddr: "127.0.0.1:8080"}).Save(badPortDir); err != nil {
		t.Fatal(err)
	}

	pens, _ := CollectPens(base)
	byZone := map[string]PenEntry{}
	for _, p := range pens {
		byZone[p.Zone] = p
	}
	if len(byZone) != 4 {
		t.Fatalf("got %d pens (%+v), want 4", len(byZone), pens)
	}
	if p := byZone[zone1]; !p.Up || p.Port != port1 || p.ConfiguredPort() != port1 || !p.Hosted || p.Squatted {
		t.Fatalf("zone1 entry = %+v, want Up=true Port=%d Hosted=true Squatted=false", p, port1)
	}
	if p := byZone[zone2]; p.Up || p.Port != 0 || p.ConfiguredPort() != port2 || !p.Squatted {
		t.Fatalf("zone2 squatted entry = %+v, want Up=false Port=0 ConfiguredPort=%d Squatted=true", p, port2)
	}
	if p := byZone[zoneLeg]; p.Up || p.Port != 0 || p.ConfiguredPort() != portLeg || !p.Hosted || !p.Squatted {
		t.Fatalf("zoneLeg missing-token entry = %+v, want Up=false Port=0 ConfiguredPort=%d Hosted=true Squatted=true", p, portLeg)
	}
	if p := byZone[zone3]; p.Up || p.Port != port3 || p.ConfiguredPort() != port3 || p.Hosted || p.Squatted {
		t.Fatalf("zone3 stopped entry = %+v, want Up=false Port=%d Hosted=false Squatted=false", p, port3)
	}

	rawWire, err := json.Marshal(Response{OK: true, Version: ProtocolVer, Pens: pens})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawWire), "configured") {
		t.Fatalf("Response JSON leaked unexported configuredPort: %s", rawWire)
	}
	var decoded struct {
		Pens []map[string]any `json:"pens"`
	}
	if err := json.Unmarshal(rawWire, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, p := range decoded.Pens {
		if p["zone"] == zone2 {
			if portVal, _ := p["port"].(float64); portVal != 0 {
				t.Fatalf("squatted pen wire port = %v, want 0 (%s)", portVal, rawWire)
			}
		}
	}
}

func TestServeListWatchCachingAndPrivacy(t *testing.T) {
	t.Parallel()
	base := t.TempDir()

	var proxyCalls atomic.Int32
	sess := &Session{
		ConfigBase: base,
		Now:        time.Now,
		DetectProxy: func(_ []*state.AgentConfig) platform.SystemProxyState {
			proxyCalls.Add(1)
			return platform.SystemProxyState{
				OSProxyConflict: true,
				OSProxyKind:     "http,pac",
				OSProxyDetail:   "HTTP proxy, PAC (http://secret-corp.example/wpad.dat?token=xyz)",
			}
		},
	}
	var inBuf, outBuf bytes.Buffer
	_ = WriteFrame(&inBuf, Request{Op: "list_pens"})
	_ = WriteFrame(&inBuf, Request{Op: "exec"})
	if err := ServeWithSession(&inBuf, &outBuf, sess, 25*time.Millisecond); err != nil {
		t.Fatalf("ServeWithSession: %v", err)
	}
	raw1, err := ReadFrame(&outBuf)
	if err != nil {
		t.Fatalf("read first frame: %v", err)
	}
	if strings.Contains(string(raw1), "secret-corp.example") || strings.Contains(string(raw1), "wpad.dat") {
		t.Fatalf("native response leaked OS PAC URL: %s", raw1)
	}
	var resp1 Response
	if err := json.Unmarshal(raw1, &resp1); err != nil || !resp1.OK || !resp1.OSProxyConflict || resp1.OSProxyKind != "http,pac" {
		t.Fatalf("resp1 = %+v (err=%v)", resp1, err)
	}
	if !ExtensionRecentlySeen(base, time.Minute) {
		t.Fatal("expected extension heartbeat to be recorded")
	}
	raw2, err := ReadFrame(&outBuf)
	if err != nil {
		t.Fatalf("read second frame: %v", err)
	}
	var resp2 Response
	if err := json.Unmarshal(raw2, &resp2); err != nil || resp2.OK || resp2.Error != "unsupported op" {
		t.Fatalf("resp2 = %+v (err=%v), want unsupported op", resp2, err)
	}

	var watchProxyCalls atomic.Int32
	watchSess := &Session{
		ConfigBase: base,
		Now:        time.Now,
		DetectProxy: func(_ []*state.AgentConfig) platform.SystemProxyState {
			watchProxyCalls.Add(1)
			return platform.SystemProxyState{}
		},
	}
	pr, pw := io.Pipe()
	or, ow := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- ServeWithSession(pr, ow, watchSess, 20*time.Millisecond)
		_ = ow.Close()
	}()
	if err := WriteFrame(pw, Request{Op: "watch"}); err != nil {
		t.Fatal(err)
	}
	initRaw, err := ReadFrame(or)
	if err != nil {
		t.Fatalf("watch initial frame: %v", err)
	}
	var initResp Response
	if err := json.Unmarshal(initRaw, &initResp); err != nil || len(initResp.Pens) != 0 {
		t.Fatalf("initial watch = %+v (err=%v), want 0 pens", initResp, err)
	}

	time.Sleep(100 * time.Millisecond)
	ln, port := listenInHogmanRange(t)
	_ = ln.Close()
	newZone := "newpen.pens.hogman.network"
	newDir := filepath.Join(base, newZone)
	if err := os.MkdirAll(newDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (&state.AgentConfig{Zone: newZone, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port)}).Save(newDir); err != nil {
		t.Fatal(err)
	}

	updRaw, err := ReadFrame(or)
	if err != nil {
		t.Fatalf("watch update frame: %v", err)
	}
	var updResp Response
	if err := json.Unmarshal(updRaw, &updResp); err != nil || len(updResp.Pens) != 1 || updResp.Pens[0].Zone != newZone {
		t.Fatalf("updated watch = %+v (err=%v), want %s", updResp, err, newZone)
	}
	if got := watchProxyCalls.Load(); got != 1 {
		t.Fatalf("DetectProxy called %d times across multiple watch ticks, want 1 (cached for 30s)", got)
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

func TestRenderManifestsAndSavedIDs(t *testing.T) {
	t.Parallel()
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cb, err := RenderChromeManifest("/abs/path/hogman-native-host", []string{id})
	if err != nil {
		t.Fatalf("RenderChromeManifest: %v", err)
	}
	if strings.Contains(string(cb), "allowed_extensions") || !strings.Contains(string(cb), `"chrome-extension://`+id+`/"`) {
		t.Fatalf("unexpected chrome manifest:\n%s", cb)
	}
	if _, err := RenderChromeManifest("relative/path", []string{id}); err == nil {
		t.Fatal("expected relative path rejection")
	}
	if _, err := RenderChromeManifest("/abs/path", []string{"not-valid-id"}); err == nil {
		t.Fatal("expected invalid chrome ID rejection")
	}

	ffID := "hogman-browser@hogman.network"
	fb, err := RenderFirefoxManifest("/abs/path/hogman-native-host", []string{ffID})
	if err != nil {
		t.Fatalf("RenderFirefoxManifest: %v", err)
	}
	if strings.Contains(string(fb), "allowed_origins") || !strings.Contains(string(fb), ffID) {
		t.Fatalf("unexpected firefox manifest:\n%s", fb)
	}
	if !ValidFirefoxExtID("{12345678-1234-1234-1234-1234567890ab}") {
		t.Fatal("expected UUID Gecko ID to be valid")
	}
	if ValidFirefoxExtID("bad id with spaces") || ValidFirefoxExtID("") {
		t.Fatal("expected invalid Gecko ID to be rejected")
	}
	if len(DefaultChromeExtIDs) != 1 || !ValidChromeExtID(DefaultChromeExtIDs[0]) {
		t.Fatalf("DefaultChromeExtIDs = %v, want 1 valid Chrome Web Store ID", DefaultChromeExtIDs)
	}
	if len(DefaultFirefoxExtIDs) != 1 || !ValidFirefoxExtID(DefaultFirefoxExtIDs[0]) {
		t.Fatalf("DefaultFirefoxExtIDs = %v, want 1 valid Firefox AMO ID", DefaultFirefoxExtIDs)
	}

	base := t.TempDir()
	want := SavedBrowserIDs{
		ChromeIDs:  []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		FirefoxIDs: []string{"hogman-browser@hogman.network"},
	}
	if err := SaveBrowserIDs(base, want); err != nil {
		t.Fatalf("SaveBrowserIDs: %v", err)
	}
	got := LoadSavedBrowserIDs(base)
	if len(got.ChromeIDs) != 1 || got.ChromeIDs[0] != want.ChromeIDs[0] || len(got.FirefoxIDs) != 1 || got.FirefoxIDs[0] != want.FirefoxIDs[0] {
		t.Fatalf("LoadSavedBrowserIDs = %+v, want %+v", got, want)
	}
}

func TestCollectPensReportsRemovedReason(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	ln, port := listenInHogmanRange(t)
	zone := "kicked1.pens.hogman.network"
	dir := filepath.Join(base, zone)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &state.AgentConfig{Zone: zone, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", port)}
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	tok := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(dir, state.StatusTokenFilename), []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	a := agent.New(cfg, nil)
	a.SetReady(true, nil)
	a.StatusToken = tok
	a.LiveStatus = func(context.Context) (bool, bool, string, bool) {
		return false, true, "device removed from pen", true
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: a}}
	srv.Start()
	defer srv.Close()

	pens, _ := CollectPens(base)
	if len(pens) != 1 || pens[0].Up || pens[0].Squatted || pens[0].StatusReason() != "device removed from pen" {
		t.Fatalf("CollectPens = %+v, want Up=false Squatted=false StatusReason='device removed from pen'", pens)
	}
}
