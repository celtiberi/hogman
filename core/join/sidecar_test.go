package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"hogman/join/internal/bridge"
	"hogman/join/internal/fsutil"
	"hogman/join/internal/share"
	"hogman/join/internal/state"
)

func TestUnixSocketShareTargetValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		if _, _, err := share.ParseTarget("unix:///tmp/app.sock"); err == nil {
			t.Fatal("expected unix:// target to fail on windows")
		}
		return
	}

	got, folder, err := share.ParseTarget("unix:///run/hogman-in/app.sock")
	if err != nil || folder || got != "unix:///run/hogman-in/app.sock" {
		t.Fatalf("share.ParseTarget(unix valid) = (%q, %v, %v)", got, folder, err)
	}

	for _, bad := range []string{
		"unix://",
		"unix://relative.sock",
		"unix://@abstract",
		"unix:///run/../etc/passwd",
		"unix:///run/hogman-in/",
		"unix:///",
		"unix://host/path.sock",
	} {
		if got, _, err := share.ParseTarget(bad); err == nil {
			t.Errorf("share.ParseTarget(%q) succeeded (%q), want error", bad, got)
		}
	}
}

func TestBridgeAndUnixShareHandlerEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket test")
	}

	// Upstream loopback HTTP server simulating the sealed app container on 127.0.0.1:<port>.
	var gotHost, gotXFF, gotXFH, gotXFP, gotFwd string
	appSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotXFH = r.Header.Get("X-Forwarded-Host")
		gotXFP = r.Header.Get("X-Forwarded-Proto")
		gotFwd = r.Header.Get("Forwarded")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "sealed-app-ok:"+r.URL.Path)
	}))
	defer appSrv.Close()

	// Use a short /tmp dir because Unix socket paths have a 104-byte limit on macOS.
	sockDir, err := os.MkdirTemp("/tmp", "hb-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "app.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	bridgeErr := make(chan error, 1)
	go func() {
		bridgeErr <- bridge.Run(ctx, sockPath, strings.TrimPrefix(appSrv.URL, "http://"), 16, func() {
			close(ready)
		})
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("bridge did not become ready")
	}

	// Verify socket permissions are 0600 and healthcheck succeeds.
	fi, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o, want 0600", fi.Mode().Perm())
	}
	if err := bridge.RunCommand(bridge.Options{CheckUnix: sockPath}); err != nil {
		t.Fatalf("bridge --check failed: %v", err)
	}

	// Build NewHandler pointing at unix://sockPath and verify forwarding + header stripping.
	h, closeH, err := share.NewHandler(&state.ShareConfig{
		Name:   "lab-notes",
		Zone:   "lab.pens.example.com",
		Target: "unix://" + sockPath,
	})
	if err != nil {
		t.Fatalf("share.NewHandler(unix) failed: %v", err)
	}
	defer closeH()

	req := httptest.NewRequest("GET", "https://lab-notes.lab.pens.example.com/hello", nil)
	req.RemoteAddr = "100.64.0.9:54321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, spoofed")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("Forwarded", "for=1.2.3.4")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "sealed-app-ok:/hello" {
		t.Fatalf("response = %d %q", rec.Code, rec.Body.String())
	}
	if gotHost != "lab-notes.lab.pens.example.com" {
		t.Errorf("upstream Host = %q, want lab-notes.lab.pens.example.com", gotHost)
	}
	if gotXFF != "100.64.0.9" {
		t.Errorf("X-Forwarded-For = %q, want exact 100.64.0.9 (spoofed header must be stripped)", gotXFF)
	}
	if gotXFH != "lab-notes.lab.pens.example.com" || gotXFP != "https" || gotFwd != "" {
		t.Errorf("forwarded headers = (host=%q proto=%q fwd=%q)", gotXFH, gotXFP, gotFwd)
	}

	// Verify symlink to socket is refused by share.NewHandler's dialer.
	symPath := filepath.Join(sockDir, "sym.sock")
	if err := os.Symlink(sockPath, symPath); err != nil {
		t.Fatal(err)
	}
	hSym, closeSym, err := share.NewHandler(&state.ShareConfig{
		Name:   "lab-notes",
		Zone:   "lab.pens.example.com",
		Target: "unix://" + symPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeSym()
	recSym := httptest.NewRecorder()
	hSym.ServeHTTP(recSym, httptest.NewRequest("GET", "https://lab-notes.lab.pens.example.com/", nil))
	if recSym.Code != http.StatusBadGateway {
		t.Fatalf("symlink socket returned %d, want 502 refusal", recSym.Code)
	}

	// Graceful shutdown removes the socket file.
	cancel()
	if err := <-bridgeErr; err != nil {
		t.Fatalf("bridge.Run returned error on cancel: %v", err)
	}
	if _, err := os.Lstat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket %s was not cleaned up on shutdown (err=%v)", sockPath, err)
	}
}

func TestBridgeValidation(t *testing.T) {
	// Reject non-loopback --forward-tcp targets.
	for _, bad := range []string{"192.168.1.10:8080", "169.254.169.254:80", "0.0.0.0:8080", "example.com:80", "127.0.0.1:0"} {
		if _, err := bridge.ValidateLoopbackTCPTarget(bad); err == nil {
			t.Errorf("ValidateLoopbackTCPTarget(%q) succeeded, want error", bad)
		}
	}
	for _, good := range []string{"127.0.0.1:8080", "[::1]:8080"} {
		if _, err := bridge.ValidateLoopbackTCPTarget(good); err != nil {
			t.Errorf("ValidateLoopbackTCPTarget(%q) failed: %v", good, err)
		}
	}
}

func TestShareLockAndContainerCLIFlags(t *testing.T) {
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		unlock1, err := fsutil.AcquireShareLock(dir)
		if err != nil {
			t.Fatalf("first AcquireShareLock failed: %v", err)
		}
		if _, err := fsutil.AcquireShareLock(dir); err == nil {
			t.Fatal("second concurrent AcquireShareLock should fail")
		}
		unlock1()
		unlock2, err := fsutil.AcquireShareLock(dir)
		if err != nil {
			t.Fatalf("AcquireShareLock after unlock failed: %v", err)
		}
		unlock2()
	}

	// CLI flag wiring for --state-dir, --enroll-only, --upstream-host, and `bridge`.
	var gotO options
	var gotBridge bridge.Options
	var errBuf bytes.Buffer
	h := cliHandlers{
		errOut: &errBuf,
		shareStart: func(_, _, _ string, o options) error {
			gotO = o
			return nil
		},
		bridge: func(bo bridge.Options) error {
			gotBridge = bo
			return nil
		},
	}
	rc := runCLI([]string{
		"share", "lab-notes", "unix:///run/hogman-in/app.sock",
		"--state-dir", "/var/lib/hogman",
		"--enroll-only",
		"--upstream-host", "localhost:8080",
	}, h)
	if rc != 0 || gotO.stateDir != "/var/lib/hogman" || !gotO.enrollOnly || gotO.upstreamHost != "localhost:8080" {
		t.Fatalf("share container flags: rc=%d o=%+v err=%s", rc, gotO, errBuf.String())
	}

	// --link-stdin + positional link arg must fail with exit 2.
	errBuf.Reset()
	rc = runCLI([]string{"share", "lab-notes", "3000", "https://h.example/join#k=abc", "--link-stdin"}, h)
	if rc != 2 {
		t.Fatalf("share --link-stdin + arg: rc=%d want 2 (err=%s)", rc, errBuf.String())
	}

	// `hogman bridge` CLI flag routing.
	errBuf.Reset()
	rc = runCLI([]string{"bridge", "--listen-unix", "/run/hogman-in/app.sock", "--forward-tcp", "127.0.0.1:8080", "--max-conns", "64"}, h)
	if rc != 0 || gotBridge.ListenUnix != "/run/hogman-in/app.sock" || gotBridge.ForwardTCP != "127.0.0.1:8080" || gotBridge.MaxConns != 64 {
		t.Fatalf("bridge flags: rc=%d bo=%+v err=%s", rc, gotBridge, errBuf.String())
	}
}

func TestShareIdentityHeaders(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	sendSpoofed := func(h http.Handler, remoteAddr string) {
		t.Helper()
		gotHeaders = nil
		req := httptest.NewRequest(http.MethodGet, "https://fleet.ops.pens.example.com/api", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Hogman-Handle", "spoofed-owner")
		// Underscore spellings collapse to HTTP_X_HOGMAN_HANDLE in CGI/PHP/WSGI/Rack.
		req.Header["X_Hogman_Handle"] = []string{"spoofed-underscore"}
		req.Header["X-Hogman_Handle"] = []string{"spoofed-mixed"}
		req.Header.Set("X-Hogman-Role", "owner")
		req.Header["X_Hogman_Role"] = []string{"owner"}
		req.Header.Set("X-Hogman-IP", "100.64.0.1")
		req.Header.Set("X-Hogman-Node", "spoofed-node")
		req.Header.Set("X-Hogman-Tags", "tag:admin")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("upstream status = %d body=%s", rec.Code, rec.Body.String())
		}
	}

	// 1. Default OFF: inbound X-Hogman-* headers (including underscore variants) are ALWAYS stripped and resolver is not called.
	resolverCalls := 0
	hOff, closeOff, err := share.NewHandlerWithResolver(&state.ShareConfig{
		Name:   "fleet",
		Zone:   "ops.pens.example.com",
		Target: upstream.URL,
	}, func(ctx context.Context, remoteAddr string) (*share.PeerIdentity, error) {
		resolverCalls++
		return &share.PeerIdentity{Handle: "bob", Node: "bob-laptop", IP: "100.64.0.11"}, nil
	})
	if err != nil {
		t.Fatalf("NewHandlerWithResolver(off): %v", err)
	}
	defer closeOff()
	sendSpoofed(hOff, "100.64.0.11:51234")
	if resolverCalls != 0 {
		t.Fatalf("resolver called %d times when IdentityHeaders=false, want 0", resolverCalls)
	}
	for k := range gotHeaders {
		if share.IsHogmanHeaderName(k) {
			t.Fatalf("client-supplied header %q leaked when IdentityHeaders=false: %v", k, gotHeaders)
		}
	}

	// 2. Enabled ON with personal device (including Headscale trailing '@' on LoginName):
	// spoofed hyphen/underscore/mixed headers are stripped and replaced with verified peer identity.
	hOn, closeOn, err := share.NewHandlerWithResolver(&state.ShareConfig{
		Name:            "fleet",
		Zone:            "ops.pens.example.com",
		Target:          upstream.URL,
		IdentityHeaders: true,
	}, func(ctx context.Context, remoteAddr string) (*share.PeerIdentity, error) {
		return share.PeerIdentityFromWhoIs(remoteAddr, &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				Name:         "bob-laptop.ops.pens.example.com.",
				ComputedName: "bob-laptop",
			},
			UserProfile: &tailcfg.UserProfile{LoginName: "bob@"},
		}), nil
	})
	if err != nil {
		t.Fatalf("NewHandlerWithResolver(on): %v", err)
	}
	defer closeOn()
	sendSpoofed(hOn, "100.64.0.11:51234")
	if got := gotHeaders.Get("X-Hogman-Handle"); got != "bob" {
		t.Fatalf("X-Hogman-Handle = %q, want bob", got)
	}
	if got := gotHeaders.Get("X-Hogman-Node"); got != "bob-laptop" {
		t.Fatalf("X-Hogman-Node = %q, want bob-laptop", got)
	}
	if got := gotHeaders.Get("X-Hogman-IP"); got != "100.64.0.11" {
		t.Fatalf("X-Hogman-IP = %q, want 100.64.0.11", got)
	}
	if got := gotHeaders.Get("X-Hogman-Tags"); got != "" {
		t.Fatalf("X-Hogman-Tags = %q, want empty for personal device", got)
	}
	for k := range gotHeaders {
		if share.IsHogmanHeaderName(k) && k != "X-Hogman-Handle" && k != "X-Hogman-Node" && k != "X-Hogman-Ip" {
			t.Fatalf("unexpected or spoofed X-Hogman header %q leaked: %v", k, gotHeaders[k])
		}
	}

	// 3. Tagged server node: emits X-Hogman-Tags, never X-Hogman-Handle (even if LoginName is set).
	hSrv, closeSrv, err := share.NewHandlerWithResolver(&state.ShareConfig{
		Name:            "fleet",
		Zone:            "ops.pens.example.com",
		Target:          upstream.URL,
		IdentityHeaders: true,
	}, func(ctx context.Context, remoteAddr string) (*share.PeerIdentity, error) {
		return share.PeerIdentityFromWhoIs(remoteAddr, &apitype.WhoIsResponse{
			Node: &tailcfg.Node{
				Name:         "notes.ops.pens.example.com.",
				ComputedName: "notes",
				Tags:         []string{"tag:server"},
			},
			UserProfile: &tailcfg.UserProfile{LoginName: "alice"},
		}), nil
	})
	if err != nil {
		t.Fatalf("NewHandlerWithResolver(tagged): %v", err)
	}
	defer closeSrv()
	sendSpoofed(hSrv, "100.64.0.20:44444")
	if got := gotHeaders.Get("X-Hogman-Handle"); got != "" {
		t.Fatalf("tagged server must not get X-Hogman-Handle, got %q", got)
	}
	if got := gotHeaders.Get("X-Hogman-Tags"); got != "tag:server" {
		t.Fatalf("X-Hogman-Tags = %q, want tag:server", got)
	}
	if got := gotHeaders.Get("X-Hogman-Node"); got != "notes" || gotHeaders.Get("X-Hogman-IP") != "100.64.0.20" {
		t.Fatalf("tagged server node/ip = %q / %q", gotHeaders.Get("X-Hogman-Node"), gotHeaders.Get("X-Hogman-IP"))
	}

	// 4. WhoIs lookup error: fail closed with 503 and never forward to the upstream app.
	hErr, closeErr, err := share.NewHandlerWithResolver(&state.ShareConfig{
		Name:            "fleet",
		Zone:            "ops.pens.example.com",
		Target:          upstream.URL,
		IdentityHeaders: true,
	}, func(ctx context.Context, remoteAddr string) (*share.PeerIdentity, error) {
		return nil, errors.New("whois unavailable")
	})
	if err != nil {
		t.Fatalf("NewHandlerWithResolver(err): %v", err)
	}
	defer closeErr()
	gotHeaders = nil
	errReq := httptest.NewRequest(http.MethodGet, "https://fleet.ops.pens.example.com/api", nil)
	errReq.RemoteAddr = "100.64.0.11:51234"
	errReq.Header.Set("X-Hogman-Handle", "spoofed-owner")
	errRec := httptest.NewRecorder()
	hErr.ServeHTTP(errRec, errReq)
	if errRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("WhoIs error status = %d, want 503", errRec.Code)
	}
	if gotHeaders != nil {
		t.Fatalf("upstream must not be called when WhoIs fails; got headers %v", gotHeaders)
	}

	// 5. Local-target restriction: refuses folder shares and non-loopback LAN targets.
	if _, _, err := share.NewHandlerWithResolver(&state.ShareConfig{
		Name:            "docs",
		Zone:            "ops.pens.example.com",
		Target:          t.TempDir(),
		Folder:          true,
		IdentityHeaders: true,
	}, nil); err == nil {
		t.Fatal("expected IdentityHeaders=true on folder share to fail")
	}
	if _, _, err := share.NewHandlerWithResolver(&state.ShareConfig{
		Name:            "lan",
		Zone:            "ops.pens.example.com",
		Target:          "http://192.168.1.40:8080",
		IdentityHeaders: true,
	}, nil); err == nil {
		t.Fatal("expected IdentityHeaders=true on LAN target to fail")
	}
	// Dial-time enforcement: localhost resolving to a LAN IP must be refused.
	dialFn := share.LoopbackOnlyDialContext(
		func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("192.168.1.40")}}, nil
		},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			t.Fatalf("dial should not be called for LAN IP %s", addr)
			return nil, errors.New("unexpected dial")
		},
	)
	if _, err := dialFn(context.Background(), "tcp", "localhost:8080"); err == nil {
		t.Fatal("expected loopbackOnlyDialContext to refuse localhost -> 192.168.1.40")
	}

	// 6. CLI flag wiring: off by default, enabled when --identity-headers is passed.
	var gotO options
	var errBuf bytes.Buffer
	h := cliHandlers{
		errOut: &errBuf,
		shareStart: func(_, _, _ string, o options) error {
			gotO = o
			return nil
		},
	}
	if rc := runCLI([]string{"share", "fleet", "8080"}, h); rc != 0 || gotO.identityHeaders {
		t.Fatalf("default share --identity-headers: rc=%d flag=%v err=%s", rc, gotO.identityHeaders, errBuf.String())
	}
	if rc := runCLI([]string{"share", "fleet", "8080", "--identity-headers"}, h); rc != 0 || !gotO.identityHeaders {
		t.Fatalf("share --identity-headers: rc=%d flag=%v err=%s", rc, gotO.identityHeaders, errBuf.String())
	}
}
