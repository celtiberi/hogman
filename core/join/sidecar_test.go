package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUnixSocketShareTargetValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		if _, _, err := shareTarget("unix:///tmp/app.sock"); err == nil {
			t.Fatal("expected unix:// target to fail on windows")
		}
		return
	}

	got, folder, err := shareTarget("unix:///run/hogman-in/app.sock")
	if err != nil || folder || got != "unix:///run/hogman-in/app.sock" {
		t.Fatalf("shareTarget(unix valid) = (%q, %v, %v)", got, folder, err)
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
		if got, _, err := shareTarget(bad); err == nil {
			t.Errorf("shareTarget(%q) succeeded (%q), want error", bad, got)
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
		bridgeErr <- runBridge(ctx, sockPath, strings.TrimPrefix(appSrv.URL, "http://"), 16, func() {
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
	if err := bridgeCmd(bridgeOptions{checkUnix: sockPath}); err != nil {
		t.Fatalf("bridge --check failed: %v", err)
	}

	// Build shareHandler pointing at unix://sockPath and verify forwarding + header stripping.
	h, closeH, err := shareHandler(&shareConfig{
		Name:   "lab-notes",
		Zone:   "lab.pens.example.com",
		Target: "unix://" + sockPath,
	})
	if err != nil {
		t.Fatalf("shareHandler(unix) failed: %v", err)
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

	// Verify symlink to socket is refused by shareHandler's dialer.
	symPath := filepath.Join(sockDir, "sym.sock")
	if err := os.Symlink(sockPath, symPath); err != nil {
		t.Fatal(err)
	}
	hSym, closeSym, err := shareHandler(&shareConfig{
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
		t.Fatalf("runBridge returned error on cancel: %v", err)
	}
	if _, err := os.Lstat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket %s was not cleaned up on shutdown (err=%v)", sockPath, err)
	}
}

func TestBridgeValidation(t *testing.T) {
	// Reject non-loopback --forward-tcp targets.
	for _, bad := range []string{"192.168.1.10:8080", "169.254.169.254:80", "0.0.0.0:8080", "example.com:80", "127.0.0.1:0"} {
		if _, err := validateLoopbackTCPTarget(bad); err == nil {
			t.Errorf("validateLoopbackTCPTarget(%q) succeeded, want error", bad)
		}
	}
	for _, good := range []string{"127.0.0.1:8080", "[::1]:8080"} {
		if _, err := validateLoopbackTCPTarget(good); err != nil {
			t.Errorf("validateLoopbackTCPTarget(%q) failed: %v", good, err)
		}
	}
}

func TestShareLockAndContainerCLIFlags(t *testing.T) {
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		unlock1, err := acquireShareLock(dir)
		if err != nil {
			t.Fatalf("first acquireShareLock failed: %v", err)
		}
		if _, err := acquireShareLock(dir); err == nil {
			t.Fatal("second concurrent acquireShareLock should fail")
		}
		unlock1()
		unlock2, err := acquireShareLock(dir)
		if err != nil {
			t.Fatalf("acquireShareLock after unlock failed: %v", err)
		}
		unlock2()
	}

	// CLI flag wiring for --state-dir, --enroll-only, --upstream-host, and `bridge`.
	var gotO options
	var gotBridge bridgeOptions
	var errBuf bytes.Buffer
	h := cliHandlers{
		errOut: &errBuf,
		shareStart: func(_, _, _ string, o options) error {
			gotO = o
			return nil
		},
		bridge: func(bo bridgeOptions) error {
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
	if rc != 0 || gotBridge.listenUnix != "/run/hogman-in/app.sock" || gotBridge.forwardTCP != "127.0.0.1:8080" || gotBridge.maxConns != 64 {
		t.Fatalf("bridge flags: rc=%d bo=%+v err=%s", rc, gotBridge, errBuf.String())
	}
}
