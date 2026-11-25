package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMeshHandlerDirectIgnoresXFFAndUsesVerifiedPeer(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	_, bobDev := e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.20", "")

	resolve := func(_ context.Context, remoteAddr string) (*PeerIdentity, error) {
		if strings.HasPrefix(remoteAddr, "100.64.0.20:") {
			return &PeerIdentity{
				IP:       "100.64.0.20",
				HSNodeID: bobDev.HSNodeID,
				NodeKey:  bobDev.NodeKey,
			}, nil
		}
		return nil, errors.New("unknown peer")
	}
	h := MeshHandlerDirect(e.svc, resolve)

	// Reset Headscale counters before testing steady-state WhoIs auth.
	e.hs.mu.Lock()
	e.hs.listNodesCalls = 0
	e.hs.getNodeCalls = 0
	e.hs.mu.Unlock()

	// Bob connects from 100.64.0.20 but spoofs X-Forwarded-For: 100.64.0.10 (alice/owner).
	// Direct identity must identify him as bob, refuse admin endpoints, and make 0 Headscale calls.
	req := httptest.NewRequest("GET", "/api/me", nil)
	req.RemoteAddr = "100.64.0.20:54321"
	req.Header.Set("X-Forwarded-For", "100.64.0.10")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/me status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	e.hs.mu.Lock()
	listCalls, getCalls := e.hs.listNodesCalls, e.hs.getNodeCalls
	e.hs.mu.Unlock()
	if listCalls != 0 || getCalls != 0 {
		t.Fatalf("steady-state GET /api/me hit Headscale (list=%d get=%d), want 0", listCalls, getCalls)
	}
	var me struct {
		Member struct {
			Handle string `json:"handle"`
		} `json:"member"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Member.Handle != "bob" {
		t.Fatalf("got member %q, want bob (X-Forwarded-For must be ignored)", me.Member.Handle)
	}

	reqAdmin := httptest.NewRequest("GET", "/api/admin/members", nil)
	reqAdmin.RemoteAddr = "100.64.0.20:54321"
	reqAdmin.Header.Set("X-Forwarded-For", "100.64.0.10")
	recAdmin := httptest.NewRecorder()
	h.ServeHTTP(recAdmin, reqAdmin)
	if recAdmin.Code != http.StatusForbidden {
		t.Fatalf("spoofed XFF admin endpoint: status=%d want 403", recAdmin.Code)
	}

	// Unknown peer must be rejected even with valid X-Forwarded-For.
	reqBad := httptest.NewRequest("GET", "/api/me", nil)
	reqBad.RemoteAddr = "100.64.0.99:54321"
	reqBad.Header.Set("X-Forwarded-For", "100.64.0.10")
	recBad := httptest.NewRecorder()
	h.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusForbidden {
		t.Fatalf("unknown peer: status=%d want 403", recBad.Code)
	}
}

func TestPortalHandlerHeadersHostAndNoDirListing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>You're in</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "secret.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	apiCalled := false
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
	h := PortalHandler("acme.pens.hogman.test", dir, api)

	// Wrong Host rejected with 404.
	reqWrong := httptest.NewRequest("GET", "https://evil.example/", nil)
	recWrong := httptest.NewRecorder()
	h.ServeHTTP(recWrong, reqWrong)
	if recWrong.Code != http.StatusNotFound {
		t.Fatalf("wrong host status=%d want 404", recWrong.Code)
	}

	// Valid host serves index.html with all required security headers.
	req := httptest.NewRequest("GET", "https://home.acme.pens.hogman.test/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "You're in") {
		t.Fatalf("GET / status=%d body=%q", rec.Code, rec.Body.String())
	}
	for k, want := range map[string]string{
		"Strict-Transport-Security": "max-age=31536000",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"Cache-Control":             "no-store",
		"Origin-Agent-Cluster":      "?1",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Fatalf("header %s = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("missing CSP header: %q", rec.Header().Get("Content-Security-Policy"))
	}

	// Subdirectory without index.html must 404 (no directory listing).
	reqDir := httptest.NewRequest("GET", "https://home.acme.pens.hogman.test/sub/", nil)
	recDir := httptest.NewRecorder()
	h.ServeHTTP(recDir, reqDir)
	if recDir.Code != http.StatusNotFound {
		t.Fatalf("directory listing status=%d want 404", recDir.Code)
	}

	// /api/* routes to apiHandler.
	reqAPI := httptest.NewRequest("GET", "https://home.acme.pens.hogman.test/api/me", nil)
	recAPI := httptest.NewRecorder()
	h.ServeHTTP(recAPI, reqAPI)
	if !apiCalled || recAPI.Code != http.StatusOK {
		t.Fatalf("api route failed: called=%v status=%d", apiCalled, recAPI.Code)
	}
}

func TestDNSServerSelfCheckAndCoreIPv6(t *testing.T) {
	e := newTestEnv(t)
	v4 := netip.MustParseAddr("100.64.0.1")
	v6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	d, err := NewDNSServerWithIPs(e.svc, v4, v6)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SelfCheck(); err != nil {
		t.Fatalf("SelfCheck failed: %v", err)
	}
}

func TestSetupAllowsEmptyCoreIPInTsnetModeAndConfigureTestCA(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "hs.key")
	if err := os.WriteFile(keyFile, []byte("test-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "root.crt")
	if err := os.WriteFile(caFile, []byte("test-ca\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tsDir := filepath.Join(dir, "tsnet")
	if err := os.MkdirAll(tsDir, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TEST_MODE", "true")
	t.Setenv("TSNET_CA_FILE", caFile)
	t.Setenv("SSL_CERT_FILE", "")
	configureTestCA()
	if got := os.Getenv("SSL_CERT_FILE"); got != caFile {
		t.Fatalf("SSL_CERT_FILE = %q, want %q", got, caFile)
	}

	t.Setenv("TSNET_STATE_DIR", tsDir)
	t.Setenv("CORE_MESH_IP", "")
	t.Setenv("ZONE", "bobo.pens.example.com")
	t.Setenv("PUBLIC_HOST", "bobo.gate.example.com")
	t.Setenv("DB", filepath.Join(dir, "registrar.db"))
	t.Setenv("HEADSCALE_API_KEY_FILE", keyFile)
	t.Setenv("CHALLENGE_DNS_URL", "")
	svc := setup()
	defer svc.st.Close()
	if svc.cfg.CoreIP != "" {
		t.Fatalf("expected empty CoreIP on first boot before mesh-ip exists, got %q", svc.cfg.CoreIP)
	}

	// Once tsnet writes mesh-ip, setup() picks it up even if CORE_MESH_IP is unset.
	if err := os.WriteFile(filepath.Join(tsDir, "mesh-ip"), []byte("100.64.0.9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc2 := setup()
	defer svc2.st.Close()
	if svc2.cfg.CoreIP != "100.64.0.9" {
		t.Fatalf("expected CoreIP from mesh-ip, got %q", svc2.cfg.CoreIP)
	}
}
