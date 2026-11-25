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
	"sync"
	"testing"
	"time"
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

	// Reset Headscale counters: steady-state direct auth must make ZERO Headscale calls.
	e.hs.mu.Lock()
	e.hs.listNodesCalls = 0
	e.hs.getNodeCalls = 0
	e.hs.mu.Unlock()

	// Bob connects from 100.64.0.20 but spoofs X-Forwarded-For: 100.64.0.10 (alice/owner).
	// Direct identity must identify him as bob and refuse admin endpoints.
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
		t.Fatalf("steady-state GET /api/me hit Headscale (list=%d, get=%d); want 0", listCalls, getCalls)
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

func TestVerifyDirectPeerSecurityAndBackfill(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	nowTime := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	e.svc.nowFn = func() time.Time { return nowTime }

	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	_, d := e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.10", "")

	// 1. Wrong node key must fail closed even when HSNodeID and IP match.
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: d.HSNodeID, NodeKey: "nodekey:wrong",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched node key: err=%v want ErrNotFound", err)
	}

	// 2. Expired key must fail closed.
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: d.HSNodeID, NodeKey: d.NodeKey,
		KeyExpiry: nowTime.Add(-time.Second),
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired key: err=%v want ErrNotFound", err)
	}

	// 3. Valid non-expired key succeeds even if display-only presence snapshot is empty or poisoned.
	e.svc.presenceMu.Lock()
	e.svc.presenceByID = map[string]HSNode{} // empty/missing device in presence snapshot
	e.svc.presenceAt = nowTime
	e.svc.presenceMu.Unlock()
	m, gotD, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: d.HSNodeID, NodeKey: d.NodeKey,
		KeyExpiry: nowTime.Add(time.Hour),
	})
	if err != nil || m.Handle != "bob" || gotD.ID != d.ID {
		t.Fatalf("valid peer with empty presence snapshot failed: m=%v d=%v err=%v", m, gotD, err)
	}

	// 4. Suspending in SQLite immediately blocks direct handler even if WhoIs still resolves the peer.
	if err := e.svc.Suspend(ctx, cli, "bob", "test"); err != nil {
		t.Fatal(err)
	}
	h := MeshHandlerDirect(e.svc, func(_ context.Context, _ string) (*PeerIdentity, error) {
		return &PeerIdentity{IP: "100.64.0.10", HSNodeID: d.HSNodeID, NodeKey: d.NodeKey}, nil
	})
	req := httptest.NewRequest("GET", "/api/me", nil)
	req.RemoteAddr = "100.64.0.10:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("suspended member status=%d want 403", rec.Code)
	}
	if err := e.svc.Resume(ctx, cli, "bob"); err != nil {
		t.Fatal(err)
	}

	// 5. Legacy device row with empty node_key is backfilled on first auth via Sync, then needs 0 Headscale calls.
	if err := e.st.UpdateDevice(d.ID, d.Name, d.IPv4, d.IPv6, ""); err != nil {
		t.Fatal(err)
	}
	e.hs.mu.Lock()
	e.hs.listNodesCalls = 0
	e.hs.mu.Unlock()
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: d.HSNodeID, NodeKey: d.NodeKey,
	}); err != nil {
		t.Fatalf("legacy node_key backfill failed: %v", err)
	}
	e.hs.mu.Lock()
	backfillCalls := e.hs.listNodesCalls
	e.hs.mu.Unlock()
	if backfillCalls != 1 {
		t.Fatalf("expected 1 Sync call to backfill node_key, got %d", backfillCalls)
	}
	if _, _, err := e.svc.VerifyDirectPeer(ctx, &PeerIdentity{
		IP: "100.64.0.10", HSNodeID: d.HSNodeID, NodeKey: d.NodeKey,
	}); err != nil {
		t.Fatalf("second auth after backfill failed: %v", err)
	}
	e.hs.mu.Lock()
	afterCalls := e.hs.listNodesCalls
	e.hs.mu.Unlock()
	if afterCalls != 1 {
		t.Fatalf("expected 0 extra Headscale calls after backfill, got %d", afterCalls-1)
	}
}

func TestPresenceSnapshotCachedAndSyncSingleFlightAdaptive(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	nowTime := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	e.svc.nowFn = func() time.Time { return nowTime }

	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")

	// Before first sync, NeedsFastSync is true; after idle sync with no open keys, it becomes false.
	if !e.svc.NeedsFastSync() {
		t.Fatal("expected NeedsFastSync=true before initial Sync")
	}
	if err := e.svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if e.svc.NeedsFastSync() {
		t.Fatal("expected NeedsFastSync=false when idle with no open device keys")
	}

	// PresenceSnapshot reuses Sync's snapshot within TTL (0 extra Headscale calls).
	e.hs.mu.Lock()
	e.hs.listNodesCalls = 0
	e.hs.mu.Unlock()
	snap := e.svc.PresenceSnapshot(ctx)
	if len(snap) != 1 {
		t.Fatalf("snapshot len=%d want 1", len(snap))
	}
	e.hs.mu.Lock()
	calls := e.hs.listNodesCalls
	e.hs.mu.Unlock()
	if calls != 0 {
		t.Fatalf("PresenceSnapshot hit Headscale within TTL (%d calls), want 0", calls)
	}

	// Advancing past TTL triggers one refresh.
	nowTime = nowTime.Add(10 * time.Second)
	_ = e.svc.PresenceSnapshot(ctx)
	e.hs.mu.Lock()
	calls = e.hs.listNodesCalls
	e.hs.mu.Unlock()
	if calls != 1 {
		t.Fatalf("PresenceSnapshot after TTL made %d calls, want 1", calls)
	}

	// Issuing a device key immediately flips NeedsFastSync back to true and wakes the sync loop.
	if _, _, err := e.svc.IssueDeviceKey(ctx, cli, "alice", "server"); err != nil {
		t.Fatal(err)
	}
	if !e.svc.NeedsFastSync() {
		t.Fatal("expected NeedsFastSync=true while an open device key exists")
	}
	select {
	case <-e.svc.SyncWake():
	default:
		t.Fatal("expected IssueDeviceKey to signal SyncWake")
	}

	// Single-flight Sync: concurrent callers share one in-flight pass.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- e.svc.Sync(ctx)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Sync err: %v", err)
		}
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
