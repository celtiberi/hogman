package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHeadscaleTemplateDisablesNodeKeyExpiry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "templates", "headscale.yaml"))
	if err != nil {
		t.Fatalf("read headscale.yaml template: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "node:\n  expiry: 0") {
		t.Fatalf("headscale.yaml must set node.expiry: 0 so sleeping-pen owner keys never expire:\n%s", text)
	}
}

func TestRenewOnlyPolicyAndHTTPEnforcementI7(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.svc.AddMember(context.Background(), Actor{CLI: true}, "owner1", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(context.Background(), Actor{CLI: true}, "alice", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(context.Background(), Actor{CLI: true}, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "owner1", "personal", "owner-laptop", "100.64.0.9", "")
	e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")
	e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.12", "")

	dir := t.TempDir()
	billingPath := filepath.Join(dir, "billing-status.json")
	e.svc.cfg.BillingStatusPath = billingPath

	// Normal mode: everyone + servers grant present.
	normalPol, err := e.svc.buildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(normalPol, "100.64.0.12") || !strings.Contains(normalPol, "100.64.0.11") {
		t.Fatalf("normal policy missing member/server:\n%s", normalPol)
	}

	// Renew-only mode: ONLY active owner/admin personal devices -> tag:infra (53, 443).
	if err := os.WriteFile(billingPath, []byte(`{"pen":"bobo","state":"renew_only","wake_until":"2027-12-25T00:10:00Z","renew_url":"https://get.example.com"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	renewPol, err := e.svc.buildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Grants []struct {
			Src []string `json:"src"`
			Dst []string `json:"dst"`
			IP  []string `json:"ip"`
		} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(renewPol), &parsed); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	if len(parsed.Grants) != 1 {
		t.Fatalf("renew_only grants count = %d, want 1 (no servers grant):\n%s", len(parsed.Grants), renewPol)
	}
	if !strings.Contains(renewPol, "100.64.0.9") || !strings.Contains(renewPol, "100.64.0.10") {
		t.Fatalf("renew_only policy missing owner/admin personal devices:\n%s", renewPol)
	}
	if strings.Contains(renewPol, "100.64.0.11") || strings.Contains(renewPol, "100.64.0.12") {
		t.Fatalf("renew_only policy must exclude server and regular member devices:\n%s", renewPol)
	}

	// HTTP enforcement during renew_only:
	mesh := MeshHandler(e.svc)
	pub := PublicHandler(e.svc)
	js := map[string]string{"Content-Type": "application/json"}

	// Active owner/admin personal devices can call GET /api/me and POST /api/billing/renew-token.
	rec := doMeshReq(mesh, "GET", "/api/me", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"renew_only"`) || !strings.Contains(rec.Body.String(), `"wake_until":"2027-12-25T00:10:00Z"`) || !strings.Contains(rec.Body.String(), `"can_renew":true`) {
		t.Fatalf("admin renew_only /api/me: %d %s", rec.Code, rec.Body.String())
	}
	rec = doMeshReq(mesh, "POST", "/api/billing/renew-token", "100.64.0.10", `{}`, js)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "https://get.example.com/#renew=") {
		t.Fatalf("admin renew_only renew-token: %d %s", rec.Code, rec.Body.String())
	}

	// All other mesh API routes return 403 even for active owner/admin.
	for _, tc := range []struct {
		method, path, body string
	}{
		{"GET", "/api/directory", ""},
		{"POST", "/api/devices", `{"kind":"personal"}`},
		{"POST", "/api/invites", `{"role":"member"}`},
		{"GET", "/api/admin/members", ""},
	} {
		rec = doMeshReq(mesh, tc.method, tc.path, "100.64.0.10", tc.body, js)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("renew_only %s %s = %d, want 403 (%s)", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	// Regular member and server device get 403 on GET /api/me during renew_only.
	if rec := doMeshReq(mesh, "GET", "/api/me", "100.64.0.12", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("regular member renew_only /api/me = %d, want 403", rec.Code)
	}
	if rec := doMeshReq(mesh, "GET", "/api/me", "100.64.0.11", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("server device renew_only /api/me = %d, want 403", rec.Code)
	}

	// Public POST /hogman/v1/redeem returns 403 during renew_only.
	req := httptest.NewRequest("POST", "/hogman/v1/redeem", strings.NewReader(`{"token":"abc","handle":"carol"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	pub.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("public /hogman/v1/redeem during renew_only = %d, want 403 (%s)", rr.Code, rr.Body.String())
	}

	// Removing billing-status.json (payment completed) restores full policy immediately without restart.
	if err := os.Remove(billingPath); err != nil {
		t.Fatal(err)
	}
	restoredPol, err := e.svc.buildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if restoredPol != normalPol {
		t.Fatalf("policy did not restore cleanly after clearing billing-status.json:\ngot:\n%s\nwant:\n%s", restoredPol, normalPol)
	}

	// B4 (fail closed):
	// 1) .renew-only marker ALONE (without billing-status.json) forces renew_only policy & 403s.
	markerPath := filepath.Join(dir, ".renew-only")
	if err := os.WriteFile(markerPath, []byte("renew_only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !e.svc.isRenewOnly() {
		t.Fatal("marker alone must force isRenewOnly() = true")
	}
	markerPol, err := e.svc.buildPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if markerPol != renewPol {
		t.Fatalf("marker-only policy must equal renew_only policy:\ngot:\n%s", markerPol)
	}
	if rec := doMeshReq(mesh, "GET", "/api/directory", "100.64.0.10", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("marker-only /api/directory = %d, want 403", rec.Code)
	}
	if rec := doMeshReq(mesh, "GET", "/api/me", "100.64.0.10", "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"renew_only"`) {
		t.Fatalf("marker-only /api/me should still report renew_only: %d %s", rec.Code, rec.Body.String())
	}
	_ = os.Remove(markerPath)

	// 2) Corrupt/unparseable billing-status.json fails closed into renew_only.
	if err := os.WriteFile(billingPath, []byte(`{corrupt json`), 0o644); err != nil {
		t.Fatal(err)
	}
	if !e.svc.isRenewOnly() {
		t.Fatal("corrupt billing-status.json must fail closed into renew_only")
	}
	if rec := doMeshReq(mesh, "GET", "/api/directory", "100.64.0.10", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("corrupt billing-status.json /api/directory = %d, want 403", rec.Code)
	}

	// 3) Oversized (>4096B) billing-status.json fails closed into renew_only.
	if err := os.WriteFile(billingPath, []byte(strings.Repeat(" ", 5000)), 0o644); err != nil {
		t.Fatal(err)
	}
	if !e.svc.isRenewOnly() {
		t.Fatal("oversized billing-status.json must fail closed into renew_only")
	}
	_ = os.Remove(billingPath)
}

func TestHomeCertManagerRenewOnlyReuseAndCapI7(t *testing.T) {
	dir := t.TempDir()
	tlsDir := filepath.Join(dir, "tls")
	storageDir := filepath.Join(dir, "acme")
	billingPath := filepath.Join(dir, "billing-status.json")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(billingPath, []byte(`{"pen":"bobo","state":"renew_only","renew_url":"https://get.example.com"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a valid self-signed cert good for 10 days.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "home.bobo.example.test"},
		DNSNames:     []string{"home.bobo.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeHomeTLSAtomic(tlsDir, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	mgr, err := NewHomeCertManager(HomeConfig{
		Zone:              "bobo.example.test",
		HomeTLSDir:        tlsDir,
		StorageDir:        storageDir,
		PrimaryCA:         "https://127.0.0.1:1/unreachable-ca",
		Backend:           noopACMEBackend{},
		BillingStatusPath: billingPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	// 1. Existing valid cert (>1h left) is reused without touching the unreachable CA.
	if err := mgr.EnsureOnce(context.Background()); err != nil {
		t.Fatalf("renew_only should reuse valid cert on disk without calling CA: %v", err)
	}

	// 2. If cert is missing/expired during renew_only, at most 1 issuance attempt is allowed per wake.
	_ = os.Remove(filepath.Join(tlsDir, "home.crt"))
	_ = os.Remove(filepath.Join(tlsDir, "home.key"))
	if err := mgr.EnsureOnce(context.Background()); err == nil {
		t.Fatal("first attempt against unreachable CA should fail")
	}
	if err := mgr.EnsureOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "cap (1 per wake)") {
		t.Fatalf("second attempt during same renew_only wake = %v, want 1-per-wake cap error", err)
	}
}
