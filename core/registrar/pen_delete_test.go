package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"hogman/registrar/internal/api"
	"hogman/registrar/internal/billing"
	"hogman/registrar/internal/registrar"
)

func TestPenDeleteViewAndToken(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := registrar.Actor{CLI: true}
	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "zoe", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "carol", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "dan", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "kickedguy", "member"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Kick(ctx, cli, "kickedguy", "bye"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")
	e.addDevice(t, "dan", "personal", "dan-laptop", "100.64.0.12", "")
	e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.13", "")

	dir := t.TempDir()
	billingPath := filepath.Join(dir, "billing-status.json")
	metaPath := filepath.Join(dir, "host-meta.json")
	e.svc.SetBillingStatusPath(billingPath)
	h := api.MeshHandler(e.svc)
	js := map[string]string{"Content-Type": "application/json"}

	// Absent host-meta.json -> no pen_delete in /api/me and 409 on delete-token.
	rec := doMeshReq(h, "GET", "/api/me", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"pen_delete"`) {
		t.Fatalf("absent host-meta /api/me: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doMeshReq(h, "POST", "/api/pen/delete-token", "100.64.0.10", `{"confirm":"bobo"}`, js); rec.Code != http.StatusConflict {
		t.Fatalf("absent host-meta delete-token = %d, want 409", rec.Code)
	}

	// Valid host-meta.json must NOT trip isRenewOnlyMode() for active pens.
	if err := os.WriteFile(metaPath, []byte(`{"pen":"bobo","delete_url":"https://get.example.com","has_subscription":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if e.svc.IsRenewOnly() {
		t.Fatal("host-meta.json must not put an active pen into renew_only mode")
	}

	// Owner on personal device gets sorted other_owners, member/device counts, and no raw URL/key.
	rec = doMeshReq(h, "GET", "/api/me", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner /api/me = %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "delete_url") || strings.Contains(rec.Body.String(), "get.example.com") {
		t.Fatalf("/api/me leaked raw delete_url: %s", rec.Body.String())
	}
	var meOut struct {
		PenDelete *billing.PenDeleteView `json:"pen_delete"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &meOut); err != nil || meOut.PenDelete == nil {
		t.Fatalf("expected pen_delete in owner /api/me: %s", rec.Body.String())
	}
	if meOut.PenDelete.Pen != "bobo" || !meOut.PenDelete.CanDelete || !meOut.PenDelete.HasSubscription {
		t.Fatalf("unexpected pen_delete flags: %+v", meOut.PenDelete)
	}
	if !reflect.DeepEqual(meOut.PenDelete.OtherOwners, []string{"carol", "zoe"}) {
		t.Fatalf("other_owners = %v, want [carol zoe]", meOut.PenDelete.OtherOwners)
	}
	if meOut.PenDelete.MemberCount != 5 || meOut.PenDelete.DeviceCount != 4 {
		t.Fatalf("counts = (%d members, %d devices), want (5, 4)", meOut.PenDelete.MemberCount, meOut.PenDelete.DeviceCount)
	}

	// Admin, member, and server device do NOT see pen_delete and get 403 on delete-token.
	for _, tc := range []struct {
		who string
		ip  string
	}{
		{"admin", "100.64.0.12"},
		{"member", "100.64.0.13"},
		{"server", "100.64.0.11"},
	} {
		rec = doMeshReq(h, "GET", "/api/me", tc.ip, "", nil)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"pen_delete"`) {
			t.Fatalf("%s /api/me should omit pen_delete: %d %s", tc.who, rec.Code, rec.Body.String())
		}
		rec = doMeshReq(h, "POST", "/api/pen/delete-token", tc.ip, `{"confirm":"bobo"}`, js)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s delete-token = %d, want 403 (%s)", tc.who, rec.Code, rec.Body.String())
		}
	}

	// Wrong confirmation string -> 400.
	if rec := doMeshReq(h, "POST", "/api/pen/delete-token", "100.64.0.10", `{"confirm":"wrong"}`, js); rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong confirm delete-token = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}

	// Active owner on personal device mints token with hogman-delete-v1: HMAC and audit entry.
	rec = doMeshReq(h, "POST", "/api/pen/delete-token", "100.64.0.10", `{"confirm":"bobo"}`, js)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner delete-token = %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		URL       string `json:"url"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !strings.HasPrefix(out.URL, "https://get.example.com/#delete=") {
		t.Fatalf("unexpected delete-token response: %s", rec.Body.String())
	}
	tok := strings.TrimPrefix(out.URL, "https://get.example.com/#delete=")
	payloadB64, sigB64, ok := strings.Cut(tok, ".")
	if !ok {
		t.Fatalf("malformed token: %q", tok)
	}
	rawKey, err := os.ReadFile(filepath.Join(dir, "renew.key"))
	if err != nil {
		t.Fatalf("read renew.key: %v", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(rawKey)))
	if err != nil || len(key) != 32 {
		t.Fatalf("bad renew.key: %v", err)
	}
	sigBytes, _ := base64.RawURLEncoding.DecodeString(sigB64)
	// Domain separation: verifies under hogman-delete-v1:, fails under hogman-renew-v1:.
	delMAC := hmac.New(sha256.New, key)
	delMAC.Write([]byte("hogman-delete-v1:"))
	delMAC.Write([]byte(payloadB64))
	if !hmac.Equal(delMAC.Sum(nil), sigBytes) {
		t.Fatal("delete token did not verify under hogman-delete-v1:")
	}
	renMAC := hmac.New(sha256.New, key)
	renMAC.Write([]byte("hogman-renew-v1:"))
	renMAC.Write([]byte(payloadB64))
	if hmac.Equal(renMAC.Sum(nil), sigBytes) {
		t.Fatal("delete token must NOT verify under hogman-renew-v1:")
	}

	// Audit log recorded pen.delete.token.
	auditRows, err := e.st.AuditLog(10)
	if err != nil {
		t.Fatal(err)
	}
	foundAudit := false
	for _, a := range auditRows {
		if a.Action == "pen.delete.token" && a.Actor == "alice" && a.Target == "bobo" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Fatalf("expected pen.delete.token audit row, got %+v", auditRows)
	}

	// Delete works during renew_only mode too (owners only; admin still 403).
	if err := os.WriteFile(filepath.Join(dir, ".renew-only"), []byte("renew_only\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(billingPath, []byte(`{"pen":"bobo","state":"renew_only","renew_url":"https://get.example.com","wake_until":"`+time.Now().UTC().Add(10*time.Minute).Format(time.RFC3339)+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := doMeshReq(h, "POST", "/api/pen/delete-token", "100.64.0.10", `{"confirm":"bobo"}`, js); rec.Code != http.StatusOK {
		t.Fatalf("owner delete-token in renew_only = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := doMeshReq(h, "POST", "/api/pen/delete-token", "100.64.0.12", `{"confirm":"bobo"}`, js); rec.Code != http.StatusForbidden {
		t.Fatalf("admin delete-token in renew_only = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}

	// Non-HTTPS delete_url is rejected and omitted from /api/me.
	if err := os.WriteFile(metaPath, []byte(`{"pen":"bobo","delete_url":"javascript:alert(1)"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rec = doMeshReq(h, "GET", "/api/me", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"pen_delete"`) {
		t.Fatalf("non-https delete_url should omit pen_delete: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doMeshReq(h, "POST", "/api/pen/delete-token", "100.64.0.10", `{"confirm":"bobo"}`, js); rec.Code != http.StatusConflict {
		t.Fatalf("non-https delete_url delete-token = %d, want 409", rec.Code)
	}
}
