package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeAtomicSnapshot(t *testing.T, dir, content string) {
	t.Helper()
	tmp := filepath.Join(dir, "snapshot.json.tmp")
	dst := filepath.Join(dir, snapshotFileName)
	if err := os.WriteFile(tmp, []byte(content), 0o640); err != nil {
		t.Fatalf("write tmp snapshot: %v", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		t.Fatalf("rename snapshot: %v", err)
	}
}

func TestOpsAuthFailClosedAndAudit(t *testing.T) {
	dir := t.TempDir()
	writeAtomicSnapshot(t, dir, `{"generated_at":"2026-11-24T12:00:00Z","host":{"name":"host-a","version":"v1","capacity":{"live":1,"max":10}},"pens":[],"waitlist":{"waiting":2,"invited":0,"oldest_waiting_age_sec":3600}}`)

	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	var auditBuf bytes.Buffer
	srv, err := newOpsServer(opsConfig{
		SnapshotDir:    dir,
		AllowedHandles: parseAllowedHandles("alice,bob"),
		AuditOut:       &auditBuf,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	req := func(method, path string, hdrs map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, r)
		return rec
	}

	// 1. Missing X-Hogman-Handle -> 403.
	if rec := req(http.MethodGet, "/api/ops/snapshot", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("missing handle = %d, want 403", rec.Code)
	}

	// 2. Unlisted handle -> 403.
	if rec := req(http.MethodGet, "/api/ops/snapshot", map[string]string{"X-Hogman-Handle": "mallory"}); rec.Code != http.StatusForbidden {
		t.Fatalf("unlisted handle = %d, want 403", rec.Code)
	}

	// 3. Tagged server device (even with allowlisted handle) -> 403.
	if rec := req(http.MethodGet, "/api/ops/snapshot", map[string]string{
		"X-Hogman-Handle": "alice",
		"X-Hogman-Tags":   "tag:server",
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("tagged peer = %d, want 403", rec.Code)
	}

	// 4. Cross-origin / same-site browser fetch on API -> 403.
	for _, sfs := range []string{"cross-site", "same-site"} {
		if rec := req(http.MethodGet, "/api/ops/snapshot", map[string]string{
			"X-Hogman-Handle": "alice",
			"Sec-Fetch-Site":  sfs,
		}); rec.Code != http.StatusForbidden {
			t.Fatalf("Sec-Fetch-Site=%s = %d, want 403", sfs, rec.Code)
		}
	}

	// 5. Write verbs -> 405 Method Not Allowed.
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if rec := req(m, "/api/ops/snapshot", map[string]string{"X-Hogman-Handle": "alice"}); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s = %d, want 405", m, rec.Code)
		}
	}

	// 6. Empty OPS_HANDLES -> deny-all even with a valid handle.
	denyAll, err := newOpsServer(opsConfig{
		SnapshotDir:    dir,
		AllowedHandles: parseAllowedHandles(""),
		AuditOut:       &auditBuf,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/ops/snapshot", nil)
	r.Header.Set("X-Hogman-Handle", "alice")
	rec := httptest.NewRecorder()
	denyAll.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("empty OPS_HANDLES = %d, want 403", rec.Code)
	}

	// All 9 denied requests above must have emitted denied audit lines.
	lines := strings.Split(strings.TrimSpace(auditBuf.String()), "\n")
	if len(lines) != 9 {
		t.Fatalf("denied audit lines = %d, want 9:\n%s", len(lines), auditBuf.String())
	}
	for _, ln := range lines {
		var ev auditEvent
		if err := json.Unmarshal([]byte(ln), &ev); err != nil || ev.Event != "denied" {
			t.Fatalf("bad denied audit line %q (err=%v)", ln, err)
		}
	}
}

func TestOpsAtomicRenameAndSchemaSanitization(t *testing.T) {
	dir := t.TempDir()
	// First snapshot includes unexpected PII fields (email, note, entries) to verify strict schema stripping.
	writeAtomicSnapshot(t, dir, `{
		"generated_at": "2026-11-24T12:00:00Z",
		"host": {"name": "host-a", "version": "v1", "capacity": {"live": 2, "max": 40}},
		"pens": [{"name": "alpha", "plan": "personal", "theme": "default", "state": "running", "containers_up": 4, "containers_total": 4, "ram_bytes": 1024, "setpolicy_samples": 10, "setpolicy_last_ms": 203, "setpolicy_p95_ms": 1490}],
		"waitlist": {
			"waiting": 3,
			"invited": 1,
			"oldest_waiting_age_sec": 7200,
			"entries": [{"id": 1, "email": "leak@example.com", "note": "secret note"}]
		}
	}`)

	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	var auditBuf bytes.Buffer
	srv, err := newOpsServer(opsConfig{
		SnapshotDir:    dir,
		AllowedHandles: parseAllowedHandles("alice"),
		AuditOut:       &auditBuf,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("X-Hogman-Handle", "alice")
		r.Header.Set("X-Hogman-Node", "alice-laptop")
		r.Header.Set("X-Hogman-IP", "100.64.0.10")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, r)
		return rec
	}

	// Page load + security headers.
	pageRec := get("/")
	if pageRec.Code != http.StatusOK || !strings.Contains(pageRec.Body.String(), "Hogman Fleet Ops") {
		t.Fatalf("GET / = %d", pageRec.Code)
	}
	if pageRec.Header().Get("X-Frame-Options") != "DENY" || pageRec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(pageRec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("missing security headers: %v", pageRec.Header())
	}

	// First read sees v1 and strips unexpected waitlist PII fields.
	rec1 := get("/api/ops/snapshot")
	if rec1.Code != http.StatusOK {
		t.Fatalf("first snapshot = %d %s", rec1.Code, rec1.Body.String())
	}
	body1 := rec1.Body.String()
	if strings.Contains(body1, "leak@example.com") || strings.Contains(body1, "secret note") || strings.Contains(body1, `"entries"`) {
		t.Fatalf("unexpected PII/entries leaked in response: %s", body1)
	}
	var out1 snapshotResponse
	if err := json.Unmarshal(rec1.Body.Bytes(), &out1); err != nil {
		t.Fatal(err)
	}
	if out1.Viewer != "alice" || out1.Host.Version != "v1" || out1.Host.Capacity.Live != 2 || out1.Waitlist.Waiting != 3 {
		t.Fatalf("unexpected v1 payload: %+v", out1)
	}
	if len(out1.Pens) != 1 || out1.Pens[0].SetPolicySamples != 10 || out1.Pens[0].SetPolicyLastMs != 203 || out1.Pens[0].SetPolicyP95Ms != 1490 {
		t.Fatalf("unexpected pen SetPolicy metrics: %+v", out1.Pens)
	}

	// Atomic rename on host replaces snapshot.json with a brand-new inode (v2).
	writeAtomicSnapshot(t, dir, `{
		"generated_at": "2026-11-24T12:01:00Z",
		"host": {"name": "host-a", "version": "v2", "capacity": {"live": 5, "max": 40}},
		"pens": [],
		"waitlist": {"waiting": 4, "invited": 2, "oldest_waiting_age_sec": 7260}
	}`)

	// Second read MUST serve v2 (proving directory re-open picks up the new inode).
	rec2 := get("/api/ops/snapshot")
	if rec2.Code != http.StatusOK {
		t.Fatalf("second snapshot = %d %s", rec2.Code, rec2.Body.String())
	}
	var out2 snapshotResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &out2); err != nil {
		t.Fatal(err)
	}
	if out2.Host.Version != "v2" || out2.Host.Capacity.Live != 5 || out2.Waitlist.Waiting != 4 {
		t.Fatalf("atomic rename did not serve v2: %+v", out2)
	}

	// Additional polls within allowedAuditTTL must NOT flood the audit log:
	// 1 page load ("/") + multiple API polls = 1 allowed audit line total.
	for i := 0; i < 4; i++ {
		if r := get("/api/ops/snapshot"); r.Code != http.StatusOK {
			t.Fatalf("poll %d = %d", i, r.Code)
		}
	}
	lines := strings.Split(strings.TrimSpace(auditBuf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("allowed audit lines = %d, want 1 (page load suppresses poll spam):\n%s", len(lines), auditBuf.String())
	}

	// After allowedAuditTTL passes, a direct API read logs one new allowed audit line.
	now = now.Add(allowedAuditTTL + time.Second)
	if r := get("/api/ops/snapshot"); r.Code != http.StatusOK {
		t.Fatalf("post-TTL poll = %d", r.Code)
	}
	lines = strings.Split(strings.TrimSpace(auditBuf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("post-TTL allowed audit lines = %d, want 2:\n%s", len(lines), auditBuf.String())
	}
}
