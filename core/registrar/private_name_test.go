package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var privateLabelFormatRE = regexp.MustCompile(`^[a-z][a-z0-9]{11}$`)

func TestPrivateNameHTTPFlowRetryAndD21Retirement(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	e.addDevice(t, "alice", "server", "cooler-1", "100.64.0.11", "")
	e.addDevice(t, "alice", "server", "cooler-2", "100.64.0.12", "")
	e.addDevice(t, "alice", "server", "manager", "100.64.0.13", "")
	e.addDevice(t, "alice", "server", "named-srv", "100.64.0.14", "")

	h := MeshHandler(e.svc)
	jsonHdr := map[string]string{"Content-Type": "application/json"}

	// Reject passing both name and private: true.
	rec := doMeshReq(h, "POST", "/api/names", "100.64.0.11", `{"name":"cameras","private":true}`, jsonHdr)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("both name and private: status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}

	// Server 1 claims a private name with a friendly note.
	rec = doMeshReq(h, "POST", "/api/names", "100.64.0.11", `{"private":true,"note":"Cooler 1 - North Bay"}`, jsonHdr)
	if rec.Code != http.StatusCreated {
		t.Fatalf("server1 private claim: status=%d want 201 body=%s", rec.Code, rec.Body.String())
	}
	var resp1 struct {
		Name    string `json:"name"`
		Private bool   `json:"private"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp1); err != nil {
		t.Fatal(err)
	}
	if !resp1.Private {
		t.Fatalf("expected private=true in response, got %s", rec.Body.String())
	}
	label1 := strings.TrimSuffix(resp1.Name, "."+e.svc.cfg.Zone)
	if !privateLabelFormatRE.MatchString(label1) {
		t.Fatalf("private label %q does not match ^[a-z][a-z0-9]{11}$", label1)
	}

	// Crash-safe idempotent retry: exact same server calling private: true again
	// returns the SAME label (and updates note when provided).
	rec = doMeshReq(h, "POST", "/api/names", "100.64.0.11", `{"private":true,"note":"Cooler 1 - Updated"}`, jsonHdr)
	if rec.Code != http.StatusCreated {
		t.Fatalf("server1 private retry: status=%d want 201 body=%s", rec.Code, rec.Body.String())
	}
	var resp1Retry struct {
		Name    string `json:"name"`
		Private bool   `json:"private"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp1Retry); err != nil {
		t.Fatal(err)
	}
	if resp1Retry.Name != resp1.Name {
		t.Fatalf("server1 retry minted new name %q, want %q", resp1Retry.Name, resp1.Name)
	}

	// Re-asserting by explicit label on restart preserves private=true.
	rec = doMeshReq(h, "POST", "/api/names", "100.64.0.11", `{"name":"`+label1+`","note":"Cooler 1 - Final"}`, jsonHdr)
	if rec.Code != http.StatusCreated {
		t.Fatalf("server1 restart claim: status=%d want 201 body=%s", rec.Code, rec.Body.String())
	}

	// Server 2 (a separate server device) MUST get its own distinct random label.
	rec = doMeshReq(h, "POST", "/api/names", "100.64.0.12", `{"private":true,"note":"Cooler 2"}`, jsonHdr)
	if rec.Code != http.StatusCreated {
		t.Fatalf("server2 private claim: status=%d want 201 body=%s", rec.Code, rec.Body.String())
	}
	var resp2 struct {
		Name    string `json:"name"`
		Private bool   `json:"private"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp2); err != nil {
		t.Fatal(err)
	}
	if resp2.Name == resp1.Name {
		t.Fatalf("server2 reused server1's private name %q", resp1.Name)
	}

	// Server 4 claims a normal named site, then tries private: true -> 409 conflict.
	rec = doMeshReq(h, "POST", "/api/names", "100.64.0.14", `{"name":"blog","note":"Publicly named"}`, jsonHdr)
	if rec.Code != http.StatusCreated {
		t.Fatalf("named-srv claim: status=%d want 201 body=%s", rec.Code, rec.Body.String())
	}
	rec = doMeshReq(h, "POST", "/api/names", "100.64.0.14", `{"private":true}`, jsonHdr)
	if rec.Code != http.StatusConflict {
		t.Fatalf("named-srv private claim: status=%d want 409 body=%s", rec.Code, rec.Body.String())
	}

	// Headless managing server (100.64.0.13) reads GET /api/directory without a browser
	// and sees both private sites with private=true, their notes, and the named site with private=false.
	rec = doMeshReq(h, "GET", "/api/directory", "100.64.0.13", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("manager GET /api/directory: status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	var dir []directoryEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &dir); err != nil {
		t.Fatal(err)
	}
	byName := map[string]directoryEntry{}
	for _, d := range dir {
		byName[d.Name] = d
	}
	if d, ok := byName[resp1.Name]; !ok || !d.Private || d.Note != "Cooler 1 - Final" || d.Member != "alice" {
		t.Fatalf("unexpected directory entry for server1: %+v (ok=%v)", d, ok)
	}
	if d, ok := byName["blog."+e.svc.cfg.Zone]; !ok || d.Private {
		t.Fatalf("unexpected directory entry for named blog: %+v (ok=%v)", d, ok)
	}

	// D-21: releasing a private name permanently retires it (never recycled),
	// removes it from /api/directory, and frees the member's active quota.
	rec = doMeshReq(h, "DELETE", "/api/names/"+label1, "100.64.0.11", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("server1 DELETE private name: status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	row, err := e.st.NameByName(label1)
	if err != nil {
		t.Fatalf("expected retired row for %q, got err=%v", label1, err)
	}
	if row.RetiredAt == nil {
		t.Fatalf("expected %q to have RetiredAt set after release (D-21)", label1)
	}
	if row.Note != "" {
		t.Fatalf("expected retired note cleared, got %q", row.Note)
	}
	// Explicit reclaim of retired private label must fail with 409.
	rec = doMeshReq(h, "POST", "/api/names", "100.64.0.11", `{"name":"`+label1+`"}`, jsonHdr)
	if rec.Code != http.StatusConflict {
		t.Fatalf("reclaim retired private label: status=%d want 409 body=%s", rec.Code, rec.Body.String())
	}
	// Active quota should count only cooler-2 + blog = 2 (retired label1 freed).
	alice, _ := e.st.MemberByHandle("alice")
	if cnt, err := e.st.CountMemberNames(alice.ID); err != nil || cnt != 2 {
		t.Fatalf("CountMemberNames = %d (err=%v), want 2", cnt, err)
	}
}

func TestPrivateNameCollisionRetryAndExhaustion(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	_, srv1 := e.addDevice(t, "alice", "server", "srv1", "100.64.0.11", "")
	_, srv2 := e.addDevice(t, "alice", "server", "srv2", "100.64.0.12", "")
	alice, _ := e.st.MemberByHandle("alice")
	actor := Actor{Member: alice}

	// Pre-populate one active and one retired label.
	if _, err := e.svc.Claim(actor, "alice", "aaaaaaaaaaaa", srv1.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.st.UpsertNameWithPrivate("bbbbbbbbbbbb", alice.ID, &srv1.ID, "", true); err != nil {
		t.Fatal(err)
	}
	if err := e.st.RetireName("bbbbbbbbbbbb"); err != nil {
		t.Fatal(err)
	}

	// Sequence: reserved ("home"), active ("aaaaaaaaaaaa"), retired ("bbbbbbbbbbbb"), then free ("c1d2e3f4g5h6").
	seq := []string{"home", "aaaaaaaaaaaa", "bbbbbbbbbbbb", "c1d2e3f4g5h6"}
	idx := 0
	e.svc.privateLabelFn = func() (string, error) {
		out := seq[idx]
		idx++
		return out, nil
	}
	fqdn, err := e.svc.ServerClaimPrivate(actor, srv2, nil)
	if err != nil {
		t.Fatalf("expected retry to succeed on 4th candidate, got err=%v", err)
	}
	if fqdn != "c1d2e3f4g5h6."+e.svc.cfg.Zone {
		t.Fatalf("got %q, want c1d2e3f4g5h6.%s", fqdn, e.svc.cfg.Zone)
	}

	// Exhaust all 8 attempts -> clean 503 error and no row added.
	_, srv3 := e.addDevice(t, "alice", "server", "srv3", "100.64.0.13", "")
	attempts := 0
	e.svc.privateLabelFn = func() (string, error) {
		attempts++
		return "aaaaaaaaaaaa", nil
	}
	_, err = e.svc.ServerClaimPrivate(actor, srv3, nil)
	if err == nil {
		t.Fatalf("expected error when all 8 attempts collide")
	}
	var prob *Problem
	if !errors.As(err, &prob) || prob.Status != 503 {
		t.Fatalf("expected 503 Problem, got %v", err)
	}
	if !strings.Contains(err.Error(), "after 8 attempts") {
		t.Fatalf("unexpected error message: %v", err)
	}
	if attempts != 8 {
		t.Fatalf("attempts = %d, want 8", attempts)
	}
}

func TestMigrateNamesPrivateColumn(t *testing.T) {
	p := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE members (id INTEGER PRIMARY KEY, handle TEXT UNIQUE NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, invited_by INTEGER, hs_user_id TEXT NOT NULL, created_at INTEGER NOT NULL, removed_at INTEGER);
		CREATE TABLE devices (id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL, hs_node_id TEXT NOT NULL, ipv4 TEXT NOT NULL DEFAULT '', ipv6 TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, removed_at INTEGER);
		CREATE TABLE names (name TEXT PRIMARY KEY, member_id INTEGER NOT NULL, device_id INTEGER, note TEXT NOT NULL DEFAULT '', held_until INTEGER, created_at INTEGER NOT NULL);
	`)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	st, err := OpenStore(p)
	if err != nil {
		t.Fatalf("OpenStore on legacy DB failed: %v", err)
	}
	defer st.Close()
	has, err := hasColumn(st.db, "names", "private")
	if err != nil || !has {
		t.Fatalf("expected names.private column after migration, has=%v err=%v", has, err)
	}
}
