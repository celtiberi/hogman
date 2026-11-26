package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func doMeshReq(h http.Handler, method, path, srcIP, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:42424"
	req.Header.Set("X-Forwarded-For", srcIP)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMeshCSRFProtection(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "root", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "root", "personal", "root-laptop", "100.64.0.10", "")
	_, bobSrv := e.addDevice(t, "bob", "server", "bob-srv", "100.64.0.12", "")

	h := MeshHandler(e.svc)

	// Non-JSON Content-Type and missing Content-Type must be rejected with 415.
	cases415 := []struct {
		method, path, body string
		hdrs               map[string]string
	}{
		{"POST", "/api/devices", `{"kind":"personal"}`, map[string]string{"Content-Type": "text/plain"}},
		{"POST", "/api/devices", ``, nil},
		{"POST", "/api/admin/members/bob/suspend", ``, nil},
	}
	for _, tc := range cases415 {
		rec := doMeshReq(h, tc.method, tc.path, "100.64.0.10", tc.body, tc.hdrs)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("%s %s (%v): status=%d want 415 body=%s", tc.method, tc.path, tc.hdrs, rec.Code, rec.Body.String())
		}
	}

	// Cross-origin and same-site browser headers must be rejected with 403.
	cases403 := []struct {
		method, path, body string
		hdrs               map[string]string
	}{
		{"POST", "/api/devices", `{"kind":"personal"}`, map[string]string{
			"Content-Type": "application/json", "Sec-Fetch-Site": "same-site",
		}},
		{"POST", "/api/devices", `{"kind":"personal"}`, map[string]string{
			"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site",
		}},
		{"POST", "/api/devices", `{"kind":"personal"}`, map[string]string{
			"Content-Type": "application/json", "Origin": "https://bob.bobo.hogman",
		}},
		{"DELETE", "/api/devices/" + strconv.FormatInt(bobSrv.ID, 10), ``, map[string]string{
			"Sec-Fetch-Site": "same-site",
		}},
	}
	for _, tc := range cases403 {
		rec := doMeshReq(h, tc.method, tc.path, "100.64.0.10", tc.body, tc.hdrs)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s (%v): status=%d want 403 body=%s", tc.method, tc.path, tc.hdrs, rec.Code, rec.Body.String())
		}
	}

	// Non-browser CLI JSON request succeeds.
	rec := doMeshReq(h, "POST", "/api/devices", "100.64.0.10", `{"kind":"personal"}`, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("CLI POST /api/devices: status=%d want 201 body=%s", rec.Code, rec.Body.String())
	}

	// Same-origin browser JSON request succeeds.
	rec = doMeshReq(h, "POST", "/api/devices", "100.64.0.10", `{"kind":"personal"}`, map[string]string{
		"Content-Type":   "application/json",
		"Origin":         "https://home.bobo.hogman",
		"Sec-Fetch-Site": "same-origin",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("same-origin POST /api/devices: status=%d want 201 body=%s", rec.Code, rec.Body.String())
	}

	// Empty-body admin action with application/json succeeds; malformed JSON returns 400.
	rec = doMeshReq(h, "POST", "/api/admin/members/bob/suspend", "100.64.0.10", ``, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("empty-body suspend: status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	bobMember, err := e.st.MemberByHandle("bob")
	if err != nil || bobMember.Status != "suspended" {
		t.Fatalf("bob should be suspended, got %+v (err=%v)", bobMember, err)
	}

	rec = doMeshReq(h, "POST", "/api/admin/members/bob/resume", "100.64.0.10", `{bad`, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON resume: status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}
}

// A server (what `hogman share` starts) may name itself, release its own
// names and remove itself, but not touch its member's other names or devices.
func TestMeshServerNamesItself(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	_, laptop := e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.10", "")
	_, srvA := e.addDevice(t, "bob", "server", "a", "100.64.0.11", "")
	_, srvB := e.addDevice(t, "bob", "server", "b", "100.64.0.12", "")
	h := MeshHandler(e.svc)
	js := map[string]string{"Content-Type": "application/json"}
	want := func(code int, method, path, src, body string) {
		t.Helper()
		var hdrs map[string]string
		if method == "POST" {
			hdrs = js
		}
		if rec := doMeshReq(h, method, path, src, body, hdrs); rec.Code != code {
			t.Fatalf("%s %s from %s: status=%d want %d body=%s", method, path, src, rec.Code, code, rec.Body.String())
		}
	}
	id := func(d *Device) string { return strconv.FormatInt(d.ID, 10) }

	want(201, "POST", "/api/names", "100.64.0.11", `{"name":"blog"}`)                       // names itself
	want(201, "POST", "/api/names", "100.64.0.11", `{"name":"blog"}`)                       // again: still its own
	want(201, "POST", "/api/names", "100.64.0.11", `{"name":"x.blog"}`)                     // under its own name
	want(409, "POST", "/api/names", "100.64.0.12", `{"name":"blog"}`)                       // B can't take A's name
	want(403, "POST", "/api/names", "100.64.0.12", `{"name":"c","device_id":`+id(srvA)+`}`) // nor name A
	want(403, "DELETE", "/api/names/blog", "100.64.0.12", "")                               // nor release A's name
	want(403, "POST", "/api/names", "100.64.0.12", `{"name":"z.blog"}`)                     // B can't squat under A's name
	want(201, "POST", "/api/names", "100.64.0.10", `{"name":"y.blog","device_id":`+id(srvB)+`}`)
	want(403, "DELETE", "/api/names/blog", "100.64.0.11", "") // y.blog points at B now
	want(200, "DELETE", "/api/names/x.blog", "100.64.0.11", "")
	want(403, "DELETE", "/api/devices/"+id(srvB), "100.64.0.11", "")   // not another server
	want(403, "DELETE", "/api/devices/"+id(laptop), "100.64.0.11", "") // nor the laptop
	want(202, "DELETE", "/api/devices/"+id(srvA), "100.64.0.11", "")   // itself: accepted async (I-34)
	waitCtx, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	defer cancelWait()
	e.svc.WaitBackground(waitCtx)
	if got, err := e.st.DeviceByID(srvA.ID); err != nil || got.RemovedAt == nil {
		t.Fatalf("expected self-deleted server %d to be marked removed, got=%+v err=%v", srvA.ID, got, err)
	}
}

// The owner's server still counts against the names cap: a leaked server
// link can't claim names without limit.
func TestMeshOwnerServerNameCap(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.svc.AddMember(ctx, Actor{CLI: true}, "root", "owner"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "root", "server", "srv", "100.64.0.11", "")
	h := MeshHandler(e.svc)
	js := map[string]string{"Content-Type": "application/json"}
	got409 := false
	for i := 0; i <= e.svc.cfg.MaxNamesPerMember; i++ {
		rec := doMeshReq(h, "POST", "/api/names", "100.64.0.11", `{"name":"n`+strconv.Itoa(i)+`"}`, js)
		if rec.Code == http.StatusConflict {
			got409 = true
			break
		}
		if rec.Code != http.StatusCreated {
			t.Fatalf("claim n%d: status=%d body=%s", i, rec.Code, rec.Body.String())
		}
	}
	if !got409 {
		t.Fatalf("the owner's server claimed more than %d names", e.svc.cfg.MaxNamesPerMember)
	}
}

func TestMeshServerDeviceRestricted(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "root", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "root", "personal", "root-laptop", "100.64.0.10", "")
	e.addDevice(t, "root", "server", "root-srv", "100.64.0.11", "")

	h := MeshHandler(e.svc)

	// Server device can reach GET /api/me (trimmed payload) and GET /api/directory.
	rec := doMeshReq(h, "GET", "/api/me", "100.64.0.11", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("server GET /api/me: status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	var me map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	for _, hidden := range []string{"devices", "names", "invites"} {
		if _, exists := me[hidden]; exists {
			t.Fatalf("server GET /api/me should omit %q, got %v", hidden, me)
		}
	}
	if _, ok := me["member"]; !ok {
		t.Fatalf("server GET /api/me missing member: %v", me)
	}

	rec = doMeshReq(h, "GET", "/api/directory", "100.64.0.11", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("server GET /api/directory: status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}

	// Server device owned by owner must be denied all admin and mutating endpoints.
	denied := []struct{ method, path, body string }{
		{"GET", "/api/admin/members", ""},
		{"POST", "/api/admin/members/bob/role", `{"role":"owner"}`},
		{"POST", "/api/devices", `{"kind":"personal"}`},
		{"POST", "/api/names", `{"name":"x","device_id":1}`}, // not itself
		{"POST", "/api/invites", `{}`},
		{"DELETE", "/api/devices/1", ""},
	}
	for _, tc := range denied {
		hdrs := map[string]string{}
		if tc.method == "POST" {
			hdrs["Content-Type"] = "application/json"
		}
		rec := doMeshReq(h, tc.method, tc.path, "100.64.0.11", tc.body, hdrs)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("server %s %s: status=%d want 403 body=%s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}

	bobMember, err := e.st.MemberByHandle("bob")
	if err != nil || bobMember.Role != "member" {
		t.Fatalf("bob role should remain member, got %+v (err=%v)", bobMember, err)
	}

	// Owner's personal device can still use admin API.
	rec = doMeshReq(h, "GET", "/api/admin/members", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("personal owner GET /api/admin/members: status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
}

func TestIPReuseBlockedBeforeSync(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "root", "owner"); err != nil {
		t.Fatal(err)
	}
	bob, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "root", "personal", "root-laptop", "100.64.0.10", "")

	// Case 1: owner's device logged out and Headscale reassigned 100.64.0.10 to a stray/new node before Sync runs.
	e.hs.mu.Lock()
	e.hs.nodes = []HSNode{{
		ID:          "node-reassigned-stray",
		Name:        "bob-new",
		GivenName:   "bob-new",
		IPAddresses: []string{"100.64.0.10"},
	}}
	e.hs.mu.Unlock()

	h := MeshHandler(e.svc)
	rec := doMeshReq(h, "POST", "/api/admin/members/bob/role", "100.64.0.10", `{"role":"owner"}`, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reused IP (stray): status=%d want 403 body=%s", rec.Code, rec.Body.String())
	}
	bobAfter, err := e.st.MemberByHandle("bob")
	if err != nil || bobAfter.Role != "member" {
		t.Fatalf("bob should still be member, got %+v (err=%v)", bobAfter, err)
	}

	// Case 2: Bob joins with his own legitimate device key and receives 100.64.0.10 before Sync runs.
	bobKey, _, err := e.svc.IssueDeviceKey(ctx, cli, "bob", "personal")
	if err != nil {
		t.Fatal(err)
	}
	_ = bobKey
	// Find the issued key ID in DB.
	keys, err := e.st.OpenDeviceKeys(bob.ID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("expected 1 open key for bob, got %d (err=%v)", len(keys), err)
	}
	// Reset root-laptop row as if another owner device still had 100.64.0.10 in stale SQLite.
	e.addDevice(t, "root", "personal", "root-stale", "100.64.0.10", "")
	e.hs.mu.Lock()
	e.hs.nodes = []HSNode{{
		ID:          "node-bob-legit",
		Name:        "bob-laptop",
		GivenName:   "bob-laptop",
		IPAddresses: []string{"100.64.0.10"},
		PreAuthKey:  &HSPreAuthKey{ID: keys[0].HSKeyID},
	}}
	e.hs.mu.Unlock()

	rec = doMeshReq(h, "POST", "/api/admin/members/bob/role", "100.64.0.10", `{"role":"owner"}`, map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reused IP (bob legit key): status=%d want 403 body=%s", rec.Code, rec.Body.String())
	}
	bobAfter, _ = e.st.MemberByHandle("bob")
	if bobAfter.Role != "member" {
		t.Fatalf("bob should remain member, got %q", bobAfter.Role)
	}
}

func TestEmptyXFFDoesNotMatchIPv4OnlyDevice(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}

	if _, err := e.svc.AddMember(ctx, cli, "root", "owner"); err != nil {
		t.Fatal(err)
	}
	// IPv4-only device has ipv6 = "" in SQLite.
	e.addDevice(t, "root", "personal", "root-laptop", "100.64.0.10", "")

	h := MeshHandler(e.svc)
	for _, xff := range []string{"", "100.64.0.10, ", "not-an-ip"} {
		rec := doMeshReq(h, "GET", "/api/me", xff, "", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("X-Forwarded-For=%q: status=%d want 403 body=%s", xff, rec.Code, rec.Body.String())
		}
	}
}

func TestPublicRedeemRateLimit(t *testing.T) {
	e := newTestEnv(t)
	h := PublicHandlerWithRateLimit(e.svc, 2, time.Minute)

	send := func(remoteAddr, xff, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/hogman/v1/redeem", strings.NewReader(`{"token":"`+token+`","handle":"alice"}`))
		req.RemoteAddr = remoteAddr
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// First two requests from 198.51.100.1 pass rate limit (403 on bogus token); 3rd hits 429.
	for i := 0; i < 2; i++ {
		rec := send("172.18.0.2:1234", "198.51.100.1", "bad-token")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("req #%d: status=%d want 403 body=%s", i, rec.Code, rec.Body.String())
		}
	}
	rec := send("172.18.0.2:1234", "198.51.100.1", "hmi_nonexistent")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd req from same IP: status=%d want 429 body=%s", rec.Code, rec.Body.String())
	}

	// A different visitor IP is not blocked.
	rec = send("172.18.0.2:1234", "198.51.100.2", "bad-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("other IP: status=%d want 403 body=%s", rec.Code, rec.Body.String())
	}
}

func TestKeeperPageAPI(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	for h, r := range map[string]string{"root": "owner", "bob": "member"} {
		if _, err := e.svc.AddMember(ctx, cli, h, r); err != nil {
			t.Fatal(err)
		}
	}
	e.addDevice(t, "root", "personal", "root-laptop", "100.64.0.10", "")
	e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.11", "")
	h := MeshHandler(e.svc)
	js := map[string]string{"Content-Type": "application/json"}

	var me struct {
		CanInvite bool `json:"can_invite"`
		IsAdmin   bool `json:"is_admin"`
		IsOwner   bool `json:"is_owner"`
	}
	rec := doMeshReq(h, "GET", "/api/me", "100.64.0.10", "", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || !me.CanInvite || !me.IsAdmin || !me.IsOwner {
		t.Fatalf("owner /api/me: %+v %s", me, rec.Body.String())
	}
	me.CanInvite, me.IsAdmin, me.IsOwner = true, true, true
	rec = doMeshReq(h, "GET", "/api/me", "100.64.0.11", "", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || me.CanInvite || me.IsAdmin || me.IsOwner {
		t.Fatalf("member /api/me: %+v %s", me, rec.Body.String())
	}

	rec = doMeshReq(h, "POST", "/api/invites", "100.64.0.10", `{"note":"alice"}`, js)
	var inv struct {
		ID    int64  `json:"id"`
		URL   string `json:"url"`
		Token string `json:"token"`
		Note  string `json:"note"`
		QR    string `json:"qr_svg"`
	}
	if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &inv) != nil {
		t.Fatalf("mint invite: %d %s", rec.Code, rec.Body.String())
	}
	if inv.ID == 0 || inv.Note != "alice" || !strings.Contains(inv.URL, "/join#t="+inv.Token) || !strings.HasPrefix(inv.QR, "<svg") {
		t.Fatalf("invite response missing fields: %+v", inv)
	}
	if rec := doMeshReq(h, "POST", "/api/invites", "100.64.0.11", `{}`, js); rec.Code != 403 {
		t.Fatalf("member minted an invite on a network where only admins invite: %d", rec.Code)
	}
}

func TestHerdPagedAndSearched(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	if _, err := e.svc.AddMember(ctx, cli, "root", "owner"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "root", "personal", "root-laptop", "100.64.0.10", "")
	for i := 0; i < 45; i++ {
		h := "pig" + strconv.Itoa(100+i)
		if _, err := e.svc.AddMember(ctx, cli, h, "member"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.AddMember(ctx, cli, "zed", "admin"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "pig107", "personal", "a", "100.64.1.1", "")
	e.addDevice(t, "pig107", "server", "b", "100.64.1.2", "")
	e.addDevice(t, "pig101", "personal", "c", "100.64.1.3", "")
	if _, err := e.svc.Kick(ctx, cli, "pig101", "test"); err != nil {
		t.Fatal(err)
	}
	h := MeshHandler(e.svc)
	type page struct {
		Members []struct {
			Handle  string `json:"handle"`
			Role    string `json:"role"`
			Devices int    `json:"devices"`
		} `json:"members"`
		Total int `json:"total"`
	}
	get := func(path string) page {
		t.Helper()
		rec := doMeshReq(h, "GET", path, "100.64.0.10", "", nil)
		var p page
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &p) != nil {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		return p
	}

	p := get("/api/admin/herd")
	if p.Total != 46 || len(p.Members) != 20 {
		t.Fatalf("first page: total=%d len=%d (want 46 and 20: removed members left out)", p.Total, len(p.Members))
	}
	if p.Members[0].Handle != "root" || p.Members[1].Handle != "zed" {
		t.Fatalf("keepers should come first: %s, %s", p.Members[0].Handle, p.Members[1].Handle)
	}
	if last := get("/api/admin/herd?offset=40"); len(last.Members) != 6 {
		t.Fatalf("last page has %d, want 6", len(last.Members))
	}
	s := get("/api/admin/herd?q=PIG10")
	if s.Total != 9 { // pig100..pig109 without the kicked pig101
		t.Fatalf("search pig10: total=%d want 9", s.Total)
	}
	for _, m := range s.Members {
		if m.Handle == "pig107" && m.Devices != 2 {
			t.Fatalf("pig107 has %d devices, want 2", m.Devices)
		}
	}
	if rec := doMeshReq(h, "GET", "/api/admin/herd?q=a%25", "100.64.0.10", "", nil); rec.Code != 400 {
		t.Fatalf("a search with %% should be refused, got %d", rec.Code)
	}
	e.addDevice(t, "pig102", "personal", "d", "100.64.1.4", "")
	if rec := doMeshReq(h, "GET", "/api/admin/herd", "100.64.1.4", "", nil); rec.Code != 403 {
		t.Fatalf("a member listed the herd: %d", rec.Code)
	}
}

func TestNameDirectoryNoteAndMigration(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	for h, r := range map[string]string{"root": "owner", "alice": "member", "bob": "member"} {
		if _, err := e.svc.AddMember(ctx, cli, h, r); err != nil {
			t.Fatal(err)
		}
	}
	e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	e.addDevice(t, "alice", "server", "srvA", "100.64.0.11", "")
	_, bobSrv := e.addDevice(t, "bob", "server", "bobSrv", "100.64.0.12", "")
	_, srvA2 := e.addDevice(t, "alice", "server", "srvA2", "100.64.0.13", "")
	_, rootSrv := e.addDevice(t, "root", "server", "rootSrv", "100.64.0.14", "")
	h := MeshHandler(e.svc)
	js := map[string]string{"Content-Type": "application/json"}

	// Control characters, invisible fillers, Unicode bidi overrides, and newlines
	// are stripped while normal ZWJ emojis are preserved.
	body := `{"name":"photos","note":"  Summer\n\ttrip\u0000\u001b[31m\u202e\u200b\u3164   photos 👩\u200d💻  "}`
	if rec := doMeshReq(h, "POST", "/api/names", "100.64.0.11", body, js); rec.Code != 201 {
		t.Fatalf("server claim with note: %d %s", rec.Code, rec.Body.String())
	}

	// Rune cap is 140 runes for multi-byte UTF-8 text.
	longNote := strings.Repeat("é", 150)
	if _, err := e.svc.Claim(cli, "bob", "blog", bobSrv.ID, &longNote); err != nil {
		t.Fatalf("claim long note: %v", err)
	}

	type dirEntry struct {
		Name   string `json:"name"`
		Member string `json:"member"`
		Note   string `json:"note"`
	}
	readDir := func(src string) []dirEntry {
		t.Helper()
		rec := doMeshReq(h, "GET", "/api/directory", src, "", nil)
		if rec.Code != 200 {
			t.Fatalf("GET /api/directory: %d %s", rec.Code, rec.Body.String())
		}
		var out []dirEntry
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	got := readDir("100.64.0.10")
	if len(got) != 2 {
		t.Fatalf("directory len=%d want 2: %+v", len(got), got)
	}
	byName := map[string]dirEntry{}
	for _, d := range got {
		byName[d.Name] = d
	}
	if byName["photos.bobo.hogman"].Member != "alice" || byName["photos.bobo.hogman"].Note != "Summer trip[31m photos 👩‍💻" {
		t.Fatalf("photos directory entry = %+v", byName["photos.bobo.hogman"])
	}
	if gotRunes := len([]rune(byName["blog.bobo.hogman"].Note)); gotRunes != 140 {
		t.Fatalf("capped rune len = %d want 140", gotRunes)
	}

	// Server cannot alter note on a name owned by another server, leaving note intact.
	if rec := doMeshReq(h, "POST", "/api/names", "100.64.0.12", `{"name":"photos","note":"hijacked"}`, js); rec.Code != 409 {
		t.Fatalf("bobSrv overwrote alice's note: status=%d body=%s", rec.Code, rec.Body.String())
	}
	got = readDir("100.64.0.11")
	for _, d := range got {
		if d.Name == "photos.bobo.hogman" && d.Note != "Summer trip[31m photos 👩‍💻" {
			t.Fatalf("photos note mutated after 409: %+v", d)
		}
	}

	// Server updates its own note; bare re-claim from personal device omitting note preserves it and re-points to srvA2.
	if rec := doMeshReq(h, "POST", "/api/names", "100.64.0.11", `{"name":"photos","note":"updated note"}`, js); rec.Code != 201 {
		t.Fatalf("update note: %d %s", rec.Code, rec.Body.String())
	}
	repointBody := fmt.Sprintf(`{"name":"photos","device_id":%d}`, srvA2.ID)
	if rec := doMeshReq(h, "POST", "/api/names", "100.64.0.10", repointBody, js); rec.Code != 201 {
		t.Fatalf("repoint without note: %d %s", rec.Code, rec.Body.String())
	}
	rec := doMeshReq(h, "GET", "/api/me", "100.64.0.10", "", nil)
	var me struct {
		Names []Name `json:"names"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &me) != nil || len(me.Names) != 1 ||
		me.Names[0].Note != "updated note" || me.Names[0].DeviceID == nil || *me.Names[0].DeviceID != srvA2.ID {
		t.Fatalf("/api/me after bare repoint = %+v (body=%s)", me.Names, rec.Body.String())
	}
	if rec := doMeshReq(h, "POST", "/api/names", "100.64.0.13", `{"name":"photos","note":""}`, js); rec.Code != 201 {
		t.Fatalf("clear note from srvA2: %d %s", rec.Code, rec.Body.String())
	}
	n, err := e.st.NameByName("photos")
	if err != nil || n.Note != "" {
		t.Fatalf("cleared note: %+v err=%v", n, err)
	}

	// Owner takeover with nil note clears the previous owner's note instead of keeping it.
	if _, err := e.svc.Claim(cli, "root", "blog", rootSrv.ID, nil); err != nil {
		t.Fatalf("owner takeover with nil note: %v", err)
	}
	if n, err := e.st.NameByName("blog"); err != nil || n.Member != "root" || n.Note != "" {
		t.Fatalf("after takeover: %+v err=%v", n, err)
	}

	// Legacy SQLite database without names.note column migrates cleanly across concurrent OpenStore calls.
	legacyPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+legacyPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE members (id INTEGER PRIMARY KEY, handle TEXT NOT NULL UNIQUE, role TEXT NOT NULL, status TEXT NOT NULL, invited_by INTEGER, hs_user_id TEXT NOT NULL, created_at INTEGER NOT NULL, removed_at INTEGER);
		CREATE TABLE devices (id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL, kind TEXT NOT NULL, hs_node_id TEXT NOT NULL, name TEXT NOT NULL, ipv4 TEXT NOT NULL DEFAULT '', ipv6 TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, removed_at INTEGER);
		CREATE TABLE names (name TEXT PRIMARY KEY, member_id INTEGER NOT NULL, device_id INTEGER, held_until INTEGER, created_at INTEGER NOT NULL);
		INSERT INTO members (id, handle, role, status, hs_user_id, created_at) VALUES (1, 'alice', 'member', 'active', 'hs1', 1);
		INSERT INTO devices (id, member_id, kind, hs_node_id, name, ipv4, created_at) VALUES (1, 1, 'server', 'n1', 'srv', '100.64.0.99', 1);
		INSERT INTO names (name, member_id, device_id, created_at) VALUES ('old', 1, 1, 1);
	`)
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	const openers = 8
	start := make(chan struct{})
	type openRes struct {
		st  *Store
		err error
	}
	resCh := make(chan openRes, openers)
	var wg sync.WaitGroup
	for i := 0; i < openers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			st, err := OpenStore(legacyPath)
			resCh <- openRes{st: st, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(resCh)
	for res := range resCh {
		if res.st != nil {
			st := res.st
			t.Cleanup(func() { _ = st.db.Close() })
		}
		if res.err != nil {
			t.Fatalf("concurrent OpenStore legacy migrate: %v", res.err)
		}
	}
	st, err := OpenStore(legacyPath)
	if err != nil {
		t.Fatalf("OpenStore after concurrent migrate: %v", err)
	}
	defer st.db.Close()
	gotOld, err := st.NameByName("old")
	if err != nil || gotOld.Note != "" {
		t.Fatalf("legacy row after migrate: %+v err=%v", gotOld, err)
	}
	devID := int64(1)
	if err := st.UpsertName("newsite", 1, &devID, "hello"); err != nil {
		t.Fatalf("UpsertName after migrate: %v", err)
	}
}

// Removing a server device frees its names; a kick holds them instead.
func TestRemoveDeviceFreesItsNames(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	if _, err := e.svc.AddMember(ctx, cli, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	_, srv := e.addDevice(t, "bob", "server", "share-box", "100.64.0.12", "")
	if _, err := e.svc.Claim(cli, "bob", "photos", srv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RemoveDevice(ctx, cli, srv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.NameByName("photos"); err != ErrNotFound {
		t.Fatalf("name after device removal: err=%v, want ErrNotFound", err)
	}
}

// D-16 / I-22: owners and admins are told how many owners the pen has so the
// dashboard never reports "0 owners" to an admin; plain members do not get the
// field at all.
func TestOwnerCount(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	for _, m := range []struct{ handle, role string }{
		{"root", "owner"}, {"carol", "owner"}, {"ann", "admin"}, {"bob", "member"},
	} {
		if _, err := e.svc.AddMember(ctx, cli, m.handle, m.role); err != nil {
			t.Fatal(err)
		}
	}
	e.addDevice(t, "root", "personal", "root-laptop", "100.64.0.10", "")
	e.addDevice(t, "ann", "personal", "ann-laptop", "100.64.0.12", "")
	e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.14", "")
	h := MeshHandler(e.svc)
	owners := func(ip string) (float64, bool) {
		rec := doMeshReq(h, "GET", "/api/me", ip, "", nil)
		var me map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
			t.Fatalf("GET /api/me: %v (%s)", err, rec.Body.String())
		}
		raw, ok := me["owners"]
		if !ok {
			return 0, false
		}
		n, _ := raw.(float64)
		return n, true
	}
	if n, ok := owners("100.64.0.10"); !ok || n != 2 {
		t.Fatalf("owner sees owners=(%v, %v), want (2, true)", n, ok)
	}
	if n, ok := owners("100.64.0.12"); !ok || n != 2 {
		t.Fatalf("admin sees owners=(%v, %v), want (2, true)", n, ok)
	}
	if n, ok := owners("100.64.0.14"); ok {
		t.Fatalf("member should not receive owners field, got %v", n)
	}
}

func TestIPRateLimiterIPv6AndBoundedEviction(t *testing.T) {
	if a, b := rateLimitKey("2001:db8:cafe:1::1"), rateLimitKey("2001:db8:cafe:1:9999::2"); a != b {
		t.Fatalf("same IPv6 /64 should map identically: %q != %q", a, b)
	}
	if a, b := rateLimitKey("2001:db8:cafe:1::1"), rateLimitKey("2001:db8:cafe:2::1"); a == b {
		t.Fatalf("different IPv6 /64 should map differently: %q == %q", a, b)
	}
	if a, b := rateLimitKey("::ffff:192.0.2.10"), rateLimitKey("192.0.2.10"); a != b {
		t.Fatalf("v4-mapped IPv6 should match IPv4: %q != %q", a, b)
	}

	l := newSlidingWindow[string](2, time.Minute, 3)
	t0 := time.Now()
	if ok1, _ := l.Allow("abuser", t0); !ok1 {
		t.Fatal("abuser first hit should pass")
	}
	if ok2, _ := l.Allow("abuser", t0.Add(time.Second)); !ok2 {
		t.Fatal("abuser second hit should pass")
	}
	if ok3, _ := l.Allow("abuser", t0.Add(2*time.Second)); ok3 {
		t.Fatal("abuser should hit limit at 2")
	}
	if ok1, _ := l.Allow("idle", t0.Add(3*time.Second)); !ok1 {
		t.Fatal("idle should pass")
	}
	if ok2, _ := l.Allow("warm", t0.Add(4*time.Second)); !ok2 {
		t.Fatal("warm should pass")
	}
	// Touch abuser so "idle" is evicted instead of abuser when a 4th key floods in.
	if ok, _ := l.Allow("abuser", t0.Add(5*time.Second)); ok {
		t.Fatal("abuser should remain throttled")
	}
	if ok, _ := l.Allow("flooder", t0.Add(6*time.Second)); !ok {
		t.Fatal("flooder should be admitted by evicting idle")
	}
	if l.Len() > 3 {
		t.Fatalf("entries size = %d, want <= 3", l.Len())
	}
	if ok, _ := l.Allow("abuser", t0.Add(7*time.Second)); ok {
		t.Fatal("active abuser must stay throttled after eviction")
	}
}

// H2 (audit 2026-11): in a pen the mesh API listens only on a Unix socket that
// just the portal can reach, and a request arriving there is trusted to carry
// the caller's mesh address. Over the socket, an enrolled device is known.
func TestMeshAPIOverUnixSocket(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.svc.AddMember(ctx, Actor{CLI: true}, "root", "owner"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "root", "personal", "root-laptop", "100.64.0.10", "")

	// Short path: Unix socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "hm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "mesh.sock")
	ln, err := listenMesh("unix:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi, err)
	}
	srv := &http.Server{Handler: MeshHandler(e.svc), ConnContext: markSocketConn}
	go srv.Serve(ln)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	get := func(xff string) int {
		req, _ := http.NewRequest("GET", "http://portal/api/me", nil)
		req.Header.Set("X-Forwarded-For", xff)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("100.64.0.10"); code != http.StatusOK {
		t.Fatalf("enrolled device over the socket: %d, want 200", code)
	}
	if code := get("100.64.0.99"); code != http.StatusForbidden {
		t.Fatalf("unknown device over the socket: %d, want 403", code)
	}

	// A stale socket from a previous run is replaced, not an error.
	srv.Close()
	ln2, err := listenMesh("unix:" + path)
	if err != nil {
		t.Fatalf("relisten over a stale socket: %v", err)
	}
	ln2.Close()
}

func TestNetworkInfoTheme(t *testing.T) {
	// Default ("", "default") omits "theme" from JSON; "work" (case-insensitive)
	// exposes "theme":"work" on both /hogman/v1/network and /api/me; anything else fails.
	e := newTestEnv(t)
	if _, err := e.svc.AddMember(context.Background(), Actor{CLI: true}, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "alice", "personal", "laptop", "100.64.0.10", "")

	// Empty theme omits field on both public and mesh endpoints.
	req, _ := http.NewRequest("GET", "/hogman/v1/network", nil)
	rec := httptest.NewRecorder()
	PublicHandler(e.svc).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"theme"`) {
		t.Fatalf("default /hogman/v1/network: %d %s", rec.Code, rec.Body.String())
	}
	rec = doMeshReq(MeshHandler(e.svc), "GET", "/api/me", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"theme"`) {
		t.Fatalf("default /api/me: %d %s", rec.Code, rec.Body.String())
	}

	// Normalisation & invalid value check on NewService.
	cfg := e.svc.cfg
	cfg.Theme = "default"
	svcDef, err := NewService(cfg, e.svc.st, e.svc.hs)
	if err != nil || svcDef.NetworkInfo().Theme != "" {
		t.Fatalf("theme=default: svc=%v err=%v", svcDef, err)
	}
	cfg.Theme = "  WORK "
	svcWork, err := NewService(cfg, e.svc.st, e.svc.hs)
	if err != nil || svcWork.NetworkInfo().Theme != "work" {
		t.Fatalf("theme=WORK: svc=%v err=%v", svcWork, err)
	}
	req, _ = http.NewRequest("GET", "/hogman/v1/network", nil)
	rec = httptest.NewRecorder()
	PublicHandler(svcWork).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"theme":"work"`) {
		t.Fatalf("work /hogman/v1/network: %d %s", rec.Code, rec.Body.String())
	}
	rec = doMeshReq(MeshHandler(svcWork), "GET", "/api/me", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"theme":"work"`) {
		t.Fatalf("work /api/me: %d %s", rec.Code, rec.Body.String())
	}

	cfg.Theme = "neon"
	if _, err := NewService(cfg, e.svc.st, e.svc.hs); err == nil {
		t.Fatal("invalid theme accepted by NewService")
	}
}

func TestBillingStatusInMeAndRenewToken(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.svc.AddMember(context.Background(), Actor{CLI: true}, "alice", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddMember(context.Background(), Actor{CLI: true}, "bob", "member"); err != nil {
		t.Fatal(err)
	}
	e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.11", "")
	e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.12", "")

	dir := t.TempDir()
	billingPath := filepath.Join(dir, "billing-status.json")
	e.svc.cfg.BillingStatusPath = billingPath
	h := MeshHandler(e.svc)

	// Absent file -> no billing field in /api/me.
	rec := doMeshReq(h, "GET", "/api/me", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"billing"`) {
		t.Fatalf("absent billing /api/me: %d %s", rec.Code, rec.Body.String())
	}

	// Valid grace status -> admin sees can_renew:true, regular member sees can_renew:false (omitted),
	// and neither sees raw renew_url or renew.key.
	if err := os.WriteFile(billingPath, []byte(`{"pen":"bobo","state":"grace","grace_until":"2027-12-24T00:00:00Z","renew_url":"https://get.example.com"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rec = doMeshReq(h, "GET", "/api/me", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"grace"`) || !strings.Contains(rec.Body.String(), `"can_renew":true`) || strings.Contains(rec.Body.String(), "renew_url") {
		t.Fatalf("admin grace billing /api/me: %d %s", rec.Code, rec.Body.String())
	}
	rec = doMeshReq(h, "GET", "/api/me", "100.64.0.12", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"grace"`) || strings.Contains(rec.Body.String(), `"can_renew":true`) {
		t.Fatalf("member grace billing /api/me: %d %s", rec.Code, rec.Body.String())
	}

	// Regular member and server device cannot mint a renew token (403).
	js := map[string]string{"Content-Type": "application/json"}
	if rec := doMeshReq(h, "POST", "/api/billing/renew-token", "100.64.0.12", `{}`, js); rec.Code != http.StatusForbidden {
		t.Fatalf("member renew-token = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	if rec := doMeshReq(h, "POST", "/api/billing/renew-token", "100.64.0.11", `{}`, js); rec.Code != http.StatusForbidden {
		t.Fatalf("server renew-token = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}

	// Active admin on personal device mints a short-lived signed fragment token and creates 0600 renew.key.
	rec = doMeshReq(h, "POST", "/api/billing/renew-token", "100.64.0.10", `{}`, js)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin renew-token = %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		URL       string `json:"url"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !strings.HasPrefix(out.URL, "https://get.example.com/#renew=") {
		t.Fatalf("unexpected renew-token response: %s", rec.Body.String())
	}
	fi, err := os.Stat(filepath.Join(dir, "renew.key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("renew.key stat = (%v, %v), want 0600", fi, err)
	}

	// Non-HTTPS renew_url disables can_renew and refuses minting.
	if err := os.WriteFile(billingPath, []byte(`{"pen":"bobo","state":"grace","renew_url":"javascript:alert(1)"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rec = doMeshReq(h, "GET", "/api/me", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"can_renew":true`) || strings.Contains(rec.Body.String(), "javascript:") {
		t.Fatalf("non-https renew_url leaked: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doMeshReq(h, "POST", "/api/billing/renew-token", "100.64.0.10", `{}`, js); rec.Code != http.StatusConflict {
		t.Fatalf("renew-token with invalid renew_url = %d, want 409", rec.Code)
	}
}

func TestPortalPresenceDirectoryAndAdminDevices(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	cli := Actor{CLI: true}
	if _, err := e.svc.AddMember(ctx, cli, "alice", "owner"); err != nil {
		t.Fatal(err)
	}
	bobMember, err := e.svc.AddMember(ctx, cli, "bob", "member")
	if err != nil {
		t.Fatal(err)
	}
	_, aliceLaptop := e.addDevice(t, "alice", "personal", "alice-laptop", "100.64.0.10", "")
	_, bobLaptop := e.addDevice(t, "bob", "personal", "bob-laptop", "100.64.0.11", "")
	_, aliceSrv := e.addDevice(t, "alice", "server", "alice-srv", "100.64.0.20", "")
	_, bobSrv := e.addDevice(t, "bob", "server", "bob-srv", "100.64.0.21", "")
	_, bobGhost := e.addDevice(t, "bob", "server", "bob-ghost", "100.64.0.22", "")

	e.hs.mu.Lock()
	kept := e.hs.nodes[:0]
	for _, n := range e.hs.nodes {
		switch n.ID {
		case aliceLaptop.HSNodeID:
			n.Online = true
			n.LastSeen = "2026-11-24T06:15:30.123456-06:00"
		case bobLaptop.HSNodeID:
			n.Online = false
			n.LastSeen = "2026-11-23T22:00:00Z"
		case aliceSrv.HSNodeID:
			n.Online = true
			n.LastSeen = "2026-11-24T12:10:05.987654Z"
		case bobSrv.HSNodeID:
			n.Online = false
			n.LastSeen = "0001-01-01T00:00:00Z"
		case bobGhost.HSNodeID:
			// Drop bob-ghost from Headscale so it stays in SQLite but is absent from Headscale.
			continue
		}
		kept = append(kept, n)
	}
	e.hs.nodes = kept
	e.hs.mu.Unlock()

	if _, err := e.svc.Claim(cli, "alice", "photos", aliceSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(cli, "bob", "blog", bobSrv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Claim(cli, "bob", "ghost", bobGhost.ID, nil); err != nil {
		t.Fatal(err)
	}
	// Defense-in-depth: force a name row pointing at bob's personal laptop directly in SQLite
	// to verify /api/directory never leaks personal device presence.
	if err := e.st.UpsertName("laptop-leak", bobMember.ID, &bobLaptop.ID, ""); err != nil {
		t.Fatal(err)
	}

	h := MeshHandler(e.svc)

	// Regular member reads GET /api/directory: server sites include live online/last_seen,
	// offline server serializes explicit online:false with zero timestamp omitted, missing node
	// omits both, and personal device row omits both.
	rec := doMeshReq(h, "GET", "/api/directory", "100.64.0.11", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/directory = %d %s", rec.Code, rec.Body.String())
	}
	var dir []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &dir); err != nil {
		t.Fatalf("unmarshal /api/directory: %v (%s)", err, rec.Body.String())
	}
	dirByName := map[string]map[string]any{}
	for _, entry := range dir {
		dirByName[entry["name"].(string)] = entry
	}
	photos := dirByName["photos.bobo.hogman"]
	if photos["online"] != true || photos["last_seen"] != "2026-11-24T12:10:05Z" {
		t.Fatalf("photos presence = %#v, want online=true last_seen=2026-11-24T12:10:05Z", photos)
	}
	blog := dirByName["blog.bobo.hogman"]
	if v, ok := blog["online"]; !ok || v != false {
		t.Fatalf("blog online = (%v, %v), want explicit false", v, ok)
	}
	if _, ok := blog["last_seen"]; ok {
		t.Fatalf("blog zero last_seen should be omitted: %#v", blog)
	}
	ghost := dirByName["ghost.bobo.hogman"]
	if _, ok := ghost["online"]; ok {
		t.Fatalf("ghost missing node should omit online: %#v", ghost)
	}
	if _, ok := ghost["last_seen"]; ok {
		t.Fatalf("ghost missing node should omit last_seen: %#v", ghost)
	}
	leak := dirByName["laptop-leak.bobo.hogman"]
	if _, ok := leak["online"]; ok {
		t.Fatalf("personal device in directory must omit online: %#v", leak)
	}
	if _, ok := leak["last_seen"]; ok {
		t.Fatalf("personal device in directory must omit last_seen: %#v", leak)
	}

	// Regular member and server device cannot access GET /api/admin/devices.
	if rec := doMeshReq(h, "GET", "/api/admin/devices", "100.64.0.11", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("member GET /api/admin/devices = %d, want 403", rec.Code)
	}
	if rec := doMeshReq(h, "GET", "/api/admin/devices", "100.64.0.20", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("server GET /api/admin/devices = %d, want 403", rec.Code)
	}

	// Owner reads GET /api/admin/devices: both personal and server devices carry live Headscale presence.
	rec = doMeshReq(h, "GET", "/api/admin/devices", "100.64.0.10", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner GET /api/admin/devices = %d %s", rec.Code, rec.Body.String())
	}
	var devs []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &devs); err != nil {
		t.Fatalf("unmarshal /api/admin/devices: %v (%s)", err, rec.Body.String())
	}
	gotDev := map[string]map[string]any{}
	for _, d := range devs {
		gotDev[d["name"].(string)] = d
	}
	if gotDev["alice-laptop"]["online"] != true || gotDev["alice-laptop"]["last_seen"] != "2026-11-24T12:15:30Z" {
		t.Fatalf("alice-laptop presence = %#v, want online=true last_seen=2026-11-24T12:15:30Z", gotDev["alice-laptop"])
	}
	if v, ok := gotDev["bob-laptop"]["online"]; !ok || v != false || gotDev["bob-laptop"]["last_seen"] != "2026-11-23T22:00:00Z" {
		t.Fatalf("bob-laptop presence = %#v, want online=false last_seen=2026-11-23T22:00:00Z", gotDev["bob-laptop"])
	}
	if gotDev["alice-srv"]["online"] != true || gotDev["alice-srv"]["last_seen"] != "2026-11-24T12:10:05Z" {
		t.Fatalf("alice-srv presence = %#v", gotDev["alice-srv"])
	}
	if v, ok := gotDev["bob-srv"]["online"]; !ok || v != false {
		t.Fatalf("bob-srv online = (%v, %v), want explicit false", v, ok)
	}
	if _, ok := gotDev["bob-srv"]["last_seen"]; ok {
		t.Fatalf("bob-srv zero last_seen should be omitted: %#v", gotDev["bob-srv"])
	}
	if _, ok := gotDev["bob-ghost"]["online"]; ok {
		t.Fatalf("bob-ghost absent from Headscale should omit online: %#v", gotDev["bob-ghost"])
	}
}

func TestMeHelpersPropagateStoreErrors(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	owner, err := e.svc.AddMember(ctx, Actor{CLI: true}, "alice", "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ownerCount(e.svc, Actor{Member: owner}); err == nil {
		t.Fatal("ownerCount on closed store = nil, want error")
	}
	if _, err := buildPenDeleteView(e.svc, "alice", &hostMeta{Pen: "bobo", DeleteURL: "https://example.test"}); err == nil {
		t.Fatal("buildPenDeleteView on closed store = nil, want error")
	}
}
