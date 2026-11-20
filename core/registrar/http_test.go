package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
		{"POST", "/api/names", `{"name":"x","device_id":2}`},
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
