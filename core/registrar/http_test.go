package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
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
