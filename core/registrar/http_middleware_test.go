package main

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnforceRoutePolicyMatrix(t *testing.T) {
	ownerPersonal := caller{
		member: &Member{ID: 1, Handle: "owner", Role: "owner", Status: "active"},
		device: &Device{ID: 10, Kind: "personal"},
	}
	adminPersonal := caller{
		member: &Member{ID: 2, Handle: "admin", Role: "admin", Status: "active"},
		device: &Device{ID: 11, Kind: "personal"},
	}
	memberPersonal := caller{
		member: &Member{ID: 3, Handle: "bob", Role: "member", Status: "active"},
		device: &Device{ID: 12, Kind: "personal"},
	}
	ownerServer := caller{
		member: &Member{ID: 1, Handle: "owner", Role: "owner", Status: "active"},
		device: &Device{ID: 13, Kind: "server"},
	}
	suspendedAdmin := caller{
		member: &Member{ID: 4, Handle: "susp", Role: "admin", Status: "suspended"},
		device: &Device{ID: 14, Kind: "personal"},
	}

	cases := []struct {
		name      string
		pol       routePolicy
		c         caller
		renewOnly bool
		wantOK    bool
	}{
		// Default zero-value policy: personal only, any role, blocked in renew_only.
		{"default personal member", routePolicy{}, memberPersonal, false, true},
		{"default server owner denied", routePolicy{}, ownerServer, false, false},
		{"default renew_only admin denied", routePolicy{}, adminPersonal, true, false},

		// Admin-only personal route.
		{"admin route owner allowed", routePolicy{Role: roleAdmin}, ownerPersonal, false, true},
		{"admin route admin allowed", routePolicy{Role: roleAdmin}, adminPersonal, false, true},
		{"admin route member denied", routePolicy{Role: roleAdmin}, memberPersonal, false, false},
		{"admin route server denied", routePolicy{Role: roleAdmin}, ownerServer, false, false},

		// Server-only ACME route.
		{"server-only server allowed", routePolicy{Device: deviceServerOnly}, ownerServer, false, true},
		{"server-only personal denied", routePolicy{Device: deviceServerOnly}, ownerPersonal, false, false},
		{"server-only renew_only denied", routePolicy{Device: deviceServerOnly}, ownerServer, true, false},

		// Renew-only billing/me route: active admin/owner on personal device only.
		{"renew_only allowed route owner personal", routePolicy{Device: deviceAny, AllowRenewOnly: true}, ownerPersonal, true, true},
		{"renew_only allowed route admin personal", routePolicy{Role: roleAdmin, AllowRenewOnly: true}, adminPersonal, true, true},
		{"renew_only allowed route member denied", routePolicy{Device: deviceAny, AllowRenewOnly: true}, memberPersonal, true, false},
		{"renew_only allowed route server denied", routePolicy{Device: deviceAny, AllowRenewOnly: true}, ownerServer, true, false},
		{"renew_only allowed route suspended admin denied", routePolicy{Role: roleAdmin, AllowRenewOnly: true}, suspendedAdmin, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := enforceRoutePolicy(tc.pol, tc.c, tc.renewOnly)
			if tc.wantOK && err != nil {
				t.Fatalf("enforceRoutePolicy = %v, want nil", err)
			}
			if !tc.wantOK {
				var p *Problem
				if !errors.As(err, &p) || p.Status != http.StatusForbidden {
					t.Fatalf("enforceRoutePolicy = %v, want 403 Problem", err)
				}
			}
		})
	}
}

func TestRecoverAndLogHandlesPanicsAnd5xx(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// 1. Panic returns clean JSON 500 with no-store and logs panic without leaking secret stack to body.
	panicHandler := recoverAndLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom secret-internal-detail")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/panic", nil)
	rec := httptest.NewRecorder()
	panicHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic status = %d, want 500", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("panic Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	if strings.Contains(rec.Body.String(), "secret-internal-detail") {
		t.Fatalf("panic response leaked panic value: %s", rec.Body.String())
	}
	if !strings.Contains(buf.String(), "http handler panic") {
		t.Fatalf("expected structured panic log, got %q", buf.String())
	}

	// 2. http.ErrAbortHandler is re-panicked per net/http contract.
	abortHandler := recoverAndLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	func() {
		defer func() {
			if rec := recover(); rec != http.ErrAbortHandler {
				t.Fatalf("expected ErrAbortHandler re-panic, got %v", rec)
			}
		}()
		abortHandler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/abort", nil))
	}()

	// 3. Nested recoverAndLog logs 5xx exactly once.
	buf.Reset()
	nested := recoverAndLog(logger, recoverAndLog(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "down"})
	})))
	rec = httptest.NewRecorder()
	nested.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/down", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nested status = %d, want 503", rec.Code)
	}
	if got := strings.Count(buf.String(), "http server error"); got != 1 {
		t.Fatalf("nested recoverAndLog logged %d times, want 1 (%q)", got, buf.String())
	}
}
