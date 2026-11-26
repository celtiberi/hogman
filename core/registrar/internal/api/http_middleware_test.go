package api

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hogman/registrar/internal/acme"
	"hogman/registrar/internal/registrar"
	"hogman/registrar/internal/store"
)

func TestEnforceRoutePolicyMatrix(t *testing.T) {
	ownerPersonal := caller{
		member: &store.Member{ID: 1, Handle: "owner", Role: "owner", Status: "active"},
		device: &store.Device{ID: 10, Kind: "personal"},
	}
	adminPersonal := caller{
		member: &store.Member{ID: 2, Handle: "admin", Role: "admin", Status: "active"},
		device: &store.Device{ID: 11, Kind: "personal"},
	}
	memberPersonal := caller{
		member: &store.Member{ID: 3, Handle: "bob", Role: "member", Status: "active"},
		device: &store.Device{ID: 12, Kind: "personal"},
	}
	ownerServer := caller{
		member: &store.Member{ID: 1, Handle: "owner", Role: "owner", Status: "active"},
		device: &store.Device{ID: 13, Kind: "server"},
	}
	suspendedAdmin := caller{
		member: &store.Member{ID: 4, Handle: "susp", Role: "admin", Status: "suspended"},
		device: &store.Device{ID: 14, Kind: "personal"},
	}

	cases := []struct {
		name      string
		pol       routePolicy
		c         caller
		renewOnly bool
		wantOK    bool
	}{
		{"default personal member", routePolicy{}, memberPersonal, false, true},
		{"default server owner denied", routePolicy{}, ownerServer, false, false},
		{"default renew_only admin denied", routePolicy{}, adminPersonal, true, false},

		{"admin route owner allowed", routePolicy{Role: roleAdmin}, ownerPersonal, false, true},
		{"admin route admin allowed", routePolicy{Role: roleAdmin}, adminPersonal, false, true},
		{"admin route member denied", routePolicy{Role: roleAdmin}, memberPersonal, false, false},
		{"admin route server denied", routePolicy{Role: roleAdmin}, ownerServer, false, false},

		{"server-only server allowed", routePolicy{Device: deviceServerOnly}, ownerServer, false, true},
		{"server-only personal denied", routePolicy{Device: deviceServerOnly}, ownerPersonal, false, false},
		{"server-only renew_only denied", routePolicy{Device: deviceServerOnly}, ownerServer, true, false},

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
				var ae *apiError
				if !errors.As(err, &ae) || ae.status != http.StatusForbidden {
					t.Fatalf("enforceRoutePolicy = %v, want 403 apiError", err)
				}
			}
		})
	}
}

func TestWriteErrorTranslation(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	cases := []struct {
		name           string
		err            error
		wantStatus     int
		wantBodySubstr string
		wantRetryAfter string
	}{
		{"invalid", &registrar.Error{Kind: registrar.KindInvalid, Msg: "bad handle"}, 400, "bad handle", ""},
		{"forbidden", &registrar.Error{Kind: registrar.KindForbidden, Msg: "admins only"}, 403, "admins only", ""},
		{"not found", &registrar.Error{Kind: registrar.KindNotFound, Msg: "no member"}, 404, "no member", ""},
		{"conflict", &registrar.Error{Kind: registrar.KindConflict, Msg: "handle taken"}, 409, "handle taken", ""},
		{"rate limited", &registrar.Error{Kind: registrar.KindRateLimited, Msg: "slow down", RetryAfter: 42}, 429, "slow down", "42"},
		{"unavailable", &registrar.Error{Kind: registrar.KindUnavailable, Msg: "not configured"}, 503, "not configured", ""},
		{"challenge error", &acme.ChallengeError{Status: 429, Msg: "acme throttle", RetryAfter: 17}, 429, "acme throttle", "17"},
		{"opaque internal", errors.New("sqlite secret table detail"), 500, "internal error", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeError(logger, rec, tc.err)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
			}
			if got := rec.Header().Get("Retry-After"); got != tc.wantRetryAfter {
				t.Fatalf("Retry-After = %q, want %q", got, tc.wantRetryAfter)
			}
			if !strings.Contains(rec.Body.String(), tc.wantBodySubstr) {
				t.Fatalf("body = %q, want substring %q", rec.Body.String(), tc.wantBodySubstr)
			}
			if tc.wantStatus == 500 && strings.Contains(rec.Body.String(), "sqlite secret") {
				t.Fatalf("internal error leaked raw message: %s", rec.Body.String())
			}
		})
	}
}

func TestRecoverAndLogHandlesPanicsAnd5xx(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

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
