package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hogman/join/internal/penapi"
	"hogman/join/internal/state"
)

func withFastSelfDeleteTimeouts(t *testing.T) {
	t.Helper()
	oldDel, oldConf, oldPoll := penapi.SelfDeleteTimeout, penapi.ConfirmDeleteTimeout, penapi.ConfirmPollInterval
	penapi.SelfDeleteTimeout = 150 * time.Millisecond
	penapi.ConfirmDeleteTimeout = 150 * time.Millisecond
	penapi.ConfirmPollInterval = 15 * time.Millisecond
	t.Cleanup(func() {
		penapi.SelfDeleteTimeout = oldDel
		penapi.ConfirmDeleteTimeout = oldConf
		penapi.ConfirmPollInterval = oldPoll
	})
}

func newMockHomeClient(srv *httptest.Server) *http.Client {
	srvURL, err := url.Parse(srv.URL)
	if err != nil {
		panic(err)
	}
	hc := srv.Client()
	hc.Timeout = 30 * time.Second
	baseRT := hc.Transport
	hc.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		r2 := req.Clone(req.Context())
		r2.URL.Scheme = srvURL.Scheme
		r2.URL.Host = srvURL.Host
		return baseRT.RoundTrip(r2)
	})
	return hc
}

func TestGiveBackDeviceImmediate202Accepted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/me":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"this_device":{"id":42}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/devices/42":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	start := time.Now()
	if err := giveBackDevice(context.Background(), newMockHomeClient(srv), &state.ShareConfig{Zone: "bobo.pens.example.test"}); err != nil {
		t.Fatalf("giveBackDevice on 202 = %v, want nil", err)
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("giveBackDevice on 202 took %v, expected immediate completion", elapsed)
	}
}

func TestGiveBackDeviceDroppedReplyConfirmedByMe403NotEnrolled(t *testing.T) {
	withFastSelfDeleteTimeouts(t)
	release := make(chan struct{})
	defer close(release)
	var deleted atomic.Bool

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/me":
			if deleted.Load() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"this device is not enrolled in the network"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"this_device":{"id":42}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/devices/42":
			deleted.Store(true)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		default:
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	if err := giveBackDevice(context.Background(), newMockHomeClient(srv), &state.ShareConfig{Zone: "bobo.pens.example.test"}); err != nil {
		t.Fatalf("giveBackDevice confirmed by 403 not-enrolled = %v, want nil", err)
	}
}

func TestGiveBackDeviceDroppedReplyRejectsSuspendedRenewOnlyAnd404(t *testing.T) {
	withFastSelfDeleteTimeouts(t)
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"suspended 403", http.StatusForbidden, `{"error":"membership suspended"}`},
		{"renew_only 403", http.StatusForbidden, `{"error":"this pen is woken for renewal only"}`},
		{"misrouted 404", http.StatusNotFound, `{"error":"not found"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			var deleteSeen atomic.Bool

			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/me":
					if deleteSeen.Load() {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(tc.status)
						_, _ = w.Write([]byte(tc.body))
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"this_device":{"id":42}}`))
				case r.Method == http.MethodDelete && r.URL.Path == "/api/devices/42":
					deleteSeen.Store(true)
					select {
					case <-release:
					case <-r.Context().Done():
					}
				}
			}))
			defer srv.Close()

			err := giveBackDevice(context.Background(), newMockHomeClient(srv), &state.ShareConfig{Zone: "bobo.pens.example.test"})
			if err == nil || !strings.Contains(err.Error(), "could not confirm removal") {
				t.Fatalf("case %s: err = %v, want unconfirmed error", tc.name, err)
			}
		})
	}
}

func TestGiveBackDeviceDroppedReplyConfirmedByNeedsLoginOverControlChannel(t *testing.T) {
	withFastSelfDeleteTimeouts(t)
	release := make(chan struct{})
	defer close(release)
	var deleteSeen atomic.Bool
	var polls atomic.Int32

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/me":
			if deleteSeen.Load() {
				// WireGuard link already torn down by an older synchronous registrar: /me times out too.
				select {
				case <-release:
				case <-r.Context().Done():
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"this_device":{"id":42}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/devices/42":
			deleteSeen.Store(true)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
	}))
	defer srv.Close()

	// Control plane transitions to NeedsLogin on the 2nd poll.
	checkNL := func(context.Context) bool {
		return polls.Add(1) >= 2
	}
	err := giveBackDeviceWith(context.Background(), newMockHomeClient(srv), &state.ShareConfig{Zone: "bobo.pens.example.test"}, 0, checkNL)
	if err != nil {
		t.Fatalf("giveBackDeviceWith confirmed by NeedsLogin = %v, want nil", err)
	}
}

func TestGiveBackDeviceDroppedReplyUnconfirmedWhenStillEnrolled(t *testing.T) {
	withFastSelfDeleteTimeouts(t)
	release := make(chan struct{})
	defer close(release)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/me":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"this_device":{"id":42}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/devices/42":
			select {
			case <-release:
			case <-r.Context().Done():
			}
		default:
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	err := giveBackDevice(context.Background(), newMockHomeClient(srv), &state.ShareConfig{Zone: "bobo.pens.example.test"})
	if err == nil || !strings.Contains(err.Error(), "could not confirm removal") {
		t.Fatalf("expected unconfirmed error when GET /api/me still returns 200, got: %v", err)
	}
}

func TestGiveBackDeviceDroppedReplyUnconfirmedWhenBothTimeOutAndNotNeedsLogin(t *testing.T) {
	withFastSelfDeleteTimeouts(t)
	release := make(chan struct{})
	defer close(release)
	var deleteSeen atomic.Bool

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/me":
			if deleteSeen.Load() {
				select {
				case <-release:
				case <-r.Context().Done():
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"this_device":{"id":42}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/devices/42":
			deleteSeen.Store(true)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
	}))
	defer srv.Close()

	err := giveBackDeviceWith(context.Background(), newMockHomeClient(srv), &state.ShareConfig{Zone: "bobo.pens.example.test"}, 0, func(context.Context) bool { return false })
	if err == nil || !strings.Contains(err.Error(), "could not confirm removal") {
		t.Fatalf("expected unconfirmed error, got: %v", err)
	}
}

func TestGiveBackDeviceGuardsZeroDeviceIDAndRespectsCtxCancel(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"this_device":{"id":0}}`))
	}))
	defer srv.Close()

	if err := giveBackDevice(context.Background(), newMockHomeClient(srv), &state.ShareConfig{Zone: "bobo.pens.example.test"}); err == nil || !strings.Contains(err.Error(), "device ID") {
		t.Fatalf("expected zero device ID error, got: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := giveBackDevice(ctx, newMockHomeClient(srv), &state.ShareConfig{Zone: "bobo.pens.example.test"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx err = %v, want context.Canceled", err)
	}
}

func TestGiveBackDeviceStillReportsRealHTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/me":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"this_device":{"id":7}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/devices/7":
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	}))
	defer srv.Close()

	if err := giveBackDevice(context.Background(), newMockHomeClient(srv), &state.ShareConfig{Zone: "bobo.pens.example.test"}); err == nil {
		t.Fatal("expected giveBackDevice to report HTTP 403 error")
	}
}

func TestRemoveOwnDeviceWithStates(t *testing.T) {
	withFastSelfDeleteTimeouts(t)
	const zone = "bobo.pens.example.test"

	t.Run("202 Accepted returns true immediately", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/me" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"this_device":{"id":9}}`))
				return
			}
			w.WriteHeader(http.StatusAccepted)
		}))
		defer srv.Close()
		if !removeOwnDeviceWith(context.Background(), newMockHomeClient(srv), zone, nil) {
			t.Fatal("expected true on 202")
		}
	})

	t.Run("code 0 confirmed by NeedsLogin returns true", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		var delSeen atomic.Bool
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/me" && !delSeen.Load() {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"this_device":{"id":9}}`))
				return
			}
			delSeen.Store(true)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		defer srv.Close()
		if !removeOwnDeviceWith(context.Background(), newMockHomeClient(srv), zone, func(context.Context) bool { return true }) {
			t.Fatal("expected true when control plane confirms NeedsLogin")
		}
	})

	t.Run("code 0 with active /me 200 returns false", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/me" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"this_device":{"id":9}}`))
				return
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		defer srv.Close()
		if removeOwnDeviceWith(context.Background(), newMockHomeClient(srv), zone, func(context.Context) bool { return true }) {
			t.Fatal("expected false when /api/me still returns 200")
		}
	})
}
