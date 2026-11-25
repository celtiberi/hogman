package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestGiveBackDeviceBoundedTimeoutOnDroppedReply(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/me":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"this_device":{"id":42}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/devices/42":
			// Simulate Headscale dropping the peer's WireGuard link before the
			// HTTP response arrives: stall well past selfDeleteTimeout.
			select {
			case <-release:
			case <-r.Context().Done():
			}
		default:
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	srvURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
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

	start := time.Now()
	err = giveBackDevice(context.Background(), hc, &shareConfig{Zone: "bobo.pens.example.test"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("giveBackDevice on dropped reply = %v, want nil", err)
	}
	if elapsed >= 8*time.Second {
		t.Fatalf("giveBackDevice took %v, expected <= ~%v (not 30s client timeout)", elapsed, selfDeleteTimeout)
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

	srvURL, _ := url.Parse(srv.URL)
	hc := srv.Client()
	hc.Timeout = 30 * time.Second
	baseRT := hc.Transport
	hc.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		r2 := req.Clone(req.Context())
		r2.URL.Scheme = srvURL.Scheme
		r2.URL.Host = srvURL.Host
		return baseRT.RoundTrip(r2)
	})

	if err := giveBackDevice(context.Background(), hc, &shareConfig{Zone: "bobo.pens.example.test"}); err == nil {
		t.Fatal("expected giveBackDevice to report HTTP 403 error")
	}
}
