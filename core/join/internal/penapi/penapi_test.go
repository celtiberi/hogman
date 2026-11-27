package penapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHomeAPICtxErrorParsingSanitizationAndRetryAfter(t *testing.T) {
	t.Parallel()
	longTail := strings.Repeat("a", 300) + "-END"
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/rate":
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": []string{"120"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":"too many requests"}`)),
			}, nil
		case "/api/not-enrolled":
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":"this device is not enrolled in the network"}`)),
			}, nil
		case "/api/empty-err":
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		case "/api/empty-ok":
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		case "/api/captive":
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
				Body:       io.NopCloser(strings.NewReader("<html><body>SECRET_PORTAL_BODY " + strings.Repeat("X", 500) + "</body></html>")),
			}, nil
		case "/api/captive-ctrl-ct":
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Header:     http.Header{"Content-Type": []string{"text/plain\x1b[31m\u009b31m"}},
				Body:       io.NopCloser(strings.NewReader("MIDDLEBOX_SECRET_BODY")),
			}, nil
		case "/api/json-ctrl":
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":"bad \u001b[2J\u009b2J\u202einput\u007f ` + longTail + `"}`)),
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}
	})}

	code, err := HomeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodPost, "/rate", nil, nil)
	var he *HomeAPIError
	if code != http.StatusTooManyRequests || !errors.As(err, &he) || he.RetryAfter != 2*time.Minute || he.Msg != "too many requests" {
		t.Fatalf("/rate = (%d, %v), want 429 RetryAfter=2m", code, err)
	}

	code, err = HomeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodGet, "/not-enrolled", nil, nil)
	if code != http.StatusForbidden || !IsNotEnrolledError(err) {
		t.Fatalf("/not-enrolled = (%d, %v), want 403 not enrolled", code, err)
	}

	code, err = HomeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodGet, "/empty-err", nil, nil)
	if code != http.StatusInternalServerError || err == nil || err.Error() != "HTTP 500" {
		t.Fatalf("/empty-err = (%d, %v), want HTTP 500", code, err)
	}

	var out struct{ OK bool }
	code, err = HomeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodDelete, "/empty-ok", nil, &out)
	if code != http.StatusNoContent || err != nil {
		t.Fatalf("/empty-ok = (%d, %v), want 204 nil", code, err)
	}

	code, err = HomeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodGet, "/json-ctrl", nil, nil)
	if code != http.StatusBadRequest || err == nil {
		t.Fatalf("/json-ctrl = (%d, %v), want 400 error", code, err)
	}
	wantJSON := "bad ?[2J?2J?input? " + longTail
	if err.Error() != wantJSON {
		t.Fatalf("/json-ctrl = %q, want %q", err.Error(), wantJSON)
	}
	for _, r := range err.Error() {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("/json-ctrl: unsanitized control/format char %U in %q", r, err.Error())
		}
	}

	code, err = HomeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodGet, "/captive", nil, nil)
	if code != http.StatusFound || err == nil {
		t.Fatalf("/captive = (%d, %v), want 302 error", code, err)
	}
	if strings.Contains(err.Error(), "SECRET_PORTAL_BODY") || strings.Contains(err.Error(), "<html>") {
		t.Fatalf("/captive echoed HTML body: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "HTTP 302 (text/html)") {
		t.Fatalf("/captive = %q, want HTTP 302 (text/html) hint", err.Error())
	}

	code, err = HomeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodGet, "/captive-ctrl-ct", nil, nil)
	if code != http.StatusBadGateway || err == nil {
		t.Fatalf("/captive-ctrl-ct = (%d, %v), want 502 error", code, err)
	}
	if strings.Contains(err.Error(), "MIDDLEBOX_SECRET_BODY") {
		t.Fatalf("/captive-ctrl-ct echoed raw body: %q", err.Error())
	}
	for _, r := range err.Error() {
		if unicode.IsControl(r) {
			t.Fatalf("/captive-ctrl-ct: unsanitized control char %U in %q", r, err.Error())
		}
	}
}

func TestValidateNetworkInfoAndDeleteSelfDevice(t *testing.T) {
	if err := ValidateNetworkInfo("bobo.gate.example.com", &NetworkInfo{
		Zone:        "bobo.pens.example.com",
		LoginServer: "https://bobo.gate.example.com",
		Portal:      "https://home.bobo.pens.example.com",
		DNSServer:   "100.64.0.1",
		CertMode:    "public",
	}); err != nil {
		t.Fatalf("valid NetworkInfo rejected: %v", err)
	}
	if err := ValidateNetworkInfo("bobo.gate.example.com", &NetworkInfo{
		Zone:        "bobo.pens.example.com",
		LoginServer: "https://evil.example.com",
		Portal:      "https://home.bobo.pens.example.com",
	}); err == nil {
		t.Fatal("mismatched LoginServer accepted")
	}
	if err := ValidateNetworkInfo("bobo.gate.example.com", &NetworkInfo{
		Zone:        "bobo.pens.example.com",
		LoginServer: "https://bobo.gate.example.com",
		Portal:      "https://home.bobo.pens.example.com",
		DNSServer:   "192.168.1.1",
	}); err == nil {
		t.Fatal("non-mesh DNSServer accepted")
	}

	origDel, origConf, origPoll := SelfDeleteTimeout, ConfirmDeleteTimeout, ConfirmPollInterval
	SelfDeleteTimeout = 50 * time.Millisecond
	ConfirmDeleteTimeout = 80 * time.Millisecond
	ConfirmPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		SelfDeleteTimeout = origDel
		ConfirmDeleteTimeout = origConf
		ConfirmPollInterval = origPoll
	})

	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodDelete {
			return nil, errors.New("connection reset by peer")
		}
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(strings.NewReader(`{"error":"device not enrolled"}`)),
		}, nil
	})}
	if res := DeleteSelfDevice(context.Background(), hc, "bobo.pens.example.com", 7, nil); res.Outcome != SelfDeleteRemoved {
		t.Fatalf("code 0 confirmed via 403 = %+v, want SelfDeleteRemoved", res)
	}
}
