package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHomeAPICtxErrorParsingAndRetryAfter(t *testing.T) {
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/api/rate":
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": []string{"120"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":"too many requests"}`)),
			}, nil
		case "/api/plain":
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("not enrolled")),
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
		default:
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		}
	})}

	code, err := homeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodPost, "/rate", nil, nil)
	var he *homeAPIError
	if code != http.StatusTooManyRequests || !errors.As(err, &he) || he.RetryAfter != 2*time.Minute || he.Msg != "too many requests" {
		t.Fatalf("/rate = (%d, %v), want 429 RetryAfter=2m", code, err)
	}

	code, err = homeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodGet, "/plain", nil, nil)
	if code != http.StatusForbidden || !isNotEnrolledError(err) {
		t.Fatalf("/plain = (%d, %v), want 403 not enrolled", code, err)
	}

	code, err = homeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodGet, "/empty-err", nil, nil)
	if code != http.StatusInternalServerError || err == nil || err.Error() != "HTTP 500" {
		t.Fatalf("/empty-err = (%d, %v), want HTTP 500", code, err)
	}

	var out struct{ OK bool }
	code, err = homeAPICtx(context.Background(), hc, "bobo.pens.example.com", http.MethodDelete, "/empty-ok", nil, &out)
	if code != http.StatusNoContent || err != nil {
		t.Fatalf("/empty-ok = (%d, %v), want 204 nil", code, err)
	}
}

func TestDeleteSelfDeviceOutcomes(t *testing.T) {
	origDel, origConf, origPoll := selfDeleteTimeout, confirmDeleteTimeout, confirmPollInterval
	selfDeleteTimeout = 50 * time.Millisecond
	confirmDeleteTimeout = 80 * time.Millisecond
	confirmPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		selfDeleteTimeout = origDel
		confirmDeleteTimeout = origConf
		confirmPollInterval = origPoll
	})

	t.Run("202 accepted removes cleanly", func(t *testing.T) {
		hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodGet && r.URL.Path == "/api/me" {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"this_device":{"id":7}}`))}, nil
			}
			if r.Method == http.MethodDelete && r.URL.Path == "/api/devices/7" {
				return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			return nil, nil
		})}
		res := deleteSelfDevice(context.Background(), hc, "bobo.pens.example.com", 0, nil)
		if res.outcome != selfDeleteRemoved {
			t.Fatalf("got %+v, want selfDeleteRemoved", res)
		}
	})

	t.Run("code 0 confirmed via 403 not enrolled", func(t *testing.T) {
		hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodDelete {
				return nil, errors.New("connection reset by peer")
			}
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       io.NopCloser(strings.NewReader(`{"error":"device not enrolled"}`)),
			}, nil
		})}
		res := deleteSelfDevice(context.Background(), hc, "bobo.pens.example.com", 7, nil)
		if res.outcome != selfDeleteRemoved {
			t.Fatalf("got %+v, want selfDeleteRemoved", res)
		}
	})

	t.Run("code 0 confirmed via NeedsLogin fallback", func(t *testing.T) {
		hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("mesh dropped")
		})}
		res := deleteSelfDevice(context.Background(), hc, "bobo.pens.example.com", 7, func(context.Context) bool { return true })
		if res.outcome != selfDeleteRemoved {
			t.Fatalf("got %+v, want selfDeleteRemoved", res)
		}
	})

	t.Run("code 0 unconfirmed when neither probe confirms", func(t *testing.T) {
		hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("timeout")
		})}
		res := deleteSelfDevice(context.Background(), hc, "bobo.pens.example.com", 7, func(context.Context) bool { return false })
		if res.outcome != selfDeleteUnconfirmed {
			t.Fatalf("got %+v, want selfDeleteUnconfirmed", res)
		}
	})

	t.Run("HTTP 500 rejected without confirmation", func(t *testing.T) {
		hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader(`{"error":"boom"}`)),
			}, nil
		})}
		res := deleteSelfDevice(context.Background(), hc, "bobo.pens.example.com", 7, nil)
		if res.outcome != selfDeleteRejected || res.err == nil {
			t.Fatalf("got %+v, want selfDeleteRejected", res)
		}
	})
}
