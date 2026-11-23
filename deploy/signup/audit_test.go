package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditBrokerRequiresBearerPrefix(t *testing.T) {
	b, _ := newTestBroker(t, "")
	h := b.handler()

	// Raw token without "Bearer " prefix must be rejected.
	if code, _ := call(h, "GET", "/capacity", "", map[string]string{"Authorization": testToken}); code != 401 {
		t.Fatalf("raw token without Bearer prefix = %d, want 401", code)
	}
	if code, _ := call(h, "GET", "/capacity", "", auth); code != 200 {
		t.Fatalf("Bearer token = %d, want 200", code)
	}
}

func TestAuditBrokerReadCapacityLocalNoFork(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "host.env"), []byte("MAX_PENS='4'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "pens", "alpha"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "pens", "beta"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "pens", "beta", ".removed"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	b := &broker{
		tool:  "/nonexistent/should-not-fork",
		home:  home,
		token: testToken,
	}
	h := b.handler()
	code, out := call(h, "GET", "/capacity", "", auth)
	if code != 200 || out["pens"] != float64(1) || out["max"] != float64(4) || out["open"] != true {
		t.Fatalf("local capacity = %d %v, want 200 {pens:1 max:4 open:true}", code, out)
	}
}

func TestAuditWebStatusRateLimitAndSameOriginJSON(t *testing.T) {
	b, _ := newTestBroker(t, "")
	bsrv := httptest.NewServer(b.handler())
	defer bsrv.Close()

	wb := newWeb(bsrv.URL, testToken, "pens.test")
	wb.statuses = newLimiter(2, time.Minute)
	wb.stripe = &stripeCheckout{price: "price_test", publicURL: "https://get.example.com"}
	h := wb.handler()

	for i := 0; i < 2; i++ {
		if code, _ := call(h, "GET", "/api/status", "", map[string]string{"X-Forwarded-For": "203.0.113.10"}); code != 200 {
			t.Fatalf("status %d = %d, want 200", i, code)
		}
	}
	if code, _ := call(h, "GET", "/api/status", "", map[string]string{"X-Forwarded-For": "203.0.113.10"}); code != 429 {
		t.Fatalf("status over limit = %d, want 429", code)
	}

	// Cross-origin POST to /api/checkout and /api/waitlist/leave must be rejected.
	for _, path := range []string{"/api/checkout", "/api/waitlist/leave"} {
		req := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		req.Host = "get.example.com"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://evil.example")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("cross-origin %s = %d, want 403", path, rec.Code)
		}

		req2 := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		req2.Host = "get.example.com"
		req2.Header.Set("Content-Type", "text/plain")
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, req2)
		if rec2.Code != 415 {
			t.Fatalf("non-JSON %s = %d, want 415", path, rec2.Code)
		}
	}
}

func TestAuditWaitlistEmailAndCleanField(t *testing.T) {
	for _, bad := range []string{
		"alice\x00@example.com",
		"alice\r\n@example.com",
		"alice\x1b[31m@example.com",
		"alice bob@example.com",
		"alíce@example.com",
	} {
		if validEmail(bad) {
			t.Errorf("validEmail(%q) = true, want false", bad)
		}
	}
	if !validEmail("alice+hogman_1.2@example.com") {
		t.Error("validEmail rejected valid ASCII address")
	}
	got := cleanField("hi\u202E\x1b[31mthere\x00\nworld", 100)
	if strings.ContainsAny(got, "\x00\x1b\n\u202E") {
		t.Fatalf("cleanField left control/bidi chars: %q", got)
	}
}

func TestAuditStripeWebhookLivemodeCurrencyAndMinAmount(t *testing.T) {
	b, _ := newTestBroker(t, "")
	b.webhookSecret = testWebhookSecret
	live := true
	b.expectLivemode = &live
	b.minPersonalCents = 500
	b.minWorkCents = 2500
	h := b.handler()

	makeEv := func(id string, livemode bool, currency string, subtotal, total int64, plan string) []byte {
		meta := map[string]string{penMetaKey: penMetaValue}
		if plan != "" {
			meta["plan"] = plan
		}
		obj := map[string]any{
			"id":              id,
			"object":          "checkout.session",
			"mode":            "subscription",
			"payment_status":  "paid",
			"customer":        "cus_audit",
			"subscription":    "sub_audit",
			"currency":        currency,
			"amount_subtotal": subtotal,
			"amount_total":    total,
			"metadata":        meta,
		}
		ev := map[string]any{
			"id":          "evt_" + id,
			"object":      "event",
			"type":        "checkout.session.completed",
			"api_version": "2099-01-01",
			"livemode":    livemode,
			"data":        map[string]any{"object": obj},
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	// Test-mode event rejected when expectLivemode=true.
	ev := makeEv("cs_test_wrongmode123456", false, "usd", 1000, 1000, "personal")
	if code, _ := sendEvent(t, h, ev, signed(ev, testWebhookSecret, time.Now())); code != 400 {
		t.Fatalf("test-mode event with expectLivemode = %d, want 400", code)
	}
	// Non-USD currency is refused without minting a code (200 so Stripe stops retrying).
	ev = makeEv("cs_live_wrongcurr123456", true, "eur", 1000, 1000, "personal")
	if code, _ := sendEvent(t, h, ev, signed(ev, testWebhookSecret, time.Now())); code != 200 {
		t.Fatalf("non-USD event = %d, want 200", code)
	}
	if code, out := call(h, "GET", "/paid-code?session=cs_live_wrongcurr123456", "", auth); code != 200 || out["state"] != "pending" {
		t.Fatalf("non-USD event minted code: %d %v", code, out)
	}
	// Underpaid work plan is refused without minting a code.
	ev = makeEv("cs_live_underpaid123456", true, "usd", 500, 500, "work")
	if code, _ := sendEvent(t, h, ev, signed(ev, testWebhookSecret, time.Now())); code != 200 {
		t.Fatalf("underpaid work event = %d, want 200", code)
	}
	if code, out := call(h, "GET", "/paid-code?session=cs_live_underpaid123456", "", auth); code != 200 || out["state"] != "pending" {
		t.Fatalf("underpaid work event minted code: %d %v", code, out)
	}
	// Valid live work plan accepted and issues a code.
	ev = makeEv("cs_live_validwork123456", true, "usd", 2500, 2500, "work")
	if code, _ := sendEvent(t, h, ev, signed(ev, testWebhookSecret, time.Now())); code != 200 {
		t.Fatalf("valid live work event = %d, want 200", code)
	}
	if code, out := call(h, "GET", "/paid-code?session=cs_live_validwork123456", "", auth); code != 200 || out["state"] != "ready" {
		t.Fatalf("paid-code after valid live work event = %d %v", code, out)
	}
}
