package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

const testWebhookSecret = "whsec_test_0123456789abcdef"

const testSession = "cs_test_a1B2c3D4e5F6g7H8i9J0"

func checkoutEvent(t *testing.T, typ, session, paymentStatus string, ours bool) []byte {
	t.Helper()
	meta := map[string]string{}
	if ours {
		meta[penMetaKey] = penMetaValue
	}
	obj := map[string]any{
		"id": session, "object": "checkout.session", "mode": "subscription",
		"payment_status": paymentStatus, "customer": "cus_test123", "subscription": "sub_test123", "metadata": meta,
	}
	ev := map[string]any{"id": "evt_test_1", "object": "event", "type": typ, "api_version": "2099-01-01", "data": map[string]any{"object": obj}}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signed(payload []byte, secret string, at time.Time) string {
	return webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: secret, Timestamp: at}).Header
}

func sendEvent(t *testing.T, h http.Handler, payload []byte, sig string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(stripeEventIn{Payload: string(payload), Signature: sig})
	return call(h, "POST", "/stripe/event", string(body), auth)
}

func TestNewSignupCodeShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := newSignupCode()
		if err != nil || !codeRE.MatchString(c) {
			t.Fatalf("code %q (%v) doesn't match %s", c, err, codeRE)
		}
		seen[c] = true
	}
	if len(seen) < 199 {
		t.Fatalf("codes repeat: %d distinct of 200", len(seen))
	}
}

func TestPaidCheckoutBuysOneCode(t *testing.T) {
	b, home := newTestBroker(t, "")
	b.webhookSecret = testWebhookSecret
	h := b.handler()

	// Before Stripe's event arrives, the page sees "pending".
	if code, out := call(h, "GET", "/paid-code?session="+testSession, "", auth); code != 200 || out["state"] != "pending" {
		t.Fatalf("before the event: %d %v", code, out)
	}

	ev := checkoutEvent(t, "checkout.session.completed", testSession, "paid", true)
	if code, out := sendEvent(t, h, ev, signed(ev, testWebhookSecret, time.Now())); code != 200 {
		t.Fatalf("paid event: %d %v", code, out)
	}
	code, out := call(h, "GET", "/paid-code?session="+testSession, "", auth)
	got, _ := out["code"].(string)
	if code != 200 || out["state"] != "ready" || !codeRE.MatchString(got) {
		t.Fatalf("after the event: %d %v", code, out)
	}

	// Stripe retries; the same session never gets a second code.
	if code, _ := sendEvent(t, h, ev, signed(ev, testWebhookSecret, time.Now())); code != 200 {
		t.Fatalf("retry: %d", code)
	}
	codes, _ := os.ReadFile(filepath.Join(home, "signup", "codes"))
	if n := strings.Count(string(codes), "\n"); n != 1 || !strings.Contains(string(codes), got+" vanity paid "+testSession) {
		t.Fatalf("codes after a retry:\n%s", codes)
	}
	pays, _ := os.ReadFile(filepath.Join(home, "signup", "payments"))
	if n := strings.Count(string(pays), "\n"); n != 1 || !strings.HasPrefix(string(pays), testSession+" "+got+" cus_test123 sub_test123 ") {
		t.Fatalf("payments:\n%s", pays)
	}
	ledger, _ := os.ReadFile(filepath.Join(home, "signup", "raised.log"))
	if strings.Count(string(ledger), "bought code") != 1 {
		t.Fatalf("ledger:\n%s", ledger)
	}

	// The bought code raises a pen like any other; then the page says "used".
	pc, po := call(h, "POST", "/provision", fmt.Sprintf(`{"code":%q,"pen":"bought","owner":"alice"}`, got), auth)
	if pc != 201 || po["pen"] != "bought" { // a paid pen keeps its bare name
		t.Fatalf("provision with a bought code: %d %v", pc, po)
	}
	if code, out := call(h, "GET", "/paid-code?session="+testSession, "", auth); code != 200 || out["state"] != "used" || out["code"] != nil {
		t.Fatalf("after use: %d %v", code, out)
	}
}

func TestStripeEventsRefused(t *testing.T) {
	b, home := newTestBroker(t, "")
	b.webhookSecret = testWebhookSecret
	h := b.handler()
	ev := checkoutEvent(t, "checkout.session.completed", testSession, "paid", true)

	for name, sig := range map[string]string{
		"wrong secret": signed(ev, "whsec_someone_else_000", time.Now()),
		"too old":      signed(ev, testWebhookSecret, time.Now().Add(-10*time.Minute)),
		"no signature": "",
	} {
		if code, _ := sendEvent(t, h, ev, sig); code != 400 {
			t.Fatalf("%s: %d, want 400", name, code)
		}
	}
	// Tampering with a signed body breaks the signature.
	sig := signed(ev, testWebhookSecret, time.Now())
	tampered := []byte(strings.Replace(string(ev), "cus_test123", "cus_evil", 1))
	if code, _ := sendEvent(t, h, tampered, sig); code != 400 {
		t.Fatalf("tampered: %d", code)
	}
	// Genuine but not ours, or not paid yet: no code.
	for _, e := range [][]byte{
		checkoutEvent(t, "checkout.session.completed", testSession, "paid", false),
		checkoutEvent(t, "checkout.session.completed", testSession, "unpaid", true),
		checkoutEvent(t, "invoice.paid", testSession, "paid", true),
		[]byte(strings.Replace(string(checkoutEvent(t, "checkout.session.completed", testSession, "paid", true)), `"mode":"subscription"`, `"mode":"payment"`, 1)),
	} {
		if code, _ := sendEvent(t, h, e, signed(e, testWebhookSecret, time.Now())); code != 200 {
			t.Fatalf("ignorable event: %d", code)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "signup", "payments")); !os.IsNotExist(err) {
		t.Fatalf("a refused or ignored event made a payment record (%v)", err)
	}
	if codes, _ := os.ReadFile(filepath.Join(home, "signup", "codes")); len(codes) != 0 {
		t.Fatalf("codes: %q", codes)
	}
	// An async payment that succeeds later does buy the code.
	e := checkoutEvent(t, "checkout.session.async_payment_succeeded", testSession, "paid", true)
	if code, _ := sendEvent(t, h, e, signed(e, testWebhookSecret, time.Now())); code != 200 {
		t.Fatalf("async success: %d", code)
	}
	if _, out := call(h, "GET", "/paid-code?session="+testSession, "", auth); out["state"] != "ready" {
		t.Fatalf("after async success: %v", out)
	}
	// Payments off: the broker refuses events altogether.
	b.webhookSecret = ""
	if code, _ := sendEvent(t, h, e, signed(e, testWebhookSecret, time.Now())); code != 404 {
		t.Fatalf("payments off: %d", code)
	}
	if code, _ := call(h, "GET", "/paid-code?session=../../etc", "", auth); code != 400 {
		t.Fatalf("bad session id: %d", code)
	}
}

func TestSubscriptionEndedIsLogged(t *testing.T) {
	b, home := newTestBroker(t, "")
	b.webhookSecret = testWebhookSecret
	ev, _ := json.Marshal(map[string]any{"id": "evt_2", "object": "event", "type": "customer.subscription.deleted",
		"data": map[string]any{"object": map[string]any{"id": "sub_test123", "customer": "cus_test123", "metadata": map[string]string{penMetaKey: penMetaValue}}}})
	if code, _ := sendEvent(t, b.handler(), ev, signed(ev, testWebhookSecret, time.Now())); code != 200 {
		t.Fatalf("subscription deleted: %d", code)
	}
	ledger, _ := os.ReadFile(filepath.Join(home, "signup", "raised.log"))
	if !strings.Contains(string(ledger), "subscription sub_test123 ended") {
		t.Fatalf("ledger:\n%s", ledger)
	}
}

// fakeStripe answers POST /v1/checkout/sessions like Stripe and remembers the form.
func fakeStripe(t *testing.T) (*httptest.Server, *url.Values) {
	t.Helper()
	got := &url.Values{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/checkout/sessions" || r.Header.Get("Authorization") != "Bearer sk_test_fakefakefake123" {
			http.Error(w, `{"error":{"message":"unexpected"}}`, 400)
			return
		}
		body, _ := io.ReadAll(r.Body)
		*got, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"object":"checkout.session","url":"https://checkout.stripe.com/c/pay/%s"}`, testSession, testSession)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestWebSellsPens(t *testing.T) {
	b, _ := newTestBroker(t, "")
	b.webhookSecret = testWebhookSecret
	bsrv := httptest.NewServer(b.handler())
	defer bsrv.Close()
	wb := newWeb(bsrv.URL, testToken, "pens.test")
	h := wb.handler()

	// Selling is off unless configured.
	if _, out := call(h, "GET", "/api/status", "", nil); out["for_sale"] != false {
		t.Fatalf("status without Stripe: %v", out)
	}
	if code, _ := call(h, "POST", "/api/checkout", "", nil); code != 404 {
		t.Fatalf("checkout without Stripe: %d", code)
	}

	fake, form := fakeStripe(t)
	wb.stripe = &stripeCheckout{
		client: stripe.NewClient("sk_test_fakefakefake123", stripe.WithBackends(stripe.NewBackendsWithConfig(&stripe.BackendConfig{
			URL: stripe.String(fake.URL), HTTPClient: fake.Client(), MaxNetworkRetries: stripe.Int64(0)}))),
		price: "price_test_pen", publicURL: "https://get.example.com",
	}
	if _, out := call(h, "GET", "/api/status", "", nil); out["for_sale"] != true {
		t.Fatalf("status with Stripe: %v", out)
	}
	code, out := call(h, "POST", "/api/checkout", "", nil)
	if code != 200 || out["url"] != "https://checkout.stripe.com/c/pay/"+testSession {
		t.Fatalf("checkout: %d %v", code, out)
	}
	for k, want := range map[string]string{
		"mode":                                "subscription",
		"line_items[0][price]":                "price_test_pen",
		"line_items[0][quantity]":             "1",
		"metadata[hogman]":                    "pen",
		"subscription_data[metadata][hogman]": "pen",
		"success_url":                         "https://get.example.com/paid.html?session_id={CHECKOUT_SESSION_ID}",
		"cancel_url":                          "https://get.example.com/",
		"tax_id_collection[enabled]":          "true",
	} {
		if got := form.Get(k); got != want {
			t.Fatalf("checkout sent %s=%q, want %q (all: %v)", k, got, want, *form)
		}
	}
	if form.Get("automatic_tax[enabled]") != "" {
		t.Fatalf("automatic tax sent while off: %v", *form)
	}

	// Stripe's webhook goes through the page to the broker, which checks it.
	ev := checkoutEvent(t, "checkout.session.completed", testSession, "paid", true)
	req := httptest.NewRequest("POST", "/api/stripe/webhook", strings.NewReader(string(ev)))
	req.Header.Set("Stripe-Signature", signed(ev, testWebhookSecret, time.Now()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("webhook through the page: %d %s", rec.Code, rec.Body)
	}
	req = httptest.NewRequest("POST", "/api/stripe/webhook", strings.NewReader(string(ev)))
	req.Header.Set("Stripe-Signature", signed(ev, "whsec_forged_by_the_page", time.Now()))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("forged webhook through the page: %d", rec.Code)
	}
	if code, out := call(h, "GET", "/api/paid?session_id="+testSession, "", nil); code != 200 || out["state"] != "ready" || !codeRE.MatchString(fmt.Sprint(out["code"])) {
		t.Fatalf("paid: %d %v", code, out)
	}
	if code, _ := call(h, "GET", "/api/paid?session_id=nope", "", nil); code != 400 {
		t.Fatalf("paid with a bad id: %d", code)
	}

	// A full server doesn't sell.
	t.Setenv("FAKE_MAX", "0")
	if code, _ := call(h, "POST", "/api/checkout", "", nil); code != 409 {
		t.Fatalf("checkout while full: %d", code)
	}
}

func TestAutomaticTaxParams(t *testing.T) {
	sc := &stripeCheckout{price: "price_x", publicURL: "https://get.example.com", automatTax: true}
	p := sc.params()
	if p.AutomaticTax == nil || !*p.AutomaticTax.Enabled || p.BillingAddressCollection == nil || *p.BillingAddressCollection != "required" {
		t.Fatalf("automatic tax params: %+v", p)
	}
	for _, k := range []string{"sk_test_abcdefghijk", "rk_live_abcdefghijk"} {
		if !validStripeKey(k) {
			t.Fatalf("%s refused", k)
		}
	}
	for _, k := range []string{"pk_test_abcdefghijk", "sk_test_short", "whsec_abcdefghijkl", "sk_test_abc def ghijkl"} {
		if validStripeKey(k) {
			t.Fatalf("%s accepted", k)
		}
	}
}

func TestStripeCheckoutDualHostOriginAllowlist(t *testing.T) {
	b, _ := newTestBroker(t, "")
	b.webhookSecret = testWebhookSecret
	bsrv := httptest.NewServer(b.handler())
	defer bsrv.Close()

	wb := newWeb(bsrv.URL, testToken, "pens.test")
	wb.workHost = "get.work.example.com"
	fake, form := fakeStripe(t)
	sc := &stripeCheckout{
		client: stripe.NewClient("sk_test_fakefakefake123", stripe.WithBackends(stripe.NewBackendsWithConfig(&stripe.BackendConfig{
			URL: stripe.String(fake.URL), HTTPClient: fake.Client(), MaxNetworkRetries: stripe.Int64(0)}))),
		price:     "price_test_pen",
		publicURL: "https://get.example.com",
	}
	sc.allowOrigin("https://get.example.com")
	sc.allowOrigin("https://get.work.example.com")
	wb.stripe = sc
	h := wb.handler()

	postCheckout := func(host string) {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/checkout", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("checkout host=%s: %d %s", host, rec.Code, rec.Body.String())
		}
	}

	statusFor := func(host string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	// Without workPrice configured, the Work host MUST refuse checkout (404) and
	// report for_sale=false so it never sells a Work plan at the Personal price,
	// while the primary host remains for sale.
	if code, out := statusFor("get.work.example.com"); code != 200 || out["for_sale"] != false {
		t.Fatalf("work status without workPrice: %d %v, want for_sale=false", code, out)
	}
	req := httptest.NewRequest("POST", "/api/checkout", nil)
	req.Host = "get.work.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("work checkout without workPrice: %d %s, want 404", rec.Code, rec.Body.String())
	}
	if code, out := statusFor("get.example.com"); code != 200 || out["for_sale"] != true {
		t.Fatalf("primary status without workPrice: %d %v, want for_sale=true", code, out)
	}

	// With workPrice configured, get.work reports for_sale=true and uses workPrice + Work origin + plan=work.
	sc.workPrice = "price_test_work"
	if code, out := statusFor("get.work.example.com"); code != 200 || out["for_sale"] != true {
		t.Fatalf("work status with workPrice: %d %v, want for_sale=true", code, out)
	}
	postCheckout("get.work.example.com")
	if got := form.Get("success_url"); got != "https://get.work.example.com/paid.html?session_id={CHECKOUT_SESSION_ID}" {
		t.Fatalf("work success_url = %q", got)
	}
	if got := form.Get("cancel_url"); got != "https://get.work.example.com/" {
		t.Fatalf("work cancel_url = %q", got)
	}
	if got := form.Get("line_items[0][price]"); got != "price_test_work" {
		t.Fatalf("work price = %q, want price_test_work", got)
	}
	if got := form.Get("metadata[plan]"); got != "work" {
		t.Fatalf("work metadata[plan] = %q, want work", got)
	}
	if got := form.Get("subscription_data[metadata][plan]"); got != "work" {
		t.Fatalf("work subscription metadata[plan] = %q, want work", got)
	}

	postCheckout("get.example.com")
	if got := form.Get("line_items[0][price]"); got != "price_test_pen" {
		t.Fatalf("personal price = %q, want price_test_pen", got)
	}
	if got := form.Get("metadata[plan]"); got != "personal" {
		t.Fatalf("personal metadata[plan] = %q, want personal", got)
	}

	// Forged Host header MUST NOT be reflected into Stripe redirect URLs or Work plan.
	postCheckout("evil.attacker.example")
	if got := form.Get("success_url"); got != "https://get.example.com/paid.html?session_id={CHECKOUT_SESSION_ID}" {
		t.Fatalf("forged host reflected into success_url: %q", got)
	}
	if got := form.Get("cancel_url"); got != "https://get.example.com/" {
		t.Fatalf("forged host reflected into cancel_url: %q", got)
	}
	if got := form.Get("line_items[0][price]"); got != "price_test_pen" || form.Get("metadata[plan]") != "personal" {
		t.Fatalf("forged host got price=%q plan=%q", form.Get("line_items[0][price]"), form.Get("metadata[plan]"))
	}
}

func TestStripeWorkPlanRecordedInLedgerAndPayments(t *testing.T) {
	b, home := newTestBroker(t, "")
	b.webhookSecret = testWebhookSecret
	h := b.handler()

	workSession := "cs_test_work1234567890abcd"
	evObj := map[string]any{
		"id": "evt_work_1", "object": "event", "type": "checkout.session.completed", "api_version": "2099-01-01",
		"data": map[string]any{"object": map[string]any{
			"id": workSession, "object": "checkout.session", "mode": "subscription",
			"payment_status": "paid", "customer": "cus_work1", "subscription": "sub_work1",
			"metadata": map[string]string{penMetaKey: penMetaValue, planMetaKey: planWork},
		}},
	}
	ev, _ := json.Marshal(evObj)
	if code, out := sendEvent(t, h, ev, signed(ev, testWebhookSecret, time.Now())); code != 200 {
		t.Fatalf("work paid event: %d %v", code, out)
	}
	codes, _ := os.ReadFile(filepath.Join(home, "signup", "codes"))
	if !strings.Contains(string(codes), " vanity work paid "+workSession) {
		t.Fatalf("codes missing vanity work paid tag:\n%s", codes)
	}
	pays, _ := os.ReadFile(filepath.Join(home, "signup", "payments"))
	if !strings.HasSuffix(strings.TrimSpace(string(pays)), " work") {
		t.Fatalf("payments missing work plan:\n%s", pays)
	}
	rec, ok, err := b.findPayment(workSession)
	if err != nil || !ok || rec.plan != planWork {
		t.Fatalf("findPayment work = (%+v, %v, %v)", rec, ok, err)
	}
	// Provisioning with the Work paid code raises a bare Work pen (plan=work, theme=work).
	pc, po := call(h, "POST", "/provision", fmt.Sprintf(`{"code":%q,"pen":"acmework","owner":"alice"}`, rec.code), auth)
	if pc != 201 || po["pen"] != "acmework" || po["plan"] != "work" || po["theme"] != "work" {
		t.Fatalf("provision with work bought code: %d %v", pc, po)
	}
	ledger, _ := os.ReadFile(filepath.Join(home, "signup", "raised.log"))
	if !strings.Contains(string(ledger), "plan work, customer cus_work1") {
		t.Fatalf("ledger missing plan work:\n%s", ledger)
	}

	subEv, _ := json.Marshal(map[string]any{
		"id": "evt_work_2", "object": "event", "type": "customer.subscription.deleted",
		"data": map[string]any{"object": map[string]any{
			"id": "sub_work1", "customer": "cus_work1",
			"metadata": map[string]string{penMetaKey: penMetaValue, planMetaKey: planWork},
		}},
	})
	if code, _ := sendEvent(t, h, subEv, signed(subEv, testWebhookSecret, time.Now())); code != 200 {
		t.Fatalf("work sub deleted: %d", code)
	}
	ledger, _ = os.ReadFile(filepath.Join(home, "signup", "raised.log"))
	if !strings.Contains(string(ledger), "subscription sub_work1 ended (plan work, customer cus_work1)") {
		t.Fatalf("ledger missing work cancellation:\n%s", ledger)
	}
}
