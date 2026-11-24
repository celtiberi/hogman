package main

// Paying for a pen (D-28): Stripe's hosted Checkout takes the card, so card
// details never reach this server. A paid checkout buys one sign-up code, and
// the code then works exactly like one the operator hands out.
//
//   - web: POST /api/checkout starts a Checkout Session and sends the browser
//     to Stripe. Stripe calls POST /api/stripe/webhook when it's paid; the page
//     passes the raw event to the broker untouched. /paid.html asks
//     GET /api/paid?session_id=... until the code is ready.
//   - broker: holds the webhook signing secret and checks every event's
//     signature itself, so a compromised page can't fake a payment. A paid
//     session gets a code once, however often Stripe retries.
//
// The web side holds the Stripe API key; give it a restricted key that can
// only write Checkout Sessions. Kept here: the session, customer and
// subscription IDs and the code (needed to act on a cancelled subscription).
// No names, emails or card details: Stripe has those.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

const (
	maxWebhookBody = 64 << 10
	paidTag        = "paid"   // the note on a code a payment bought
	penMetaKey     = "hogman" // metadata on our sessions, so other sales don't mint codes
	penMetaValue   = "pen"
	planMetaKey    = "plan" // metadata recording which tier was bought ("personal" or "work")
	planPersonal   = "personal"
	planWork       = "work"
	codeAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // as hogman-host's rand_chars: no 0/O, 1/I
)

func planFromMeta(meta map[string]string) string {
	if meta[planMetaKey] == planWork {
		return planWork
	}
	return planPersonal
}

var sessionRE = regexp.MustCompile(`^cs_(test|live)_[A-Za-z0-9]{10,200}$`)

// --- web side ---

// stripeCheckout is what the page needs to sell a pen. nil: selling is off.
type stripeCheckout struct {
	client          *stripe.Client
	price           string            // personal price_...
	workPrice       string            // optional Work price_... (falls back to price when empty)
	publicURL       string            // default https://get.example.com, for Stripe's redirects
	allowedOrigins  map[string]string // lowercased bare host -> allowlisted https://<host>
	automatTax      bool              // Stripe Tax computes tax (needs Stripe Tax set up)
	createSessionFn func(ctx context.Context, p *stripe.CheckoutSessionCreateParams) (string, error)
	cancelSubFn     func(ctx context.Context, subID string) error
}

func (sc *stripeCheckout) priceForPlan(plan string) string {
	if plan == planWork {
		return sc.workPrice
	}
	return sc.price
}

func (wb *web) forSaleForRequest(r *http.Request) bool {
	if wb.stripe == nil {
		return false
	}
	if wb.isWorkHost(r) {
		return wb.stripe.workPrice != ""
	}
	return true
}

func (sc *stripeCheckout) allowOrigin(rawURL string) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(rawURL), "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return
	}
	if sc.allowedOrigins == nil {
		sc.allowedOrigins = map[string]string{}
	}
	sc.allowedOrigins[stripHostPort(u.Host)] = "https://" + u.Host
}

func (sc *stripeCheckout) originForHost(reqHost string) string {
	if origin, ok := sc.allowedOrigins[stripHostPort(reqHost)]; ok {
		return origin
	}
	return sc.publicURL
}

func loadStripeCheckout() *stripeCheckout {
	keyFile, price := env("STRIPE_SECRET_KEY_FILE", ""), env("STRIPE_PRICE", "")
	if keyFile == "" || price == "" {
		return nil
	}
	b, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatalf("stripe key: %v", err)
	}
	key := strings.TrimSpace(string(b))
	if !validStripeKey(key) {
		log.Fatal("STRIPE_SECRET_KEY_FILE doesn't hold a Stripe secret or restricted key")
	}
	pub := strings.TrimRight(env("PUBLIC_URL", ""), "/")
	if !strings.HasPrefix(pub, "https://") {
		log.Fatal("PUBLIC_URL must be the page's https:// address when selling pens")
	}
	sc := &stripeCheckout{
		client:     stripe.NewClient(key),
		price:      price,
		workPrice:  strings.TrimSpace(env("STRIPE_WORK_PRICE", "")),
		publicURL:  pub,
		automatTax: env("STRIPE_AUTOMATIC_TAX", "") == "1",
	}
	sc.allowOrigin(pub)
	if workHost := stripHostPort(env("WORK_SIGNUP_HOST", "")); workHost != "" {
		sc.allowOrigin("https://" + workHost)
	}
	log.Printf("selling pens with Stripe (%s mode)", stripeMode(key))
	return sc
}

func validStripeKey(k string) bool {
	return regexp.MustCompile(`^(sk|rk)_(test|live)_[A-Za-z0-9]{10,200}$`).MatchString(k)
}

func stripeMode(k string) string {
	if strings.Contains(k, "_live_") {
		return "live"
	}
	return "test"
}

func (sc *stripeCheckout) params() *stripe.CheckoutSessionCreateParams {
	return sc.paramsFor(sc.publicURL, planPersonal)
}

func (sc *stripeCheckout) paramsFor(origin, plan string) *stripe.CheckoutSessionCreateParams {
	if origin == "" {
		origin = sc.publicURL
	}
	if plan != planWork {
		plan = planPersonal
	}
	meta := map[string]string{penMetaKey: penMetaValue, planMetaKey: plan}
	subMeta := map[string]string{penMetaKey: penMetaValue, planMetaKey: plan}
	p := &stripe.CheckoutSessionCreateParams{
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems:  []*stripe.CheckoutSessionCreateLineItemParams{{Price: stripe.String(sc.priceForPlan(plan)), Quantity: stripe.Int64(1)}},
		SuccessURL: stripe.String(origin + "/paid.html?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(origin + "/"),
		Metadata:   meta,
		SubscriptionData: &stripe.CheckoutSessionCreateSubscriptionDataParams{
			Metadata: subMeta,
		},
		// Businesses can add their VAT number (EU/UK reverse charge).
		TaxIDCollection: &stripe.CheckoutSessionCreateTaxIDCollectionParams{Enabled: stripe.Bool(true)},
	}
	if sc.automatTax {
		p.AutomaticTax = &stripe.CheckoutSessionCreateAutomaticTaxParams{Enabled: stripe.Bool(true)}
		p.BillingAddressCollection = stripe.String(string(stripe.CheckoutSessionBillingAddressCollectionRequired))
	}
	return p
}

func (sc *stripeCheckout) renewParamsFor(origin, pen, plan, renewNonce string) *stripe.CheckoutSessionCreateParams {
	if origin == "" {
		origin = sc.publicURL
	}
	if plan != planWork {
		plan = planPersonal
	}
	meta := map[string]string{
		penMetaKey:    penMetaValue,
		planMetaKey:   plan,
		"action":      "renew",
		"pen":         pen,
		"renew_nonce": renewNonce,
	}
	subMeta := map[string]string{penMetaKey: penMetaValue, planMetaKey: plan, "pen": pen}
	p := &stripe.CheckoutSessionCreateParams{
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems:  []*stripe.CheckoutSessionCreateLineItemParams{{Price: stripe.String(sc.priceForPlan(plan)), Quantity: stripe.Int64(1)}},
		SuccessURL: stripe.String(origin + "/?renewed=1"),
		CancelURL:  stripe.String(origin + "/"),
		Metadata:   meta,
		SubscriptionData: &stripe.CheckoutSessionCreateSubscriptionDataParams{
			Metadata: subMeta,
		},
		TaxIDCollection: &stripe.CheckoutSessionCreateTaxIDCollectionParams{Enabled: stripe.Bool(true)},
	}
	if sc.automatTax {
		p.AutomaticTax = &stripe.CheckoutSessionCreateAutomaticTaxParams{Enabled: stripe.Bool(true)}
		p.BillingAddressCollection = stripe.String(string(stripe.CheckoutSessionBillingAddressCollectionRequired))
	}
	return p
}

func (sc *stripeCheckout) createCheckoutURL(ctx context.Context, p *stripe.CheckoutSessionCreateParams) (string, error) {
	if sc.createSessionFn != nil {
		return sc.createSessionFn(ctx, p)
	}
	s, err := sc.client.V1CheckoutSessions.Create(ctx, p)
	if err != nil || s == nil {
		return "", err
	}
	return s.URL, nil
}

func isStripeNotFound(err error) bool {
	var se *stripe.Error
	return errors.As(err, &se) && (se.HTTPStatusCode == 404 || se.Code == stripe.ErrorCodeResourceMissing)
}

// cancelSubscription cancels a replaced Stripe subscription so it cannot
// double-charge alongside the new subscription (I-6). It retrieves the
// subscription first and treats already-canceled/incomplete_expired or missing
// subscriptions as done without issuing a redundant Cancel call (B2).
func (sc *stripeCheckout) cancelSubscription(ctx context.Context, subID string) error {
	if sc.cancelSubFn != nil {
		return sc.cancelSubFn(ctx, subID)
	}
	sub, err := sc.client.V1Subscriptions.Retrieve(ctx, subID, nil)
	if err != nil {
		if isStripeNotFound(err) {
			return nil
		}
		return err
	}
	if sub != nil && (sub.Status == stripe.SubscriptionStatusCanceled || sub.Status == stripe.SubscriptionStatusIncompleteExpired) {
		return nil
	}
	_, err = sc.client.V1Subscriptions.Cancel(ctx, subID, nil)
	if err != nil && !isStripeNotFound(err) {
		return err
	}
	return nil
}

func (wb *web) drainPendingSubCancels(ctx context.Context) {
	if wb.stripe == nil {
		return
	}
	wb.cancelMu.Lock()
	defer wb.cancelMu.Unlock()

	code, out := wb.ask(ctx, "GET", "/lifecycle/pending-cancels", nil)
	if code != 200 {
		return
	}
	rawItems, _ := out["items"].([]any)
	for _, entry := range rawItems {
		m, _ := entry.(map[string]any)
		pen, _ := m["pen"].(string)
		subID, _ := m["subscription_id"].(string)
		if pen == "" || !strings.HasPrefix(subID, "sub_") {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := wb.stripe.cancelSubscription(cctx, subID)
		cancel()
		if err != nil {
			log.Printf("stripe cancel old subscription %s (pen %s): %v", subID, pen, err)
			_, _ = wb.ask(ctx, "POST", "/lifecycle/cancel-alert", map[string]string{
				"pen":             pen,
				"subscription_id": subID,
				"error":           err.Error(),
			})
			continue
		}
		_, _ = wb.ask(ctx, "POST", "/lifecycle/cancel-done", map[string]string{
			"pen":             pen,
			"subscription_id": subID,
		})
	}
}

func (wb *web) runPendingSubCancelLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	// Drain once shortly after startup in case a previous run died mid-cancel.
	time.Sleep(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		wb.drainPendingSubCancels(ctx)
		cancel()
		<-t.C
	}
}

// renew starts a Stripe Checkout Session ONLY for a valid, short-lived,
// single-use signed renewal token minted inside the pen by an active owner or
// admin (D-35). Pen, plan, and payer_handle all come from the verified token
// via the broker — never from the browser.
func (wb *web) renew(w http.ResponseWriter, r *http.Request) {
	if wb.stripe == nil {
		jsonOut(w, 404, map[string]string{"error": "pens aren't for sale here"})
		return
	}
	if !wb.requireSameOriginJSON(w, r) {
		return
	}
	var in struct {
		Token          string `json:"token"`
		TurnstileToken string `json:"turnstile_token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	tok := strings.TrimSpace(in.Token)
	if len(tok) < 20 || len(tok) > 512 {
		jsonOut(w, 400, map[string]string{"error": "invalid renewal token"})
		return
	}
	clientIP := wb.clientIP(r)
	now := time.Now()
	if !wb.checkouts.allow(rateLimitKey(clientIP), now) {
		jsonOut(w, 429, map[string]string{"error": "too many tries from here; wait an hour"})
		return
	}
	if !wb.verifyTurnstile(w, r, in.TurnstileToken, clientIP) {
		return
	}
	if wb.globalCheckouts != nil && !wb.globalCheckouts.allow("*", now) {
		log.Printf("renew: global hourly cap reached")
		jsonOut(w, 429, map[string]string{"error": "checkout is temporarily busy; try again in a few minutes"})
		return
	}
	code, out := wb.ask(r.Context(), "POST", "/renew-verify", map[string]string{"token": tok})
	if code != 200 {
		jsonOut(w, code, out)
		return
	}
	pen, _ := out["pen"].(string)
	plan, _ := out["plan"].(string)
	renewNonce, _ := out["renew_nonce"].(string)
	if plan != planWork {
		plan = planPersonal
	}
	if wb.stripe.priceForPlan(plan) == "" {
		jsonOut(w, 404, map[string]string{"error": "renewals for this plan aren't enabled here"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	checkoutURL, err := wb.stripe.createCheckoutURL(ctx, wb.stripe.renewParamsFor(wb.stripe.originForHost(r.Host), pen, plan, renewNonce))
	if err != nil || !strings.HasPrefix(checkoutURL, "https://") {
		log.Printf("stripe renew checkout (%s): %v", pen, err)
		jsonOut(w, 502, map[string]string{"error": "the payment page didn't open; try again in a minute"})
		return
	}
	jsonOut(w, 200, map[string]string{"url": checkoutURL})
}

// penDelete handles owner-authenticated self-service pen deletion (I-24).
// Protected by same-origin JSON check, per-IP rate limit (5/hr), Turnstile,
// and a single-use domain-separated HMAC token (hogman-delete-v1:) verified
// on the broker against the pen's renew.key and live owner membership.
//
// Billing-first invariant: if the pen has any active/pending Stripe
// subscription, signup-web cancels it immediately BEFORE calling broker
// /pen-delete/commit. If Stripe cancellation fails, the pen is NOT purged.
func (wb *web) penDelete(w http.ResponseWriter, r *http.Request) {
	if !wb.requireSameOriginJSON(w, r) {
		return
	}
	clientIP := wb.clientIP(r)
	if wb.deletes != nil && !wb.deletes.allow(rateLimitKey(clientIP), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "too many tries from here; wait an hour"})
		return
	}
	var in struct {
		Token          string `json:"token"`
		TurnstileToken string `json:"turnstile_token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	tok := strings.TrimSpace(in.Token)
	if len(tok) < 20 || len(tok) > 512 {
		jsonOut(w, 400, map[string]string{"error": "invalid delete token"})
		return
	}
	if !wb.verifyTurnstile(w, r, in.TurnstileToken, clientIP) {
		return
	}
	code, out := wb.ask(r.Context(), "POST", "/pen-delete/prepare", map[string]string{"token": tok})
	if code != 200 {
		jsonOut(w, code, out)
		return
	}
	pen, _ := out["pen"].(string)
	nonce, _ := out["delete_nonce"].(string)
	var subIDs []string
	if rawSubs, ok := out["subscription_ids"].([]any); ok {
		for _, s := range rawSubs {
			if id, ok := s.(string); ok && strings.HasPrefix(id, "sub_") {
				subIDs = append(subIDs, id)
			}
		}
	}

	if len(subIDs) > 0 {
		if wb.stripe == nil {
			log.Printf("pen delete (%s): subscription(s) %v present but Stripe is not configured; aborting purge", pen, subIDs)
			jsonOut(w, 502, map[string]string{"error": "billing cancellation is unavailable right now; your pen was not deleted"})
			return
		}
		for _, subID := range subIDs {
			cctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			err := wb.stripe.cancelSubscription(cctx, subID)
			cancel()
			if err != nil {
				log.Printf("pen delete (%s): cancel Stripe subscription %s failed: %v (aborting purge)", pen, subID, err)
				jsonOut(w, 502, map[string]string{"error": "could not cancel your subscription right now; your pen was not deleted — please try again"})
				return
			}
		}
	}

	commitCtx, commitCancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer commitCancel()
	commitReq := map[string]any{
		"pen":          pen,
		"delete_nonce": nonce,
	}
	if len(subIDs) > 0 {
		commitReq["cancelled_subs"] = subIDs
	}
	ccode, cout := wb.ask(commitCtx, "POST", "/pen-delete/commit", commitReq)
	jsonOut(w, ccode, cout)
}

// checkout starts a Checkout Session. Not when the server is full: nobody
// should pay for a pen that can't be raised.
func (wb *web) checkout(w http.ResponseWriter, r *http.Request) {
	if !wb.forSaleForRequest(r) {
		jsonOut(w, 404, map[string]string{"error": "pens aren't for sale here"})
		return
	}
	if !wb.requireSameOriginJSON(w, r) {
		return
	}
	var in struct {
		TurnstileToken string `json:"turnstile_token"`
	}
	if r.Body != nil {
		b, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			jsonOut(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if len(bytes.TrimSpace(b)) > 0 {
			if err := json.Unmarshal(b, &in); err != nil {
				jsonOut(w, 400, map[string]string{"error": "bad request"})
				return
			}
		}
	}
	clientIP := wb.clientIP(r)
	now := time.Now()
	if !wb.checkouts.allow(rateLimitKey(clientIP), now) {
		jsonOut(w, 429, map[string]string{"error": "too many tries from here; wait an hour"})
		return
	}
	if wb.turnstile != nil {
		if err := wb.turnstile.verify(r.Context(), in.TurnstileToken, clientIP); err != nil {
			jsonOut(w, 403, map[string]string{"error": "verification check failed; please try again"})
			return
		}
	}
	if wb.globalCheckouts != nil && !wb.globalCheckouts.allow("*", now) {
		log.Printf("checkout: global hourly cap reached")
		jsonOut(w, 429, map[string]string{"error": "checkout is temporarily busy; try again in a few minutes"})
		return
	}
	code, out := wb.ask(r.Context(), "GET", "/capacity", nil)
	if code != 200 {
		jsonOut(w, code, out)
		return
	}
	if open, _ := out["open"].(bool); !open {
		jsonOut(w, 409, map[string]string{"error": "the farm is full right now; join the waiting list"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	plan := planPersonal
	if wb.isWorkHost(r) {
		plan = planWork
	}
	s, err := wb.stripe.client.V1CheckoutSessions.Create(ctx, wb.stripe.paramsFor(wb.stripe.originForHost(r.Host), plan))
	if err != nil || s == nil || !strings.HasPrefix(s.URL, "https://") {
		log.Printf("stripe checkout: %v", err)
		jsonOut(w, 502, map[string]string{"error": "the payment page didn't open; try again in a minute"})
		return
	}
	jsonOut(w, 200, map[string]string{"url": s.URL})
}

// stripeWebhook hands Stripe's event to the broker, which checks it.
func (wb *web) stripeWebhook(w http.ResponseWriter, r *http.Request) {
	if wb.stripe == nil {
		http.NotFound(w, r)
		return
	}
	if !wb.webhooks.allow(rateLimitKey(wb.clientIP(r)), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "slow down a little"}) // Stripe retries
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	sig := r.Header.Get("Stripe-Signature")
	if sig == "" || len(sig) > 1024 {
		jsonOut(w, 400, map[string]string{"error": "missing signature"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	code, out := wb.ask(ctx, "POST", "/stripe/event", map[string]string{"payload": string(body), "signature": sig})
	if code == 200 && out["ok"] == "renewed" {
		go func() {
			dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
			defer dcancel()
			wb.drainPendingSubCancels(dctx)
		}()
	}
	jsonOut(w, code, out)
}

// paid tells the page whether the code a checkout bought is ready.
func (wb *web) paid(w http.ResponseWriter, r *http.Request) {
	if wb.stripe == nil {
		jsonOut(w, 404, map[string]string{"error": "pens aren't for sale here"})
		return
	}
	if !wb.jobPolls.allow(rateLimitKey(wb.clientIP(r)), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "slow down a little"})
		return
	}
	id := r.URL.Query().Get("session_id")
	if !sessionRE.MatchString(id) {
		jsonOut(w, 400, map[string]string{"error": "that isn't a payment we know"})
		return
	}
	code, out := wb.ask(r.Context(), "GET", "/paid-code?session="+id, nil)
	jsonOut(w, code, out)
}

// --- broker side ---

type stripeEventIn struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// The fields we read from a Checkout Session (data.object of its events).
type checkoutObject struct {
	ID             string            `json:"id"`
	Mode           string            `json:"mode"`
	PaymentStatus  string            `json:"payment_status"`
	Currency       string            `json:"currency"`
	AmountTotal    int64             `json:"amount_total"`
	AmountSubtotal int64             `json:"amount_subtotal"`
	Customer       string            `json:"customer"`
	Subscription   string            `json:"subscription"`
	Metadata       map[string]string `json:"metadata"`
}

type subscriptionObject struct {
	ID       string            `json:"id"`
	Customer string            `json:"customer"`
	Metadata map[string]string `json:"metadata"`
}

type invoiceObject struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	BillingReason string `json:"billing_reason"`
	Currency      string `json:"currency"`
	Customer      string `json:"customer"`
	Subscription  string `json:"subscription"`
	AmountPaid    int64  `json:"amount_paid"`
}

func (b *broker) checkPaidAmount(id, plan, currency string, paidCents int64) (ok bool, reason string) {
	if b.expectedCurrency != "" && strings.ToLower(strings.TrimSpace(currency)) != b.expectedCurrency {
		return false, fmt.Sprintf("currency %q != expected %q", currency, b.expectedCurrency)
	}
	minCents := b.minPersonalCents
	if plan == planWork {
		minCents = b.minWorkCents
	}
	if minCents > 0 && paidCents < minCents {
		return false, fmt.Sprintf("plan=%s paid=%d %q < min=%d", plan, paidCents, currency, minCents)
	}
	return true, ""
}

func hasCodeWord(note, word string) bool {
	for _, f := range strings.Fields(note) {
		if f == word {
			return true
		}
	}
	return false
}

func (b *broker) stripeEvent(w http.ResponseWriter, r *http.Request) {
	if b.webhookSecret == "" {
		jsonOut(w, 404, map[string]string{"error": "payments are off"})
		return
	}
	var in stripeEventIn
	r.Body = http.MaxBytesReader(w, r.Body, 2*maxWebhookBody)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	// The signature covers the raw body; older than 5 minutes is refused, so a
	// captured event can't be replayed later. We read only a few fields, so a
	// newer API version on the endpoint is fine.
	ev, err := webhook.ConstructEventWithOptions([]byte(in.Payload), in.Signature, b.webhookSecret,
		webhook.ConstructEventOptions{IgnoreAPIVersionMismatch: true})
	if err != nil {
		log.Printf("stripe event refused: %v", err)
		jsonOut(w, 400, map[string]string{"error": "bad signature"})
		return
	}
	if b.expectLivemode != nil && ev.Livemode != *b.expectLivemode {
		log.Printf("stripe event refused: livemode=%v (want %v)", ev.Livemode, *b.expectLivemode)
		jsonOut(w, 400, map[string]string{"error": "livemode mismatch"})
		return
	}
	switch ev.Type {
	case "checkout.session.completed", "checkout.session.async_payment_succeeded":
		var s checkoutObject
		if err := json.Unmarshal(ev.Data.Raw, &s); err != nil || !sessionRE.MatchString(s.ID) {
			jsonOut(w, 400, map[string]string{"error": "unreadable checkout session"})
			return
		}
		if s.Metadata[penMetaKey] != penMetaValue || s.PaymentStatus != "paid" {
			jsonOut(w, 200, map[string]string{"ok": "ignored"}) // not ours, or not paid yet
			return
		}
		if s.Mode != "subscription" {
			jsonOut(w, 200, map[string]string{"ok": "ignored"})
			return
		}
		// D-35: Owner/Admin renewal checkout for an existing pen in grace or sleep.
		if s.Metadata["action"] == "renew" {
			pen := strings.ToLower(strings.TrimSpace(s.Metadata["pen"]))
			if _, ok := validPen(pen); !ok {
				jsonOut(w, 400, map[string]string{"error": "invalid renewal pen"})
				return
			}
			// Authoritative plan comes from lifecycle.json (not client/session metadata)
			// so a Work pen cannot be renewed at a Personal price.
			rec, rerr := loadPenLifecycle(b.lifecyclePath(pen))
			if os.IsNotExist(rerr) {
				log.Printf("stripe renew %s (%s): no lifecycle.json; ignoring", s.ID, pen)
				jsonOut(w, 200, map[string]string{"ok": "ignored"})
				return
			}
			if rerr != nil {
				log.Printf("stripe renew %s (%s): %v", s.ID, pen, rerr)
				jsonOut(w, 500, map[string]string{"error": "renewal failed"})
				return
			}
			if ok, reason := b.checkPaidAmount(s.ID, rec.Plan, s.Currency, s.AmountTotal); !ok {
				log.Printf("stripe renew %s (%s) refused: %s", s.ID, pen, reason)
				b.notifyKind("health", fmt.Sprintf("Stripe renewal session %s (%s) rejected: %s", s.ID, pen, reason))
				jsonOut(w, 500, map[string]string{"error": "payment below configured minimum"})
				return
			}
			updatedRec, alreadyApplied, wasSleeping, err := b.recordRenewal(pen, s.ID, s.Subscription, s.Customer, s.Metadata["renew_nonce"], time.Now().UTC())
			if errors.Is(err, errNoLifecycle) {
				jsonOut(w, 200, map[string]string{"ok": "ignored"})
				return
			}
			if err != nil {
				log.Printf("stripe renew %s (%s): %v", s.ID, pen, err)
				jsonOut(w, 500, map[string]string{"error": "renewal failed"})
				return
			}
			if !alreadyApplied {
				if wasSleeping || (updatedRec != nil && updatedRec.PendingOwner != "") {
					go func(pen string, wake bool) {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
						defer cancel()
						if err := b.finishRenewalWork(ctx, pen, wake); err != nil {
							log.Printf("stripe renew %s (%s) post-work: %v", s.ID, pen, err)
						}
					}(pen, wasSleeping)
				}
				b.notifyKind("raise", "Pen renewed ("+pen+")")
			}
			jsonOut(w, 200, map[string]string{"ok": "renewed"})
			return
		}
		plan := planFromMeta(s.Metadata)
		if ok, reason := b.checkPaidAmount(s.ID, plan, s.Currency, s.AmountTotal); !ok {
			log.Printf("stripe %s alert: %s (returning 500 so Stripe retries)", s.ID, reason)
			b.notifyKind("health", fmt.Sprintf("Stripe paid session %s (%s) rejected: %s", s.ID, plan, reason))
			jsonOut(w, 500, map[string]string{"error": "payment below configured minimum"})
			return
		}
		code, fresh, err := b.codeForPayment(s)
		if err != nil {
			log.Printf("stripe %s: %v", s.ID, err)
			jsonOut(w, 500, map[string]string{"error": "internal error"}) // Stripe retries
			return
		}
		if fresh {
			plan := planFromMeta(s.Metadata)
			b.ledger(fmt.Sprintf("%s payment %s bought code %s (plan %s, customer %s, subscription %s)",
				time.Now().UTC().Format(time.RFC3339), s.ID, code, plan, s.Customer, s.Subscription))
			b.notifyKind("raise", "A pen was paid for ("+plan+")")
		}
		jsonOut(w, 200, map[string]string{"ok": "code ready"})
	case "invoice.paid":
		var inv invoiceObject
		if err := json.Unmarshal(ev.Data.Raw, &inv); err == nil && inv.Status == "paid" && inv.Subscription != "" {
			b.lifecycleMu.Lock()
			replacedPen, isReplaced := b.findPenByReplacedSubscription(inv.Subscription)
			pen, ok := "", false
			var penPlan string
			if !isReplaced && inv.BillingReason == "subscription_cycle" {
				pen, ok = b.findPenBySubscription(inv.Subscription)
				if ok {
					if rec, rerr := loadPenLifecycle(b.lifecyclePath(pen)); rerr == nil {
						penPlan = rec.Plan
					}
				}
			}
			b.lifecycleMu.Unlock()
			if isReplaced {
				msg := fmt.Sprintf("Double-charge alert: paid invoice %s arrived for replaced subscription %s on pen %s (customer %s) — issue a Stripe refund and verify the old subscription is cancelled",
					inv.ID, inv.Subscription, replacedPen, inv.Customer)
				log.Print(msg)
				b.ledger(fmt.Sprintf("%s %s", b.now().Format(time.RFC3339), msg))
				b.notifyKind("health", msg)
				jsonOut(w, 200, map[string]string{"ok": "double-charge-alerted"})
				return
			}
			if ok {
				if okAmt, reason := b.checkPaidAmount(inv.ID, penPlan, inv.Currency, inv.AmountPaid); !okAmt {
					log.Printf("stripe invoice %s (%s) refused: %s", inv.ID, pen, reason)
					b.notifyKind("health", fmt.Sprintf("Stripe invoice %s (%s) rejected: %s", inv.ID, pen, reason))
					jsonOut(w, 500, map[string]string{"error": "payment below configured minimum"})
					return
				}
				_, alreadyApplied, wasSleeping, err := b.recordRenewal(pen, inv.ID, inv.Subscription, inv.Customer, "", time.Now().UTC())
				if err != nil && !errors.Is(err, errNoLifecycle) {
					log.Printf("stripe invoice %s renew %s: %v", inv.ID, pen, err)
					jsonOut(w, 500, map[string]string{"error": "renewal failed"})
					return
				}
				if err == nil && !alreadyApplied && wasSleeping {
					go func(pen string) {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
						defer cancel()
						if err := b.finishRenewalWork(ctx, pen, true); err != nil {
							log.Printf("stripe invoice %s (%s) wake: %v", inv.ID, pen, err)
						}
					}(pen)
				}
			}
		}
		jsonOut(w, 200, map[string]string{"ok": "noted"})
	case "customer.subscription.deleted":
		var sub subscriptionObject
		if err := json.Unmarshal(ev.Data.Raw, &sub); err == nil && sub.Metadata[penMetaKey] == penMetaValue {
			// D-35: cancelling mid-year changes nothing; the pen runs to its paid_until date.
			plan := planFromMeta(sub.Metadata)
			now := b.now()
			b.lifecycleMu.Lock()
			if pen, ok := b.findPenBySubscription(sub.ID); ok {
				p := b.lifecyclePath(pen)
				_ = withPenLifecycleFileLock(p, func() error {
					rec, err := loadPenLifecycle(p)
					if err != nil || rec.CancelledAt != 0 {
						return nil
					}
					rec.CancelledAt = now.Unix()
					rec.UpdatedAt = now.Unix()
					if err := savePenLifecycle(p, rec); err != nil {
						return err
					}
					_ = b.syncRegistrarHostMeta(pen, rec)
					return nil
				})
			}
			b.clearPendingCancelSub(sub.ID, now)
			b.lifecycleMu.Unlock()
			b.ledger(fmt.Sprintf("%s subscription %s ended (plan %s, customer %s): pen runs until paid_until",
				now.Format(time.RFC3339), sub.ID, plan, sub.Customer))
			b.notifyKind("raise", "A pen's subscription ended ("+plan+")")
		}
		jsonOut(w, 200, map[string]string{"ok": "noted"})
	default:
		jsonOut(w, 200, map[string]string{"ok": "ignored"})
	}
}

// paidCode answers the page: the code for a paid session, once its event came.
func (b *broker) paidCode(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("session")
	if !sessionRE.MatchString(id) {
		jsonOut(w, 400, map[string]string{"error": "that isn't a payment we know"})
		return
	}
	rec, ok, err := b.findPayment(id)
	if err != nil {
		log.Printf("payments: %v", err)
		jsonOut(w, 500, map[string]string{"error": "internal error"})
		return
	}
	if !ok {
		jsonOut(w, 200, map[string]string{"state": "pending"})
		return
	}
	_, unused, err := b.findCode(rec.code)
	if err != nil {
		log.Printf("codes: %v", err)
		jsonOut(w, 500, map[string]string{"error": "internal error"})
		return
	}
	if !unused {
		jsonOut(w, 200, map[string]string{"state": "used"})
		return
	}
	jsonOut(w, 200, map[string]string{"state": "ready", "code": rec.code})
}

// --- payments: $HOGMAN_HOME/signup/payments, one line per paid session ---
// "<session> <code> <customer> <subscription> <unix time> <plan>"

type payment struct{ session, code, customer, subscription, plan string }

func (b *broker) paymentsPath() string { return filepath.Join(b.home, "signup", "payments") }

func (b *broker) findPaymentByCode(code string) (payment, bool, error) {
	unlock, err := b.lock(b.paymentsPath() + ".lock")
	if err != nil {
		return payment{}, false, err
	}
	defer unlock()
	f, err := os.Open(b.paymentsPath())
	if os.IsNotExist(err) {
		return payment{}, false, nil
	}
	if err != nil {
		return payment{}, false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) >= 4 && subtle.ConstantTimeCompare([]byte(p[1]), []byte(code)) == 1 {
			plan := planPersonal
			if len(p) >= 6 && p[5] == planWork {
				plan = planWork
			}
			return payment{session: p[0], code: p[1], customer: p[2], subscription: p[3], plan: plan}, true, nil
		}
	}
	return payment{}, false, sc.Err()
}

func (b *broker) findPayment(session string) (payment, bool, error) {
	unlock, err := b.lock(b.paymentsPath() + ".lock")
	if err != nil {
		return payment{}, false, err
	}
	defer unlock()
	return b.findPaymentLocked(session)
}

func (b *broker) findPaymentLocked(session string) (payment, bool, error) {
	f, err := os.Open(b.paymentsPath())
	if os.IsNotExist(err) {
		return payment{}, false, nil
	}
	if err != nil {
		return payment{}, false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) >= 4 && subtle.ConstantTimeCompare([]byte(p[0]), []byte(session)) == 1 {
			plan := planPersonal
			if len(p) >= 6 && p[5] == planWork {
				plan = planWork
			}
			return payment{session: p[0], code: p[1], customer: p[2], subscription: p[3], plan: plan}, true, nil
		}
	}
	return payment{}, false, sc.Err()
}

// codeForPayment returns the session's code, making it on the first event.
func (b *broker) codeForPayment(s checkoutObject) (code string, fresh bool, err error) {
	unlock, err := b.lock(b.paymentsPath() + ".lock")
	if err != nil {
		return "", false, err
	}
	defer unlock()
	if p, ok, err := b.findPaymentLocked(s.ID); err != nil || ok {
		return p.code, false, err
	}
	code, err = newSignupCode()
	if err != nil {
		return "", false, err
	}
	// The code first: a payment line always points at a code that existed.
	// Paid pens get a bare name of the buyer's choice (no -xxxx ending);
	// Work purchases carry the "work" tag so the broker provisions PLAN=work (D-30).
	codeNote := "vanity " + paidTag + " " + s.ID
	if planFromMeta(s.Metadata) == planWork {
		codeNote = "vanity work " + paidTag + " " + s.ID
	}
	if err := b.addCode(code, codeNote); err != nil {
		return "", false, err
	}
	// If the payment line can't be written, take the code back (best effort):
	// Stripe retries, and the retry makes a fresh code and line together.
	rollback := func(err error) (string, bool, error) {
		if uerr := b.useCode(code); uerr != nil {
			log.Printf("payments: couldn't take back code for %s: %v", s.ID, uerr)
		}
		return "", false, err
	}
	f, err := os.OpenFile(b.paymentsPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return rollback(err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s %s %s %d %s\n", s.ID, code, idOrDash(s.Customer), idOrDash(s.Subscription), time.Now().Unix(), planFromMeta(s.Metadata))
	if err != nil {
		return rollback(err)
	}
	// A failed sync may still have written the line: keep the code, so a
	// retry that finds the line hands out a code that exists.
	return code, true, f.Sync()
}

func (b *broker) addCode(code, note string) error {
	unlock, err := b.lockCodes()
	if err != nil {
		return err
	}
	defer unlock()
	f, err := os.OpenFile(b.codesPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s %s\n", code, note); err != nil {
		return err
	}
	return f.Sync()
}

func idOrDash(id string) string {
	if id == "" || strings.ContainsAny(id, " \t\r\n") {
		return "-"
	}
	return id
}

// newSignupCode: PIG-XXXX-XXXX from codeAlphabet, like hogman-host's codes.
func newSignupCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := []byte("PIG-")
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(c)%len(codeAlphabet)]) // 256 % 32 == 0: no bias
	}
	return string(out), nil
}

func readWebhookSecret(envName string) string {
	f := env(envName, "")
	if f == "" {
		return ""
	}
	b, err := os.ReadFile(f)
	if err != nil {
		log.Fatalf("%s: %v", envName, err)
	}
	s := strings.TrimSpace(string(b))
	if !strings.HasPrefix(s, "whsec_") || len(s) < 20 {
		log.Fatalf("%s doesn't hold a Stripe webhook signing secret (whsec_...)", envName)
	}
	return s
}
