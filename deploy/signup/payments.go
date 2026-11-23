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
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	codeAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // as hogman-host's rand_chars: no 0/O, 1/I
)

var sessionRE = regexp.MustCompile(`^cs_(test|live)_[A-Za-z0-9]{10,200}$`)

// --- web side ---

// stripeCheckout is what the page needs to sell a pen. nil: selling is off.
type stripeCheckout struct {
	client     *stripe.Client
	price      string // price_...
	publicURL  string // https://get.example.com, for Stripe's redirects
	automatTax bool   // Stripe Tax computes tax (needs Stripe Tax set up)
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
	log.Printf("selling pens with Stripe (%s mode)", stripeMode(key))
	return &stripeCheckout{client: stripe.NewClient(key), price: price, publicURL: pub, automatTax: env("STRIPE_AUTOMATIC_TAX", "") == "1"}
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
	p := &stripe.CheckoutSessionCreateParams{
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems:  []*stripe.CheckoutSessionCreateLineItemParams{{Price: stripe.String(sc.price), Quantity: stripe.Int64(1)}},
		SuccessURL: stripe.String(sc.publicURL + "/paid.html?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(sc.publicURL + "/"),
		Metadata:   map[string]string{penMetaKey: penMetaValue},
		SubscriptionData: &stripe.CheckoutSessionCreateSubscriptionDataParams{
			Metadata: map[string]string{penMetaKey: penMetaValue},
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

// checkout starts a Checkout Session. Not when the server is full: nobody
// should pay for a pen that can't be raised.
func (wb *web) checkout(w http.ResponseWriter, r *http.Request) {
	if wb.stripe == nil {
		jsonOut(w, 404, map[string]string{"error": "pens aren't for sale here"})
		return
	}
	if !wb.checkouts.allow(rateLimitKey(clientIP(r)), time.Now()) {
		jsonOut(w, 429, map[string]string{"error": "too many tries from here; wait an hour"})
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
	s, err := wb.stripe.client.V1CheckoutSessions.Create(ctx, wb.stripe.params())
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
	code, out := wb.ask(r.Context(), "POST", "/stripe/event", map[string]string{"payload": string(body), "signature": sig})
	jsonOut(w, code, out)
}

// paid tells the page whether the code a checkout bought is ready.
func (wb *web) paid(w http.ResponseWriter, r *http.Request) {
	if wb.stripe == nil {
		jsonOut(w, 404, map[string]string{"error": "pens aren't for sale here"})
		return
	}
	if !wb.jobPolls.allow(rateLimitKey(clientIP(r)), time.Now()) {
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
	ID            string            `json:"id"`
	Mode          string            `json:"mode"`
	PaymentStatus string            `json:"payment_status"`
	Customer      string            `json:"customer"`
	Subscription  string            `json:"subscription"`
	Metadata      map[string]string `json:"metadata"`
}

type subscriptionObject struct {
	ID       string            `json:"id"`
	Customer string            `json:"customer"`
	Metadata map[string]string `json:"metadata"`
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
		code, fresh, err := b.codeForPayment(s)
		if err != nil {
			log.Printf("stripe %s: %v", s.ID, err)
			jsonOut(w, 500, map[string]string{"error": "internal error"}) // Stripe retries
			return
		}
		if fresh {
			b.ledger(fmt.Sprintf("%s payment %s bought code %s (customer %s, subscription %s)",
				time.Now().UTC().Format(time.RFC3339), s.ID, code, s.Customer, s.Subscription))
			b.notifyKind("raise", "A pen was paid for")
		}
		jsonOut(w, 200, map[string]string{"ok": "code ready"})
	case "customer.subscription.deleted":
		var sub subscriptionObject
		if err := json.Unmarshal(ev.Data.Raw, &sub); err == nil && sub.Metadata[penMetaKey] == penMetaValue {
			// What a cancelled pen should do (warn, suspend, remove) is a later
			// decision; for now the operator hears about it and acts by hand.
			b.ledger(fmt.Sprintf("%s subscription %s ended (customer %s): see payments for its code",
				time.Now().UTC().Format(time.RFC3339), sub.ID, sub.Customer))
			b.notifyKind("raise", "A pen's subscription ended")
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
	if _, unused, err := b.findCode(rec.code); err == nil && !unused {
		jsonOut(w, 200, map[string]string{"state": "used"})
		return
	}
	jsonOut(w, 200, map[string]string{"state": "ready", "code": rec.code})
}

// --- payments: $HOGMAN_HOME/signup/payments, one line per paid session ---
// "<session> <code> <customer> <subscription> <unix time>"

type payment struct{ session, code, customer, subscription string }

func (b *broker) paymentsPath() string { return filepath.Join(b.home, "signup", "payments") }

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
		if len(p) >= 4 && p[0] == session {
			return payment{session: p[0], code: p[1], customer: p[2], subscription: p[3]}, true, nil
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
	// Paid pens get a bare name of the buyer's choice (no -xxxx ending).
	if err := b.addCode(code, "vanity "+paidTag+" "+s.ID); err != nil {
		return "", false, err
	}
	f, err := os.OpenFile(b.paymentsPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s %s %s %d\n", s.ID, code, idOrDash(s.Customer), idOrDash(s.Subscription), time.Now().Unix())
	if err != nil {
		return "", false, err
	}
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
