package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stripe/stripe-go/v87"
)

func signTestRenewToken(key []byte, pen, handle, role string, exp int64, nonce string) string {
	raw := fmt.Sprintf("v1|%s|%s|%s|%d|%s", pen, handle, role, exp, nonce)
	payload := base64.RawURLEncoding.EncodeToString([]byte(raw))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(renewTokenPurpose))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

func TestLifecycleStateMachineD35(t *testing.T) {
	t0 := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	paidUntil := t0.Add(lifecycleYearDuration)
	rec := penLifecycle{
		Plan:      planPersonal,
		State:     stateActive,
		PaidUntil: paidUntil.Unix(),
	}

	// Before paid_until: stays active.
	next, changed := evaluateLifecycle(rec, paidUntil.Add(-time.Second))
	if changed || next.State != stateActive {
		t.Fatalf("before paid_until: changed=%v state=%s", changed, next.State)
	}

	// B6: Even if sweeps were paused for 45 days past paid_until, evaluating
	// transitions at most ONE step (active -> grace) and gives a full 30 days
	// of visible grace from the moment grace starts (never jumping to sleep).
	lateSweep := paidUntil.Add(45 * 24 * time.Hour)
	lateGrace, changed := evaluateLifecycle(rec, lateSweep)
	if !changed || lateGrace.State != stateGrace {
		t.Fatalf("late sweep must enter grace first: changed=%v state=%s", changed, lateGrace.State)
	}
	if want := lateSweep.Add(30 * 24 * time.Hour).Unix(); lateGrace.GraceUntil != want {
		t.Fatalf("late sweep grace_until = %d, want %d (full 30d from grace start)", lateGrace.GraceUntil, want)
	}

	// SF-1: Active uncancelled Stripe subscription gets a 3-day auto-renew buffer.
	subRec := rec
	subRec.SubscriptionID = "sub_live_123"
	if _, ch := evaluateLifecycle(subRec, paidUntil.Add(2*24*time.Hour)); ch {
		t.Fatal("active subscription within 3-day buffer must not enter grace yet")
	}
	if subNext, ch := evaluateLifecycle(subRec, paidUntil.Add(3*24*time.Hour)); !ch || subNext.State != stateGrace {
		t.Fatalf("active subscription past 3-day buffer should enter grace: ch=%v state=%s", ch, subNext.State)
	}
	// Cancelled subscription enters grace immediately at paid_until (no buffer).
	subRec.CancelledAt = paidUntil.Add(-10 * 24 * time.Hour).Unix()
	if cancNext, ch := evaluateLifecycle(subRec, paidUntil); !ch || cancNext.State != stateGrace {
		t.Fatalf("cancelled subscription should enter grace at paid_until: ch=%v state=%s", ch, cancNext.State)
	}

	// Normal progression: active -> grace (30d) -> sleeping (365d) -> deleted.
	next, changed = evaluateLifecycle(rec, paidUntil)
	if !changed || next.State != stateGrace || next.GraceUntil != paidUntil.Add(30*24*time.Hour).Unix() {
		t.Fatalf("at paid_until: changed=%v rec=%+v", changed, next)
	}
	if stayGrace, ch := evaluateLifecycle(next, paidUntil.Add(29*24*time.Hour)); ch || stayGrace.State != stateGrace {
		t.Fatalf("day 29 grace: changed=%v state=%s", ch, stayGrace.State)
	}
	sleepTime := paidUntil.Add(30 * 24 * time.Hour)
	asleep, changed := evaluateLifecycle(next, sleepTime)
	if !changed || asleep.State != stateSleeping || asleep.SleepSince != sleepTime.Unix() || asleep.DeleteAfter != sleepTime.Add(365*24*time.Hour).Unix() {
		t.Fatalf("day 30 grace: changed=%v rec=%+v", changed, asleep)
	}
	if stillAsleep, ch := evaluateLifecycle(asleep, sleepTime.Add(364*24*time.Hour)); ch || stillAsleep.State != stateSleeping {
		t.Fatalf("day 364 sleep: changed=%v state=%s", ch, stillAsleep.State)
	}
	deleted, changed := evaluateLifecycle(asleep, sleepTime.Add(365*24*time.Hour))
	if !changed || deleted.State != stateDeleted {
		t.Fatalf("day 365 sleep: changed=%v state=%s", changed, deleted.State)
	}

	// Free pens stay active automatically across sweeps.
	freeRec := penLifecycle{Plan: planFree, State: stateActive}
	if freeNext, ch := evaluateLifecycle(freeRec, t0.Add(5*365*24*time.Hour)); ch || freeNext.State != stateActive {
		t.Fatalf("free pen should stay active automatically: changed=%v state=%s", ch, freeNext.State)
	}
}

func TestApplyRenewalNoBackdatingDefaultD35(t *testing.T) {
	paidUntil := time.Date(2027, 11, 24, 0, 0, 0, 0, time.UTC)
	graceRec := penLifecycle{
		Plan:       planWork,
		State:      stateGrace,
		PaidUntil:  paidUntil.Unix(),
		GraceUntil: paidUntil.Add(30 * 24 * time.Hour).Unix(),
	}

	// Renewing on day 20 of grace with backdate=false (D-35 default):
	// fresh 365-day year starts from day of payment, NOT old paid_until.
	payDay := paidUntil.Add(20 * 24 * time.Hour)
	renewed, wasSleeping := applyRenewal(graceRec, payDay, false)
	if wasSleeping || renewed.State != stateActive || renewed.GraceUntil != 0 || renewed.PendingWake {
		t.Fatalf("unexpected grace renewal: %+v wasSleeping=%v", renewed, wasSleeping)
	}
	if got, want := renewed.PaidUntil, payDay.Add(365*24*time.Hour).Unix(); got != want {
		t.Fatalf("no-backdating paid_until = %d, want %d", got, want)
	}

	// Opt-in backdate=true extends from old paid_until instead.
	backdated, _ := applyRenewal(graceRec, payDay, true)
	if got, want := backdated.PaidUntil, paidUntil.Add(365*24*time.Hour).Unix(); got != want {
		t.Fatalf("backdated paid_until = %d, want %d", got, want)
	}

	// Early renewal preserves remaining paid days.
	earlyDay := paidUntil.Add(-15 * 24 * time.Hour)
	activeRec := penLifecycle{Plan: planPersonal, State: stateActive, PaidUntil: paidUntil.Unix()}
	early, _ := applyRenewal(activeRec, earlyDay, false)
	if got, want := early.PaidUntil, paidUntil.Add(365*24*time.Hour).Unix(); got != want {
		t.Fatalf("early renewal paid_until = %d, want %d", got, want)
	}

	// Waking from sleep sets PendingWake=true and clears sleep timestamps.
	sleepRec := penLifecycle{
		Plan:        planPersonal,
		State:       stateSleeping,
		PaidUntil:   paidUntil.Unix(),
		SleepSince:  paidUntil.Add(30 * 24 * time.Hour).Unix(),
		DeleteAfter: paidUntil.Add(395 * 24 * time.Hour).Unix(),
	}
	wakeDay := paidUntil.Add(90 * 24 * time.Hour)
	woke, wasSleeping := applyRenewal(sleepRec, wakeDay, false)
	if !wasSleeping || !woke.PendingWake || woke.State != stateActive || woke.SleepSince != 0 || woke.DeleteAfter != 0 {
		t.Fatalf("wake renewal = %+v wasSleeping=%v", woke, wasSleeping)
	}
	if woke.PaidUntil != wakeDay.Add(365*24*time.Hour).Unix() {
		t.Fatalf("wake paid_until = %d, want %d", woke.PaidUntil, wakeDay.Add(365*24*time.Hour).Unix())
	}
}

func TestDueBillingAlertOrderingAndUnconfiguredEmail(t *testing.T) {
	t0 := time.Date(2027, 11, 24, 0, 0, 0, 0, time.UTC)
	rec := penLifecycle{
		Plan:        planPersonal,
		State:       stateGrace,
		PaidUntil:   t0.Unix(),
		GraceUntil:  t0.Add(30 * 24 * time.Hour).Unix(),
		AlertEmails: []string{"owner@example.com"},
	}

	// SF-6: Even on day 25 of grace, grace-start must fire BEFORE grace-day-23.
	day25 := t0.Add(25 * 24 * time.Hour)
	ms, _, _, due := dueBillingAlert("lab", rec, day25)
	if !due || ms != "grace-start" {
		t.Fatalf("expected grace-start first, got milestone=%q due=%v", ms, due)
	}
	rec.AlertsSent = map[string]int64{"grace-start": day25.Unix()}
	ms, _, body, due := dueBillingAlert("lab", rec, day25)
	if !due || ms != "grace-day-23" || !strings.Contains(body, "pen's home page") || !strings.Contains(body, "becomes an owner") || strings.Contains(body, "?renew=") {
		t.Fatalf("expected grace-day-23 with in-pen copy and no public renew URL, got milestone=%q due=%v body=%q", ms, due, body)
	}

	// SF-6: When Resend is unconfigured, sendBillingAlert returns (false, nil) so
	// sweepLifecycles does NOT mark the milestone sent.
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, "signup"), 0o700)
	_ = os.MkdirAll(filepath.Join(home, "pens", "lab", "data", "registrar"), 0o700)
	b := &broker{home: home, token: "test-token"}
	if err := savePenLifecycle(b.lifecyclePath("lab"), &penLifecycle{
		Plan:        planPersonal,
		State:       stateActive,
		PaidUntil:   t0.Unix(),
		AlertEmails: []string{"owner@example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	trs, err := b.sweepLifecycles(context.Background(), t0.Add(time.Hour), false)
	if err != nil || len(trs) != 1 || trs[0].AlertSent != "" {
		t.Fatalf("unconfigured email should not mark AlertSent: trs=%+v err=%v", trs, err)
	}
	saved, err := loadPenLifecycle(b.lifecyclePath("lab"))
	if err != nil || len(saved.AlertsSent) != 0 {
		t.Fatalf("AlertsSent must remain empty when Resend is unconfigured: %+v (%v)", saved, err)
	}
}

func TestBrokerLifecycleSweepBannerAlertsWakeRetryAndAdminPromotion(t *testing.T) {
	home := t.TempDir()
	logFile := filepath.Join(home, "host-calls.log")
	failWakeFlag := filepath.Join(home, "fail-wake")
	failPromoteFlag := filepath.Join(home, "fail-promote")
	fakeHost := filepath.Join(home, "fake-hogman-host")
	script := `#!/bin/sh
echo "$@" >> "` + logFile + `"
cmd="$1"
case "$cmd" in
  sleep) touch "` + home + `/pens/$2/.sleeping" ;;
  wake)
    if [ -f "` + failWakeFlag + `" ]; then
      echo "host temporarily full" >&2
      exit 1
    fi
    rm -f "` + home + `/pens/$2/.sleeping"
    ;;
  pen)
    if [ -f "` + failPromoteFlag + `" ]; then
      echo "pen still starting" >&2
      exit 1
    fi
    ;;
  purge)
    pen="$2"
    [ "$pen" = "--due" ] && pen="$3"
    rm -rf "` + home + `/pens/$pen/data"
    touch "` + home + `/pens/$pen/.removed" "` + home + `/pens/$pen/.retired"
    ;;
esac
exit 0
`
	if err := os.WriteFile(fakeHost, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(home, "host.env"), []byte("MAX_PENS=8\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(home, "signup"), 0o700)

	pen := "lab"
	// B4: billing-status.json lives under data/registrar/ (mounted into registrar).
	regDir := filepath.Join(home, "pens", pen, "data", "registrar")
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		t.Fatal(err)
	}

	var sentAlerts []string
	roles := map[string][2]string{
		"alice": {"admin", "active"},
		"bob":   {"member", "active"},
	}
	b := &broker{
		home:      home,
		tool:      fakeHost,
		token:     "test-token",
		publicURL: "https://get.example.com",
		alertSendFn: func(_ context.Context, to []string, subj, _ string) error {
			sentAlerts = append(sentAlerts, strings.Join(to, ",")+":"+subj)
			return nil
		},
		memberRoleFn: func(_ context.Context, _ string, handle string) (string, string, bool) {
			r, ok := roles[handle]
			return r[0], r[1], ok
		},
	}

	t0 := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	paidUntil := t0.Add(365 * 24 * time.Hour)
	if err := savePenLifecycle(b.lifecyclePath(pen), &penLifecycle{
		Plan:        planPersonal,
		State:       stateActive,
		PaidUntil:   paidUntil.Unix(),
		AlertEmails: []string{"owner@example.com"},
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Entering grace writes data/registrar/billing-status.json with pen + origin only (no ?renew=).
	trs, err := b.sweepLifecycles(context.Background(), paidUntil.Add(time.Hour), false)
	if err != nil || len(trs) != 1 || trs[0].To != stateGrace || trs[0].AlertSent != "grace-start" {
		t.Fatalf("grace sweep = (%+v, %v)", trs, err)
	}
	bannerBytes, err := os.ReadFile(b.registrarBillingPath(pen))
	if err != nil {
		t.Fatalf("expected registrar billing-status.json in grace: %v", err)
	}
	var banner portalBillingStatus
	if err := json.Unmarshal(bannerBytes, &banner); err != nil || banner.Pen != pen || banner.State != stateGrace || banner.RenewURL != "https://get.example.com" {
		t.Fatalf("invalid grace banner: %s (%v)", bannerBytes, err)
	}

	// 2. Day 31 puts pen to sleep, removes grace banner, frees capacity slot.
	sleepAt := paidUntil.Add(31 * 24 * time.Hour)
	trs, err = b.sweepLifecycles(context.Background(), sleepAt, false)
	if err != nil || len(trs) != 1 || trs[0].To != stateSleeping {
		t.Fatalf("sleep sweep = (%+v, %v)", trs, err)
	}
	if _, err := os.Stat(b.registrarBillingPath(pen)); !os.IsNotExist(err) {
		t.Fatal("billing-status.json should be removed when sleeping")
	}
	if capNow, ok := b.readCapacityLocal(); !ok || capNow.Pens != 0 {
		t.Fatalf("sleeping pen must not use a host slot: cap=%+v ok=%v", capNow, ok)
	}

	// 3. B1 & B9: Renewal is idempotent on eventID, persists both PendingWake and
	// broker-verified PendingOwner (from RenewNonces), and retries both on sweeps
	// after transient failures.
	_ = os.WriteFile(failWakeFlag, []byte("1"), 0o600)
	_ = os.WriteFile(failPromoteFlag, []byte("1"), 0o600)
	wakeAt := sleepAt.Add(60 * 24 * time.Hour)
	// Seed a broker-verified nonce for active admin "alice" before renewal webhook arrives.
	sleepLoaded, _ := loadPenLifecycle(b.lifecyclePath(pen))
	sleepLoaded.RenewNonces = map[string]renewNonceRecord{
		"aabbccddeeff0011": {Handle: "alice", Exp: wakeAt.Add(15 * time.Minute).Unix(), RetainExp: wakeAt.Add(24 * time.Hour).Unix()},
	}
	_ = savePenLifecycle(b.lifecyclePath(pen), sleepLoaded)

	rec1, dup1, wasSleeping, err := b.recordRenewal(pen, "cs_test_renew_1", "sub_new", "cus_new", "aabbccddeeff0011", wakeAt)
	if err != nil || dup1 || !wasSleeping || !rec1.PendingWake || rec1.PendingOwner != "alice" {
		t.Fatalf("recordRenewal 1 = (%+v, dup=%v, sleeping=%v, err=%v)", rec1, dup1, wasSleeping, err)
	}
	// Duplicate webhook retry with same event ID must NOT extend PaidUntil again.
	rec2, dup2, _, err := b.recordRenewal(pen, "cs_test_renew_1", "sub_new", "cus_new", "aabbccddeeff0011", wakeAt.Add(10*time.Minute))
	if err != nil || !dup2 || rec2.PaidUntil != rec1.PaidUntil {
		t.Fatalf("duplicate renewal must be idempotent: rec2=%+v dup2=%v err=%v", rec2, dup2, err)
	}
	// Post-webhook wake fails while host is full -> PendingWake & PendingOwner stay persisted.
	if err := b.finishRenewalWork(context.Background(), pen, true); err == nil {
		t.Fatal("expected wake to fail while fail-wake flag exists")
	}
	// Once capacity frees up, sweep wakes pen, attempts promotion (fails transiently -> PendingOwner kept).
	_ = os.Remove(failWakeFlag)
	retryTrs, err := b.sweepLifecycles(context.Background(), wakeAt.Add(time.Hour), false)
	if err != nil || len(retryTrs) < 1 || !retryTrs[0].Woken {
		t.Fatalf("sweep wake retry = (%+v, %v)", retryTrs, err)
	}
	midState, err := loadPenLifecycle(b.lifecyclePath(pen))
	if err != nil || midState.PendingWake || midState.PendingOwner != "alice" {
		t.Fatalf("after wake with failed promote, PendingWake should clear and PendingOwner stay 'alice': %+v (%v)", midState, err)
	}
	// Next sweep after pen finishes starting succeeds and clears PendingOwner.
	_ = os.Remove(failPromoteFlag)
	if _, err := b.sweepLifecycles(context.Background(), wakeAt.Add(2*time.Hour), false); err != nil {
		t.Fatalf("sweep promote retry failed: %v", err)
	}
	finalState, err := loadPenLifecycle(b.lifecyclePath(pen))
	if err != nil || finalState.PendingOwner != "" {
		t.Fatalf("PendingOwner should be cleared after successful promotion retry: %+v (%v)", finalState, err)
	}
	// 4. D-35: applyPendingOwner refuses to promote non-admin ("bob", "mallory") permanently (done=true).
	if done, err := b.applyPendingOwner(context.Background(), pen, "bob"); !done || err != nil {
		t.Fatalf("non-admin bob should be permanently declined: done=%v err=%v", done, err)
	}
	if done, err := b.applyPendingOwner(context.Background(), pen, "mallory"); !done || err != nil {
		t.Fatalf("unknown mallory should be permanently declined: done=%v err=%v", done, err)
	}
	calls, _ := os.ReadFile(logFile)
	callStr := string(calls)
	if !strings.Contains(callStr, "wake lab") || !strings.Contains(callStr, "pen lab member role alice owner") {
		t.Fatalf("expected wake and verified admin promotion in log:\n%s", callStr)
	}
	if strings.Contains(callStr, "role bob owner") || strings.Contains(callStr, "role mallory owner") {
		t.Fatalf("non-admin must never be promoted:\n%s", callStr)
	}
}

func TestStripeRenewalWebhookChecksAndWebRenewFlow(t *testing.T) {
	b, home := newTestBroker(t, "")
	b.webhookSecret = testWebhookSecret
	b.minPersonalCents = 5000
	b.minWorkCents = 12000
	b.expectedCurrency = "usd"
	b.publicURL = "https://get.example.com"
	h := b.handler()

	// Seed a Work pen in grace with its per-pen 0600 renew.key and an expired nonce.
	regDir := filepath.Join(home, "pens", "acme", "data", "registrar")
	_ = os.MkdirAll(regDir, 0o700)
	acmeKey := make([]byte, 32)
	for i := range acmeKey {
		acmeKey[i] = byte(0xa0 + i)
	}
	if err := os.WriteFile(b.renewKeyPath("acme"), []byte(hex.EncodeToString(acmeKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = byte(0x10 + i)
	}
	t0 := time.Now().UTC().Add(-10 * 24 * time.Hour)
	if err := savePenLifecycle(b.lifecyclePath("acme"), &penLifecycle{
		Plan:           planWork,
		State:          stateGrace,
		PaidUntil:      t0.Unix(),
		GraceUntil:     t0.Add(30 * 24 * time.Hour).Unix(),
		SubscriptionID: "sub_work_1",
		RenewNonces: map[string]renewNonceRecord{
			"0011223344556677": {Handle: "alice", Exp: time.Now().Add(-2 * time.Hour).Unix(), RetainExp: time.Now().Add(-time.Hour).Unix()},
		},
	}); err != nil {
		t.Fatal(err)
	}
	roles := map[string][2]string{
		"alice": {"admin", "active"},
		"bob":   {"member", "active"},
	}
	b.memberRoleFn = func(_ context.Context, _ string, handle string) (string, string, bool) {
		r, ok := roles[handle]
		return r[0], r[1], ok
	}

	// D-35: POST /api/renew accepts ONLY a valid, short-lived, single-use signed
	// in-pen token (no unauthenticated {"pen":"acme"}).
	bsrv := httptest.NewServer(h)
	defer bsrv.Close()
	wb := newWeb(bsrv.URL, testToken, "gate.example.com")
	var capturedParams *stripe.CheckoutSessionCreateParams
	wb.stripe = &stripeCheckout{
		price:          "price_personal_50",
		workPrice:      "price_work_120",
		publicURL:      "https://get.example.com",
		allowedOrigins: map[string]string{"get.example.com": "https://get.example.com"},
		createSessionFn: func(_ context.Context, p *stripe.CheckoutSessionCreateParams) (string, error) {
			capturedParams = p
			return "https://checkout.stripe.com/c/pay/cs_test_renew", nil
		},
	}
	wh := wb.handler()
	postRenew := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "https://get.example.com/api/renew", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://get.example.com")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		wh.ServeHTTP(rec, req)
		return rec
	}

	// Unauthenticated {"pen":"acme"} is rejected (400 unknown field).
	if rec := postRenew(`{"pen":"acme"}`); rec.Code != 400 {
		t.Fatalf("unauthenticated pen body = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	now := time.Now().UTC()
	// Wrong key -> 403.
	badKeyTok := signTestRenewToken(otherKey, "acme", "alice", "admin", now.Add(10*time.Minute).Unix(), "aabbccddeeff00112233445566778899")
	if rec := postRenew(fmt.Sprintf(`{"token":%q}`, badKeyTok)); rec.Code != 403 {
		t.Fatalf("wrong-key token = %d, want 403", rec.Code)
	}
	// Expired token -> 403.
	expTok := signTestRenewToken(acmeKey, "acme", "alice", "admin", now.Add(-time.Minute).Unix(), "aabbccddeeff00112233445566778800")
	if rec := postRenew(fmt.Sprintf(`{"token":%q}`, expTok)); rec.Code != 403 {
		t.Fatalf("expired token = %d, want 403", rec.Code)
	}
	// Non-admin member ("bob") -> 403 even with valid HMAC.
	bobTok := signTestRenewToken(acmeKey, "acme", "bob", "admin", now.Add(10*time.Minute).Unix(), "aabbccddeeff00112233445566778801")
	if rec := postRenew(fmt.Sprintf(`{"token":%q}`, bobTok)); rec.Code != 403 {
		t.Fatalf("non-admin member token = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}

	// Valid active admin token succeeds, binds Work price + broker-recorded renew_nonce,
	// prunes expired nonce, and refuses replay of the same nonce.
	validNonce := "11223344556677889900aabbccddeeff"
	validTok := signTestRenewToken(acmeKey, "acme", "alice", "admin", now.Add(10*time.Minute).Unix(), validNonce)
	rec := postRenew(fmt.Sprintf(`{"token":%q}`, validTok))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "https://checkout.stripe.com/c/pay/cs_test_renew") {
		t.Fatalf("POST /api/renew = %d %s", rec.Code, rec.Body.String())
	}
	if capturedParams == nil || *capturedParams.LineItems[0].Price != "price_work_120" || capturedParams.Metadata["action"] != "renew" || capturedParams.Metadata["pen"] != "acme" || capturedParams.Metadata["renew_nonce"] != validNonce {
		t.Fatalf("unexpected stripe renew params: %+v", capturedParams)
	}
	// Replay of the exact same single-use token is rejected (403).
	if replay := postRenew(fmt.Sprintf(`{"token":%q}`, validTok)); replay.Code != 403 {
		t.Fatalf("replayed renew token = %d, want 403 (%s)", replay.Code, replay.Body.String())
	}
	// Expired nonce was pruned and fresh nonce recorded with broker-verified handle.
	savedRec, err := loadPenLifecycle(b.lifecyclePath("acme"))
	if err != nil {
		t.Fatal(err)
	}
	if _, stillOld := savedRec.RenewNonces["0011223344556677"]; stillOld {
		t.Fatal("expired renew nonce should have been pruned")
	}
	if nr, hasNew := savedRec.RenewNonces[validNonce]; !hasNew || nr.Handle != "alice" {
		t.Fatalf("used renew nonce must bind handle 'alice' in lifecycle.json: %+v", savedRec.RenewNonces)
	}

	// B2: Renewal checkout with wrong amount (Personal $50 for Work pen) or 100% coupon ($0) is rejected.
	makeRenewEv := func(id, mode, currency string, amountTotal, amountSubtotal int64, pen, nonce string) []byte {
		meta := map[string]string{"hogman": "pen", "action": "renew", "pen": pen, "plan": "personal", "payer_handle": "mallory"}
		if nonce != "" {
			meta["renew_nonce"] = nonce
		}
		obj := map[string]any{
			"id": id, "object": "checkout.session", "mode": mode, "payment_status": "paid",
			"currency": currency, "amount_total": amountTotal, "amount_subtotal": amountSubtotal,
			"customer": "cus_1", "subscription": "sub_work_2",
			"metadata": meta,
		}
		ev := map[string]any{"id": "evt_" + id, "object": "event", "type": "checkout.session.completed", "api_version": "2099-01-01", "data": map[string]any{"object": obj}}
		raw, _ := json.Marshal(ev)
		return raw
	}
	// Underpaid ($50 instead of $120 Work) -> 500
	evLow := makeRenewEv("cs_test_renewlow000001", "subscription", "usd", 5000, 12000, "acme", validNonce)
	if code, _ := sendEvent(t, h, evLow, signed(evLow, testWebhookSecret, time.Now())); code != 500 {
		t.Fatalf("underpaid Work renewal must be rejected (got %d, want 500)", code)
	}
	// Wrong currency -> 500
	evCur := makeRenewEv("cs_test_renewcur000001", "subscription", "eur", 12000, 12000, "acme", validNonce)
	if code, _ := sendEvent(t, h, evCur, signed(evCur, testWebhookSecret, time.Now())); code != 500 {
		t.Fatalf("wrong currency renewal must be rejected (got %d, want 500)", code)
	}
	// Non-subscription mode -> 200 ignored (must not renew)
	evMode := makeRenewEv("cs_test_renewmode00001", "payment", "usd", 12000, 12000, "acme", validNonce)
	if code, out := sendEvent(t, h, evMode, signed(evMode, testWebhookSecret, time.Now())); code != 200 || out["ok"] != "ignored" {
		t.Fatalf("non-subscription mode must be ignored: %d %v", code, out)
	}
	// SF-5: Pre-I-3 pen without lifecycle.json returns 200 ignored (no retry storm).
	evMissing := makeRenewEv("cs_test_renewmiss00001", "subscription", "usd", 12000, 12000, "oldpen", validNonce)
	if code, out := sendEvent(t, h, evMissing, signed(evMissing, testWebhookSecret, time.Now())); code != 200 || out["ok"] != "ignored" {
		t.Fatalf("pen without lifecycle.json must return 200 ignored: %d %v", code, out)
	}
	// Forged payer_handle ("mallory") with an unrecorded nonce must NOT promote anyone.
	if recForged, _, _, err := b.recordRenewal("acme", "cs_test_forged0000001", "sub_work_2", "cus_1", "deadbeefdeadbeef", time.Now().UTC()); err != nil || recForged.PendingOwner != "" {
		t.Fatalf("unrecorded nonce must not set PendingOwner: rec=%+v err=%v", recForged, err)
	}
	// Valid $120 USD subscription renewal with broker-recorded validNonce resolves
	// PendingOwner="alice" (ignoring forged metadata payer_handle="mallory") and is idempotent on retry.
	evOK := makeRenewEv("cs_test_renewok0000001", "subscription", "usd", 12000, 12000, "acme", validNonce)
	if code, out := sendEvent(t, h, evOK, signed(evOK, testWebhookSecret, time.Now())); code != 200 || out["ok"] != "renewed" {
		t.Fatalf("valid renewal failed: %d %v", code, out)
	}
	recAfter, err := loadPenLifecycle(b.lifecyclePath("acme"))
	if err != nil || recAfter.State != stateActive {
		t.Fatalf("acme should be active after renewal: %+v (%v)", recAfter, err)
	}
	if code, _ := sendEvent(t, h, evOK, signed(evOK, testWebhookSecret, time.Now())); code != 200 {
		t.Fatalf("duplicate renewal webhook = %d", code)
	}
	recRetry, _ := loadPenLifecycle(b.lifecyclePath("acme"))
	if recRetry.PaidUntil != recAfter.PaidUntil {
		t.Fatalf("retry double-credited paid_until: %d vs %d", recRetry.PaidUntil, recAfter.PaidUntil)
	}

	// Alerts API: add, list, remove.
	if code, out := call(h, "POST", "/lifecycle/alerts", `{"pen":"acme","action":"add","email":"ops@example.com"}`, auth); code != 200 {
		t.Fatalf("alerts add = %d %v", code, out)
	}
	if code, out := call(h, "POST", "/lifecycle/alerts", `{"pen":"acme","action":"remove","email":"ops@example.com"}`, auth); code != 200 {
		t.Fatalf("alerts remove = %d %v", code, out)
	}
}

func TestHogmanHostPurgeSleepWakeGuardrails(t *testing.T) {
	hostScript, err := filepath.Abs("../hogman-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hostScript); err != nil {
		t.Skip("deploy/hogman-host not found")
	}

	home := t.TempDir()
	binDir := filepath.Join(home, "bin")
	_ = os.MkdirAll(binDir, 0o700)
	// Stub docker so reload_front and network rm succeed in unit tests without a daemon,
	// and can simulate a running container when fake-running exists.
	dockerStub := "#!/bin/sh\nif [ \"$1\" = ps ] && [ -f \"" + home + "/fake-running\" ]; then echo container123; fi\nexit 0\n"
	_ = os.WriteFile(filepath.Join(binDir, "docker"), []byte(dockerStub), 0o755)
	_ = os.WriteFile(filepath.Join(home, "host.env"), []byte("MAX_PENS=8\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(home, "front"), 0o700)
	penDir := filepath.Join(home, "pens", "lab")
	_ = os.MkdirAll(filepath.Join(penDir, "data", "registrar"), 0o700)
	_ = os.WriteFile(filepath.Join(penDir, ".env"), []byte("PUBLIC_HOST=lab.gate.example.com\n"), 0o600)
	// Stub ./hogman inside the pen directory.
	stubHogman := filepath.Join(penDir, "hogman")
	_ = os.WriteFile(stubHogman, []byte("#!/bin/sh\n[ \"$1\" = down ] && [ -f \""+home+"/fail-down\" ] && exit 1\nexit 0\n"), 0o755)

	runHost := func(stdin string, args ...string) (string, error) {
		cmd := exec.Command("bash", append([]string{hostScript}, args...)...)
		cmd.Env = append(os.Environ(), "HOGMAN_HOME="+home, "PATH="+binDir+":"+os.Getenv("PATH"))
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// B5: manual purge without --force refuses.
	if out, err := runHost("lab\n", "purge", "lab"); err == nil || !strings.Contains(out, "--force") {
		t.Fatalf("purge without --force must fail: err=%v out=%s", err, out)
	}
	// B5: --yes is explicitly refused.
	if out, err := runHost("lab\n", "purge", "--force", "--yes", "lab"); err == nil || !strings.Contains(out, "--yes") {
		t.Fatalf("purge --yes must fail: err=%v out=%s", err, out)
	}
	// B5: non-TTY manual purge with --force refuses even when pen name is piped to stdin.
	if out, err := runHost("lab\n", "purge", "--force", "lab"); err == nil || !strings.Contains(out, "interactive terminal") {
		t.Fatalf("non-TTY purge --force must fail: err=%v out=%s", err, out)
	}
	// B5 & B7: purge --due refuses when .sleeping marker is absent.
	if out, err := runHost("", "purge", "--due", "lab"); err == nil || !strings.Contains(out, ".sleeping") {
		t.Fatalf("purge --due without .sleeping must fail: err=%v out=%s", err, out)
	}
	_ = os.WriteFile(filepath.Join(penDir, ".sleeping"), nil, 0o600)
	// B7: purge --due refuses when running containers exist even if .sleeping is set.
	_ = os.WriteFile(filepath.Join(home, "fake-running"), []byte("1"), 0o600)
	if out, err := runHost("", "purge", "--due", "lab"); err == nil || !strings.Contains(out, "running containers") {
		t.Fatalf("purge --due with running containers must fail: err=%v out=%s", err, out)
	}
	_ = os.Remove(filepath.Join(home, "fake-running"))
	// B5: purge --due refuses when lifecycle.json is missing.
	if out, err := runHost("", "purge", "--due", "lab"); err == nil || !strings.Contains(out, "no lifecycle.json") {
		t.Fatalf("purge --due without lifecycle.json must fail: err=%v out=%s", err, out)
	}
	// B5: purge --due refuses on an active pen.
	_ = savePenLifecycle(filepath.Join(penDir, "lifecycle.json"), &penLifecycle{
		Plan: planPersonal, State: stateActive, PaidUntil: time.Now().Add(30 * 24 * time.Hour).Unix(),
	})
	if out, err := runHost("", "purge", "--due", "lab"); err == nil || !strings.Contains(out, "not 'sleeping'") {
		t.Fatalf("purge --due on active pen must fail: err=%v out=%s", err, out)
	}
	// B5: purge --due refuses on a sleeping pen whose delete_after is in the future.
	_ = savePenLifecycle(filepath.Join(penDir, "lifecycle.json"), &penLifecycle{
		Plan: planPersonal, State: stateSleeping, SleepSince: time.Now().Unix(), DeleteAfter: time.Now().Add(30 * 24 * time.Hour).Unix(),
	})
	if out, err := runHost("", "purge", "--due", "lab"); err == nil || !strings.Contains(out, "not due for deletion") {
		t.Fatalf("purge --due before delete_after must fail: err=%v out=%s", err, out)
	}
	_ = os.Remove(filepath.Join(penDir, ".sleeping"))

	// SF-3: sleep fails and does NOT write .sleeping when ./hogman down fails.
	_ = os.WriteFile(filepath.Join(home, "fail-down"), []byte("1"), 0o600)
	if out, err := runHost("", "sleep", "lab"); err == nil {
		t.Fatalf("sleep must fail when ./hogman down fails: out=%s", out)
	}
	if _, err := os.Stat(filepath.Join(penDir, ".sleeping")); !os.IsNotExist(err) {
		t.Fatal(".sleeping must not be created when ./hogman down fails")
	}
	_ = os.Remove(filepath.Join(home, "fail-down"))

	// B7: sleep -> wake by hand resets lifecycle.json to active (clears sleep_since & delete_after)
	// so a manually woken pen can never be purged as expired sleep later, and sleep writes the
	// static sleeping front-door notice into front/Caddyfile.
	if out, err := runHost("", "sleep", "lab"); err != nil {
		t.Fatalf("sleep lab failed: err=%v out=%s", err, out)
	}
	if caddyRaw, err := os.ReadFile(filepath.Join(home, "front", "Caddyfile")); err != nil || !strings.Contains(string(caddyRaw), "import sleeping") {
		t.Fatalf("sleep should write static sleeping route to front/Caddyfile: err=%v content=%s", err, caddyRaw)
	}
	if out, err := runHost("", "wake", "lab"); err != nil {
		t.Fatalf("wake lab failed: err=%v out=%s", err, out)
	}
	wokenRec, err := loadPenLifecycle(filepath.Join(penDir, "lifecycle.json"))
	if err != nil || wokenRec.State != stateActive || wokenRec.SleepSince != 0 || wokenRec.DeleteAfter != 0 {
		t.Fatalf("wake must reset lifecycle.json to active: %+v (%v)", wokenRec, err)
	}

	// SF-2: wake refuses a .removed pen.
	_ = os.WriteFile(filepath.Join(penDir, ".removed"), nil, 0o600)
	if out, err := runHost("", "wake", "lab"); err == nil || !strings.Contains(out, "was removed") {
		t.Fatalf("wake must refuse .removed pen: err=%v out=%s", err, out)
	}
	_ = os.Remove(filepath.Join(penDir, ".removed"))

	// B5: purge --due succeeds once .sleeping exists and delete_after is in the past.
	_ = os.WriteFile(filepath.Join(penDir, ".sleeping"), nil, 0o600)
	_ = savePenLifecycle(filepath.Join(penDir, "lifecycle.json"), &penLifecycle{
		Plan: planPersonal, State: stateSleeping, SleepSince: time.Now().Add(-400 * 24 * time.Hour).Unix(), DeleteAfter: time.Now().Add(-time.Hour).Unix(),
	})
	if out, err := runHost("", "purge", "--due", "lab"); err != nil {
		t.Fatalf("purge --due past delete_after failed: err=%v out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(penDir, "data")); !os.IsNotExist(err) {
		t.Fatal("data/ should be removed after purge --due")
	}
	if _, err := os.Stat(filepath.Join(penDir, ".retired")); err != nil {
		t.Fatal(".retired marker must exist after purge --due")
	}
}
