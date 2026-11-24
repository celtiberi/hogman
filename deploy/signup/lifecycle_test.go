package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

	// At paid_until: transitions active -> grace (30 days).
	next, changed = evaluateLifecycle(rec, paidUntil)
	if !changed || next.State != stateGrace {
		t.Fatalf("at paid_until: changed=%v state=%s", changed, next.State)
	}
	wantGrace := paidUntil.Add(30 * 24 * time.Hour).Unix()
	if next.GraceUntil != wantGrace {
		t.Fatalf("grace_until = %d, want %d", next.GraceUntil, wantGrace)
	}

	// Day 29 of grace: stays in grace.
	stayGrace, changed := evaluateLifecycle(next, paidUntil.Add(29*24*time.Hour))
	if changed || stayGrace.State != stateGrace {
		t.Fatalf("day 29 grace: changed=%v state=%s", changed, stayGrace.State)
	}

	// Day 30 of grace: transitions grace -> sleeping (delete_after = +365d).
	sleepTime := paidUntil.Add(30 * 24 * time.Hour)
	asleep, changed := evaluateLifecycle(next, sleepTime)
	if !changed || asleep.State != stateSleeping {
		t.Fatalf("day 30 grace: changed=%v state=%s", changed, asleep.State)
	}
	if asleep.SleepSince != sleepTime.Unix() || asleep.DeleteAfter != sleepTime.Add(365*24*time.Hour).Unix() {
		t.Fatalf("unexpected sleep timestamps: %+v", asleep)
	}

	// Day 364 asleep: stays sleeping.
	stillAsleep, changed := evaluateLifecycle(asleep, sleepTime.Add(364*24*time.Hour))
	if changed || stillAsleep.State != stateSleeping {
		t.Fatalf("day 364 sleep: changed=%v state=%s", changed, stillAsleep.State)
	}

	// Day 365 asleep: transitions sleeping -> deleted.
	deleted, changed := evaluateLifecycle(asleep, sleepTime.Add(365*24*time.Hour))
	if !changed || deleted.State != stateDeleted {
		t.Fatalf("day 365 sleep: changed=%v state=%s", changed, deleted.State)
	}

	// Free pens stay active automatically across sweeps.
	freeRec := penLifecycle{Plan: planFree, State: stateActive}
	freeNext, changed := evaluateLifecycle(freeRec, t0.Add(5*365*24*time.Hour))
	if changed || freeNext.State != stateActive {
		t.Fatalf("free pen should stay active automatically: changed=%v state=%s", changed, freeNext.State)
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
	if wasSleeping || renewed.State != stateActive || renewed.GraceUntil != 0 {
		t.Fatalf("unexpected grace renewal: %+v wasSleeping=%v", renewed, wasSleeping)
	}
	if got, want := renewed.PaidUntil, payDay.Add(365*24*time.Hour).Unix(); got != want {
		t.Fatalf("no-backdating paid_until = %d, want %d (day of payment + 365d)", got, want)
	}

	// Opt-in backdate=true extends from old paid_until instead.
	backdated, _ := applyRenewal(graceRec, payDay, true)
	if got, want := backdated.PaidUntil, paidUntil.Add(365*24*time.Hour).Unix(); got != want {
		t.Fatalf("backdated paid_until = %d, want %d", got, want)
	}

	// Early renewal (before paid_until) always preserves remaining paid days.
	earlyDay := paidUntil.Add(-15 * 24 * time.Hour)
	activeRec := penLifecycle{Plan: planPersonal, State: stateActive, PaidUntil: paidUntil.Unix()}
	early, _ := applyRenewal(activeRec, earlyDay, false)
	if got, want := early.PaidUntil, paidUntil.Add(365*24*time.Hour).Unix(); got != want {
		t.Fatalf("early renewal paid_until = %d, want %d", got, want)
	}

	// Waking from sleep clears sleep timestamps and reports wasSleeping=true.
	sleepRec := penLifecycle{
		Plan:        planPersonal,
		State:       stateSleeping,
		PaidUntil:   paidUntil.Unix(),
		SleepSince:  paidUntil.Add(30 * 24 * time.Hour).Unix(),
		DeleteAfter: paidUntil.Add(395 * 24 * time.Hour).Unix(),
	}
	wakeDay := paidUntil.Add(90 * 24 * time.Hour)
	woke, wasSleeping := applyRenewal(sleepRec, wakeDay, false)
	if !wasSleeping || woke.State != stateActive || woke.SleepSince != 0 || woke.DeleteAfter != 0 {
		t.Fatalf("wake renewal = %+v wasSleeping=%v", woke, wasSleeping)
	}
	if woke.PaidUntil != wakeDay.Add(365*24*time.Hour).Unix() {
		t.Fatalf("wake paid_until = %d, want %d", woke.PaidUntil, wakeDay.Add(365*24*time.Hour).Unix())
	}
}

func TestBrokerLifecycleSweepBannerAlertsAndWake(t *testing.T) {
	home := t.TempDir()
	logFile := filepath.Join(home, "host-calls.log")
	fakeHost := filepath.Join(home, "fake-hogman-host")
	script := `#!/bin/sh
echo "$@" >> "` + logFile + `"
cmd="$1"
pen="$2"
case "$cmd" in
  sleep) touch "` + home + `/pens/$pen/.sleeping" ;;
  wake) rm -f "` + home + `/pens/$pen/.sleeping" "` + home + `/pens/$pen/.removed" ;;
  purge) rm -rf "` + home + `/pens/$pen/data"; touch "` + home + `/pens/$pen/.removed" "` + home + `/pens/$pen/.retired" ;;
esac
exit 0
`
	if err := os.WriteFile(fakeHost, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(home, "host.env"), []byte("MAX_PENS=8\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(home, "signup"), 0o700)

	pen := "lab"
	portalDir := filepath.Join(home, "pens", pen, "data", "portal")
	if err := os.MkdirAll(portalDir, 0o700); err != nil {
		t.Fatal(err)
	}

	var sentAlerts []string
	b := &broker{
		home:  home,
		tool:  fakeHost,
		token: "test-token",
		alertSendFn: func(_ context.Context, to []string, subj, _ string) error {
			sentAlerts = append(sentAlerts, strings.Join(to, ",")+":"+subj)
			return nil
		},
	}
	if b.backdateRenewal {
		t.Fatal("backdateRenewal must default to false per D-35")
	}

	t0 := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	paidUntil := t0.Add(365 * 24 * time.Hour)
	initRec := &penLifecycle{
		Plan:        planPersonal,
		State:       stateActive,
		PaidUntil:   paidUntil.Unix(),
		AlertEmails: []string{"owner@example.com"},
		RenewURL:    "https://get.example.com/renew?pen=lab",
	}
	if err := savePenLifecycle(b.lifecyclePath(pen), initRec); err != nil {
		t.Fatal(err)
	}

	// 1. Entering grace writes portal billing-status.json and sends grace-start alert once.
	trs, err := b.sweepLifecycles(context.Background(), paidUntil.Add(time.Hour), false)
	if err != nil || len(trs) != 1 || trs[0].To != stateGrace || trs[0].AlertSent != "grace-start" {
		t.Fatalf("grace sweep = (%+v, %v)", trs, err)
	}
	bannerBytes, err := os.ReadFile(b.portalBillingPath(pen))
	if err != nil {
		t.Fatalf("expected portal billing-status.json in grace: %v", err)
	}
	var banner portalBillingStatus
	if err := json.Unmarshal(bannerBytes, &banner); err != nil || banner.State != stateGrace {
		t.Fatalf("invalid grace banner: %s (%v)", bannerBytes, err)
	}
	// Repeating sweep on day 2 does not duplicate the grace-start alert.
	if _, err := b.sweepLifecycles(context.Background(), paidUntil.Add(24*time.Hour), false); err != nil {
		t.Fatal(err)
	}
	if len(sentAlerts) != 1 {
		t.Fatalf("expected 1 deduplicated alert, got %d: %v", len(sentAlerts), sentAlerts)
	}

	// 2. Day 30 puts pen to sleep, removes grace banner, frees capacity slot.
	sleepAt := paidUntil.Add(31 * 24 * time.Hour)
	trs, err = b.sweepLifecycles(context.Background(), sleepAt, false)
	if err != nil || len(trs) != 1 || trs[0].To != stateSleeping {
		t.Fatalf("sleep sweep = (%+v, %v)", trs, err)
	}
	if _, err := os.Stat(b.portalBillingPath(pen)); !os.IsNotExist(err) {
		t.Fatal("billing-status.json should be removed when sleeping")
	}
	capNow, ok := b.readCapacityLocal()
	if !ok || capNow.Pens != 0 {
		t.Fatalf("sleeping pen must not use a host slot: cap=%+v ok=%v", capNow, ok)
	}

	// 3. Admin pays while sleeping -> wakes pen, promotes admin to owner, starts fresh year (no backdating).
	wakeAt := sleepAt.Add(60 * 24 * time.Hour)
	renewed, err := b.renewPen(context.Background(), pen, "alice", "sub_new", "cus_new", wakeAt)
	if err != nil {
		t.Fatalf("renewPen failed: %v", err)
	}
	if renewed.State != stateActive || renewed.PaidUntil != wakeAt.Add(365*24*time.Hour).Unix() {
		t.Fatalf("renewed = %+v", renewed)
	}
	calls, _ := os.ReadFile(logFile)
	callStr := string(calls)
	if !strings.Contains(callStr, "sleep lab") || !strings.Contains(callStr, "wake lab") || !strings.Contains(callStr, "pen lab member role alice owner") {
		t.Fatalf("unexpected host calls:\n%s", callStr)
	}

	// 4. Dry-run HTTP endpoint returns 200 JSON without mutating state.
	req := httptest.NewRequest("POST", "/lifecycle/sweep?dry_run=1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	recHTTP := httptest.NewRecorder()
	b.handler().ServeHTTP(recHTTP, req)
	if recHTTP.Code != http.StatusOK {
		t.Fatalf("POST /lifecycle/sweep?dry_run=1 = %d %s", recHTTP.Code, recHTTP.Body.String())
	}
}
