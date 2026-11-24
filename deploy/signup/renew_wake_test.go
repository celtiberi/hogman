package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRenewOnlyWakeCapsCapacityPersistenceAndTimingI7(t *testing.T) {
	var alertMu sync.Mutex
	var alerts []string
	ntfySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		alertMu.Lock()
		alerts = append(alerts, string(body))
		alertMu.Unlock()
		w.WriteHeader(200)
	}))
	defer ntfySrv.Close()
	hasAlert := func(substr string) bool {
		time.Sleep(40 * time.Millisecond)
		alertMu.Lock()
		defer alertMu.Unlock()
		for _, a := range alerts {
			if strings.Contains(a, substr) {
				return true
			}
		}
		return false
	}

	// Fake hogman-host tool that slows down wake --renew-only slightly (to prove
	// POST /api/wake returns immediately without waiting) and logs invocations.
	b, home := newTestBroker(t, "")
	b.tool = filepath.Join(t.TempDir(), "hogman-host")
	if err := os.WriteFile(b.tool, []byte(`#!/bin/sh
echo "$*" >> "$HOGMAN_HOME/tool.log"
if [ "$1" = "wake" ] && [ "$2" = "--renew-only" ]; then
  sleep 0.2
  touch "$HOGMAN_HOME/pens/$3/.renew-wake"
  exit 0
fi
if [ "$1" = "sleep" ]; then
  rm -f "$HOGMAN_HOME/pens/$2/.renew-wake"
  touch "$HOGMAN_HOME/pens/$2/.sleeping"
  exit 0
fi
exit 0
`), 0o755); err != nil {
		t.Fatal(err)
	}
	b.ntfy = ntfySrv.URL
	b.healthNotify = newLimiterWithCap(20, time.Minute, 32)
	b.publicURL = "https://get.example.com"
	b.wakeHealthInterval = 5 * time.Millisecond

	now := time.Date(2028, 3, 1, 12, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	b.nowFn = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	setNow := func(ts time.Time) {
		nowMu.Lock()
		now = ts
		nowMu.Unlock()
	}

	// Host with MAX_PENS=4 and reserve=2.
	_ = os.WriteFile(filepath.Join(home, "host.env"), []byte("MAX_PENS=4\nRENEW_WAKE_RESERVE=2\n"), 0o600)

	origSleep := now.Add(-60 * 24 * time.Hour).Unix()
	origDelete := now.Add(305 * 24 * time.Hour).Unix()
	makeSleepingPen := func(name string, history []int64) {
		pdir := filepath.Join(home, "pens", name)
		_ = os.MkdirAll(filepath.Join(pdir, "data", "registrar"), 0o700)
		_ = os.WriteFile(filepath.Join(pdir, ".sleeping"), nil, 0o600)
		if err := savePenLifecycle(b.lifecyclePath(name), &penLifecycle{
			Plan:        planPersonal,
			State:       stateSleeping,
			PaidUntil:   origSleep - 30*86400,
			SleepSince:  origSleep,
			DeleteAfter: origDelete,
			WakeHistory: history,
			RenewURL:    "https://get.example.com",
		}); err != nil {
			t.Fatal(err)
		}
	}

	makeSleepingPen("alpha", nil)
	makeSleepingPen("beta", nil)
	makeSleepingPen("gamma", nil)

	// 1. Cert-readiness window: health fails twice, then succeeds 3 minutes later ->
	//    WakeUntil becomes readyAt + 10m (clamped to <= WakeCeiling = startedAt + 20m).
	var healthCalls atomic.Int32
	readyDone := make(chan struct{})
	b.wakeHealthFn = func(_ context.Context, pen string) error {
		if pen == "alpha" {
			n := healthCalls.Add(1)
			if n < 3 {
				return errors.New("cert pending")
			}
			setNow(time.Date(2028, 3, 1, 12, 3, 0, 0, time.UTC))
			defer func() {
				select {
				case <-readyDone:
				default:
					close(readyDone)
				}
			}()
		}
		return nil
	}

	// Wire signup-web and verify POST /api/wake returns 202 IMMEDIATELY (<150ms,
	// even though fake hogman-host wake sleeps 200ms) with identical response
	// across sleeping pen, active/missing pen, and capped pen (no timing/state oracle).
	bsrv := httptest.NewServer(b.handler())
	defer bsrv.Close()
	wb := newWeb(bsrv.URL, testToken, "gate.example.com")
	wb.wakes = newLimiter(50, time.Hour)
	wh := wb.handler()

	postWake := func(pen string) (int, map[string]any, time.Duration) {
		t0 := time.Now()
		req := httptest.NewRequest("POST", "/api/wake", strings.NewReader(`{"pen":"`+pen+`"}`))
		req.Host = "get.example.com"
		req.Header.Set("Origin", "https://get.example.com")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		wh.ServeHTTP(rr, req)
		elapsed := time.Since(t0)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out, elapsed
	}

	codeAlpha, respAlpha, durAlpha := postWake("alpha")
	codeMissing, respMissing, durMissing := postWake("nonexistent")
	if codeAlpha != 202 || codeMissing != 202 || respAlpha["message"] != respMissing["message"] {
		t.Fatalf("responses must be uniform 202: alpha=(%d,%v) missing=(%d,%v)", codeAlpha, respAlpha, codeMissing, respMissing)
	}
	if durAlpha > 150*time.Millisecond || durMissing > 150*time.Millisecond {
		t.Fatalf("POST /api/wake blocked instead of answering immediately: alpha=%v missing=%v", durAlpha, durMissing)
	}

	// Wait for background wake + cert-ready update to complete.
	select {
	case <-readyDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for cert-ready wakeHealthFn")
	}
	time.Sleep(50 * time.Millisecond)

	recAlpha, err := loadPenLifecycle(b.lifecyclePath("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if recAlpha.State != stateRenewOnly {
		t.Fatalf("alpha state = %s, want renew_only", recAlpha.State)
	}
	if recAlpha.SleepSince != origSleep || recAlpha.DeleteAfter != origDelete {
		t.Fatalf("sleep_since/delete_after mutated during renew_only: got (%d,%d) want (%d,%d)",
			recAlpha.SleepSince, recAlpha.DeleteAfter, origSleep, origDelete)
	}
	wantReady := time.Date(2028, 3, 1, 12, 3, 0, 0, time.UTC).Unix()
	wantUntil := time.Date(2028, 3, 1, 12, 13, 0, 0, time.UTC).Unix()
	wantCeil := time.Date(2028, 3, 1, 12, 20, 0, 0, time.UTC).Unix()
	if recAlpha.WakeReadyAt != wantReady || recAlpha.WakeUntil != wantUntil || recAlpha.WakeCeiling != wantCeil {
		t.Fatalf("alpha wake timestamps = (ready=%d until=%d ceil=%d), want (%d,%d,%d)",
			recAlpha.WakeReadyAt, recAlpha.WakeUntil, recAlpha.WakeCeiling, wantReady, wantUntil, wantCeil)
	}
	// billing-status.json written with state=renew_only and wake_until.
	bsRaw, err := os.ReadFile(b.registrarBillingPath("alpha"))
	if err != nil || !strings.Contains(string(bsRaw), `"state": "renew_only"`) || !strings.Contains(string(bsRaw), "12:13:00Z") {
		t.Fatalf("billing-status.json mismatch: err=%v content=%s", err, bsRaw)
	}

	// 2. Global concurrent cap = 2: beta wakes (2nd concurrent), gamma is refused (global-cap),
	//    and once global cap stays full >5m, an operator health alert fires.
	if ok, _, _, reason := b.requestRenewWake(context.Background(), "beta", b.now()); !ok || reason != "started" {
		t.Fatalf("beta 2nd concurrent wake failed: ok=%v reason=%s", ok, reason)
	}
	if ok, _, _, reason := b.requestRenewWake(context.Background(), "gamma", b.now()); ok || reason != "global-cap" {
		t.Fatalf("gamma 3rd concurrent wake should hit global-cap: ok=%v reason=%s", ok, reason)
	}
	setNow(b.now().Add(6 * time.Minute))
	if ok, _, _, reason := b.requestRenewWake(context.Background(), "gamma", b.now()); ok || reason != "global-cap" {
		t.Fatalf("gamma still global-cap after 6m: ok=%v reason=%s", ok, reason)
	}
	if !hasAlert("global cap") {
		t.Fatalf("expected operator alert when global wake cap stayed full >5m; alerts=%v", alerts)
	}

	// 3. Persisted deadline survives a FRESH broker instance (simulating broker restart!)
	//    and targeted sweepExpiredRenewWakes ONLY sleeps expired renew_only pens without
	//    touching overdue active or sleeping pens.
	makeOverdueActive := func(name string) {
		pdir := filepath.Join(home, "pens", name)
		_ = os.MkdirAll(filepath.Join(pdir, "data", "registrar"), 0o700)
		_ = savePenLifecycle(b.lifecyclePath(name), &penLifecycle{
			Plan:      planPersonal,
			State:     stateActive,
			PaidUntil: origSleep - 30*86400,
		})
	}
	makeOverdueActive("overdue-active")
	freshBroker := &broker{home: home, tool: b.tool, token: testToken}
	afterExpiry := time.Date(2028, 3, 1, 12, 14, 0, 0, time.UTC)
	trs, err := freshBroker.sweepExpiredRenewWakes(context.Background(), afterExpiry)
	if err != nil {
		t.Fatalf("freshBroker sweepExpiredRenewWakes failed: %v", err)
	}
	foundReturn := false
	for _, tr := range trs {
		if tr.Pen == "alpha" && tr.From == stateRenewOnly && tr.To == stateSleeping {
			foundReturn = true
		}
		if tr.Pen == "overdue-active" {
			t.Fatalf("sweepExpiredRenewWakes must not transition non-renew_only pens: %+v", trs)
		}
	}
	if !foundReturn {
		t.Fatalf("fresh broker did not return alpha renew_only -> sleeping: %+v", trs)
	}
	afterSleep, _ := loadPenLifecycle(b.lifecyclePath("alpha"))
	if afterSleep.State != stateSleeping || afterSleep.SleepSince != origSleep || afterSleep.DeleteAfter != origDelete || afterSleep.WakeUntil != 0 {
		t.Fatalf("alpha after returning to sleep: %+v", afterSleep)
	}
	if _, err := os.Stat(b.registrarBillingPath("alpha")); !os.IsNotExist(err) {
		t.Fatal("billing-status.json should be removed after returning to sleep")
	}
	if _, err := os.Stat(registrarRenewOnlyMarkerPath(b.registrarBillingPath("alpha"))); !os.IsNotExist(err) {
		t.Fatal(".renew-only marker should be removed after returning to sleep")
	}
	_ = os.RemoveAll(filepath.Join(home, "pens", "overdue-active"))

	// B1 & B2: Missing data/registrar dir MUST abort and roll back cleanly without
	// marking renew_only or starting containers.
	brokenDir := filepath.Join(home, "pens", "broken")
	_ = os.MkdirAll(brokenDir, 0o700)
	_ = os.WriteFile(filepath.Join(brokenDir, ".sleeping"), nil, 0o600)
	_ = savePenLifecycle(b.lifecyclePath("broken"), &penLifecycle{
		Plan: planPersonal, State: stateSleeping, SleepSince: origSleep, DeleteAfter: origDelete,
	})
	if ok, _, _, reason := b.requestRenewWake(context.Background(), "broken", b.now()); ok || reason != "banner-error" {
		t.Fatalf("missing data/registrar must fail closed with banner-error: ok=%v reason=%s", ok, reason)
	}
	brokenRec, _ := loadPenLifecycle(b.lifecyclePath("broken"))
	if brokenRec.State != stateSleeping || brokenRec.WakeUntil != 0 || len(brokenRec.WakeHistory) != 0 {
		t.Fatalf("failed banner write must not leave pen in renew_only: %+v", brokenRec)
	}

	// Should-fix: free plan pens cannot trigger renew-only wake.
	freeDir := filepath.Join(home, "pens", "freepen")
	_ = os.MkdirAll(filepath.Join(freeDir, "data", "registrar"), 0o700)
	_ = os.WriteFile(filepath.Join(freeDir, ".sleeping"), nil, 0o600)
	_ = savePenLifecycle(b.lifecyclePath("freepen"), &penLifecycle{
		Plan: planFree, State: stateSleeping, SleepSince: origSleep, DeleteAfter: origDelete,
	})
	if ok, _, _, reason := b.requestRenewWake(context.Background(), "freepen", b.now()); ok || reason != "not-paid" {
		t.Fatalf("free pen should be refused with not-paid: ok=%v reason=%s", ok, reason)
	}

	// Put beta back to sleep too so global cap is free for per-pen & host-full tests.
	_, _ = freshBroker.sweepLifecycles(context.Background(), time.Date(2028, 3, 1, 12, 30, 0, 0, time.UTC), false)

	// 4. Per-pen daily cap (3/24h) + operator alert.
	tDay := time.Date(2028, 3, 2, 12, 0, 0, 0, time.UTC)
	makeSleepingPen("daycap", []int64{
		tDay.Add(-20 * time.Hour).Unix(),
		tDay.Add(-10 * time.Hour).Unix(),
		tDay.Add(-1 * time.Hour).Unix(),
	})
	if ok, _, _, reason := b.requestRenewWake(context.Background(), "daycap", tDay); ok || reason != "daily-cap" {
		t.Fatalf("daycap 4th wake in 24h: ok=%v reason=%s, want daily-cap", ok, reason)
	}
	if !hasAlert("daily renewal-wake cap") {
		t.Fatalf("expected daily-cap health alert; alerts=%v", alerts)
	}

	// 5. Per-pen monthly cap (10/30d) + pruning >30d entries.
	var tenWakes []int64
	for i := 1; i <= 10; i++ {
		tenWakes = append(tenWakes, tDay.Add(-time.Duration(i*2)*24*time.Hour).Unix())
	}
	makeSleepingPen("monthcap", tenWakes)
	if ok, _, _, reason := b.requestRenewWake(context.Background(), "monthcap", tDay); ok || reason != "monthly-cap" {
		t.Fatalf("monthcap 11th wake in 30d: ok=%v reason=%s, want monthly-cap", ok, reason)
	}
	// If oldest entry is >30d old, pruning allows the wake!
	tenWakes[9] = tDay.Add(-31 * 24 * time.Hour).Unix()
	makeSleepingPen("monthok", tenWakes)
	if ok, _, _, reason := b.requestRenewWake(context.Background(), "monthok", tDay); !ok || reason != "started" {
		t.Fatalf("monthok with 1 pruned >30d entry should wake: ok=%v reason=%s", ok, reason)
	}
	_, _ = freshBroker.sweepLifecycles(context.Background(), tDay.Add(30*time.Minute), false)

	// 6. Host-full case: when live pens fill MAX_PENS and reserve=0, renewal wake
	//    is refused cleanly without ever evicting or blocking paying pens.
	zeroRes := 0
	b.renewWakeReserve = &zeroRes
	for _, livePen := range []string{"live1", "live2", "live3", "live4"} {
		_ = os.MkdirAll(filepath.Join(home, "pens", livePen), 0o700)
	}
	b.invalidateCapacityCache()
	makeSleepingPen("fulltest", nil)
	if ok, _, _, reason := b.requestRenewWake(context.Background(), "fulltest", tDay); ok || reason != "host-full" {
		t.Fatalf("host-full should refuse wake: ok=%v reason=%s", ok, reason)
	}

	// 7. Payment during renew_only promotes directly to active, clears billing-status.json and wake fields.
	twoRes := 2
	b.renewWakeReserve = &twoRes
	b.invalidateCapacityCache()
	makeSleepingPen("payme", nil)
	if ok, _, _, reason := b.requestRenewWake(context.Background(), "payme", tDay); !ok || reason != "started" {
		t.Fatalf("payme wake failed: ok=%v reason=%s", ok, reason)
	}
	paidRec, already, wasSleeping, err := b.recordRenewal("payme", "cs_payme_1", "sub_payme_1", "cus_1", "", tDay.Add(2*time.Minute))
	if err != nil || already || !wasSleeping {
		t.Fatalf("recordRenewal during renew_only: rec=%+v already=%v wasSleeping=%v err=%v", paidRec, already, wasSleeping, err)
	}
	if paidRec.State != stateActive || paidRec.WakeUntil != 0 || paidRec.SleepSince != 0 || paidRec.DeleteAfter != 0 {
		t.Fatalf("paid pen should be active with wake/sleep fields cleared: %+v", paidRec)
	}
	if _, err := os.Stat(b.registrarBillingPath("payme")); !os.IsNotExist(err) {
		t.Fatal("billing-status.json must be removed on payment during renew_only")
	}

	// 8. Per-IP rate limit (5/hr) on POST /api/wake.
	wbLimited := newWeb(bsrv.URL, testToken, "gate.example.com")
	hLim := wbLimited.handler()
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/api/wake", strings.NewReader(`{"pen":"alpha"}`))
		req.RemoteAddr = "198.51.100.42:12345"
		req.Host = "get.example.com"
		req.Header.Set("Origin", "https://get.example.com")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		hLim.ServeHTTP(rr, req)
		if rr.Code != 202 {
			t.Fatalf("wake #%d = %d, want 202", i+1, rr.Code)
		}
	}
	req6 := httptest.NewRequest("POST", "/api/wake", strings.NewReader(`{"pen":"alpha"}`))
	req6.RemoteAddr = "198.51.100.42:12345"
	req6.Host = "get.example.com"
	req6.Header.Set("Origin", "https://get.example.com")
	req6.Header.Set("Sec-Fetch-Site", "same-origin")
	req6.Header.Set("Content-Type", "application/json")
	rr6 := httptest.NewRecorder()
	hLim.ServeHTTP(rr6, req6)
	if rr6.Code != 429 {
		t.Fatalf("6th wake from same IP = %d, want 429", rr6.Code)
	}
}

func TestHogmanHostRenewOnlyWakeListAndPurgeRefusalI7(t *testing.T) {
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
	_ = os.WriteFile(filepath.Join(binDir, "docker"), []byte("#!/bin/sh\nif [ \"$1\" = ps ] && [ \"$2\" = --format ]; then echo pen-lab-registrar-1; fi\nexit 0\n"), 0o755)
	_ = os.WriteFile(filepath.Join(home, "host.env"), []byte("MAX_PENS=4\nRENEW_WAKE_RESERVE=2\nSIGNUP_HOST=get.example.com\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(home, "front"), 0o700)
	penDir := filepath.Join(home, "pens", "lab")
	_ = os.MkdirAll(filepath.Join(penDir, "data", "registrar"), 0o700)
	_ = os.WriteFile(filepath.Join(penDir, ".env"), []byte("PUBLIC_HOST=lab.gate.example.com\nSTUN_PORT=3478\n"), 0o600)
	_ = os.WriteFile(filepath.Join(penDir, "hogman"), []byte("#!/bin/sh\necho \"$*\" >> \""+home+"/pen-calls.log\"\nexit 0\n"), 0o755)

	runHost := func(args ...string) (string, error) {
		cmd := exec.Command("bash", append([]string{hostScript}, args...)...)
		cmd.Env = append(os.Environ(), "HOGMAN_HOME="+home, "PATH="+binDir+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Put pen to sleep with an older sleep_since/delete_after.
	origSleep := time.Now().Add(-400 * 24 * time.Hour).Unix()
	origDelete := time.Now().Add(-time.Hour).Unix()
	_ = os.WriteFile(filepath.Join(penDir, ".sleeping"), nil, 0o600)
	_ = savePenLifecycle(filepath.Join(penDir, "lifecycle.json"), &penLifecycle{
		Plan: planPersonal, State: stateSleeping, SleepSince: origSleep, DeleteAfter: origDelete,
	})

	// 1. Hand-run wake --renew-only writes BOTH data/registrar/.renew-only and
	//    data/registrar/billing-status.json, persists state=renew_only + deadline in
	//    lifecycle.json (preserving sleep_since/delete_after so the watcher sleeps it
	//    automatically), keeps .sleeping, writes .renew-wake, routes pen on front door,
	//    and shows renew_only in `hogman-host list` (B3).
	if out, err := runHost("wake", "--renew-only", "lab"); err != nil {
		t.Fatalf("wake --renew-only failed: err=%v out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(penDir, ".sleeping")); err != nil {
		t.Fatal(".sleeping must remain on disk during renew_only")
	}
	if _, err := os.Stat(filepath.Join(penDir, ".renew-wake")); err != nil {
		t.Fatal(".renew-wake must exist during renew_only")
	}
	if _, err := os.Stat(filepath.Join(penDir, "data", "registrar", ".renew-only")); err != nil {
		t.Fatal("data/registrar/.renew-only marker must be written by wake --renew-only (B3)")
	}
	if bsRaw, err := os.ReadFile(filepath.Join(penDir, "data", "registrar", "billing-status.json")); err != nil || !strings.Contains(string(bsRaw), `"state": "renew_only"`) {
		t.Fatalf("data/registrar/billing-status.json must be written by hand-run wake --renew-only (B3): err=%v content=%s", err, bsRaw)
	}
	handRec, err := loadPenLifecycle(filepath.Join(penDir, "lifecycle.json"))
	if err != nil || handRec.State != stateRenewOnly || handRec.WakeUntil == 0 || handRec.WakeCeiling == 0 || handRec.SleepSince != origSleep || handRec.DeleteAfter != origDelete {
		t.Fatalf("hand-run wake --renew-only must persist renew_only + deadline while preserving sleep dates (B3): %+v (%v)", handRec, err)
	}
	if caddyRaw, err := os.ReadFile(filepath.Join(home, "front", "Caddyfile")); err != nil || !strings.Contains(string(caddyRaw), "import pen lab") {
		t.Fatalf("front Caddyfile should route pen during renew_only: err=%v content=%s", err, caddyRaw)
	}
	if listOut, err := runHost("list"); err != nil || !strings.Contains(listOut, "renew_only") {
		t.Fatalf("hogman-host list should show renew_only: err=%v out=%s", err, listOut)
	}

	// 2. purge --due MUST refuse a pen in renew_only even if delete_after is in the past!
	if out, err := runHost("purge", "--due", "lab"); err == nil || !strings.Contains(out, "woken for renewal") {
		t.Fatalf("purge --due must refuse renew_only pen: err=%v out=%s", err, out)
	}

	// 3. sleep on a pen returning from renew_only removes .renew-wake and .renew-only,
	//    keeps .sleeping, writes the static sleeping notice with #wake=lab and NO unsafe-inline,
	//    AND preserves origSleep/origDelete!
	if out, err := runHost("sleep", "lab"); err != nil {
		t.Fatalf("sleep lab failed: err=%v out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(penDir, ".renew-wake")); !os.IsNotExist(err) {
		t.Fatal(".renew-wake must be removed by sleep")
	}
	if _, err := os.Stat(filepath.Join(penDir, "data", "registrar", ".renew-only")); !os.IsNotExist(err) {
		t.Fatal("data/registrar/.renew-only must be removed by sleep")
	}
	recAfterSleep, err := loadPenLifecycle(filepath.Join(penDir, "lifecycle.json"))
	if err != nil || recAfterSleep.SleepSince != origSleep || recAfterSleep.DeleteAfter != origDelete {
		t.Fatalf("sleep must preserve original sleep_since/delete_after: got %+v want (%d,%d)", recAfterSleep, origSleep, origDelete)
	}
	if caddyRaw, err := os.ReadFile(filepath.Join(home, "front", "Caddyfile")); err != nil ||
		!strings.Contains(string(caddyRaw), "https://get.example.com/#wake=lab") ||
		strings.Contains(string(caddyRaw), "unsafe-inline") {
		t.Fatalf("sleeping front Caddyfile should link to #wake=lab without unsafe-inline: err=%v content=%s", err, caddyRaw)
	}

	// B3: wake --renew-only refuses to start if data/registrar is missing (fail closed).
	_ = os.RemoveAll(filepath.Join(penDir, "data", "registrar"))
	if out, err := runHost("wake", "--renew-only", "lab"); err == nil || !strings.Contains(out, "missing registrar data dir") {
		t.Fatalf("wake --renew-only without data/registrar must fail closed: err=%v out=%s", err, out)
	}
	_ = os.MkdirAll(filepath.Join(penDir, "data", "registrar"), 0o700)

	// 4. Full wake from renew_only promotes live via `./hogman sync` without restarting containers
	//    and removes .sleeping, .renew-wake, and data/registrar/.renew-only!
	_ = os.Remove(filepath.Join(home, "pen-calls.log"))
	if out, err := runHost("wake", "--renew-only", "lab"); err != nil {
		t.Fatalf("second wake --renew-only failed: err=%v out=%s", err, out)
	}
	_ = os.Remove(filepath.Join(home, "pen-calls.log"))
	if out, err := runHost("wake", "lab"); err != nil {
		t.Fatalf("full wake from renew_only failed: err=%v out=%s", err, out)
	}
	calls, _ := os.ReadFile(filepath.Join(home, "pen-calls.log"))
	if strings.TrimSpace(string(calls)) != "sync" {
		t.Fatalf("full wake from running renew_only should call 'sync' without restarting: calls=%q", string(calls))
	}
	if _, err := os.Stat(filepath.Join(penDir, ".sleeping")); !os.IsNotExist(err) {
		t.Fatal(".sleeping must be removed after full wake")
	}
	if _, err := os.Stat(filepath.Join(penDir, ".renew-wake")); !os.IsNotExist(err) {
		t.Fatal(".renew-wake must be removed after full wake")
	}
	if _, err := os.Stat(filepath.Join(penDir, "data", "registrar", ".renew-only")); !os.IsNotExist(err) {
		t.Fatal("data/registrar/.renew-only must be removed after full wake")
	}

	// 5. Running pen with valid grace status shows running; bad/corrupt/oversized/non-grace
	//    billing-status.json or stale .renew-only marker is surfaced in `hogman-host list`.
	_ = os.WriteFile(filepath.Join(binDir, "docker"), []byte("#!/bin/sh\nif [ \"$1\" = ps ] && [ \"$2\" = --format ]; then echo pen-lab-headscale-1; fi\nexit 0\n"), 0o755)
	bsPath := filepath.Join(penDir, "data", "registrar", "billing-status.json")
	markerPath := filepath.Join(penDir, "data", "registrar", ".renew-only")

	if listOut, err := runHost("list"); err != nil || !strings.Contains(listOut, "running") || strings.Contains(listOut, "renew_only") {
		t.Fatalf("clean running pen should show running: err=%v out=%s", err, listOut)
	}

	// Valid grace status -> still running.
	_ = os.WriteFile(bsPath, []byte(`{"pen":"lab","state":"grace","grace_until":"2030-01-01T00:00:00Z"}`), 0o644)
	if listOut, err := runHost("list"); err != nil || !strings.Contains(listOut, "running") || strings.Contains(listOut, "renew_only") {
		t.Fatalf("valid grace pen should show running: err=%v out=%s", err, listOut)
	}

	// Corrupt JSON -> renew_only (bad status).
	_ = os.WriteFile(bsPath, []byte(`{"state":"grace"`), 0o644)
	if listOut, err := runHost("list"); err != nil || !strings.Contains(listOut, "renew_only (bad status)") {
		t.Fatalf("corrupt billing-status.json should show renew_only (bad status): err=%v out=%s", err, listOut)
	}

	// Trailing garbage after valid JSON -> renew_only (bad status).
	_ = os.WriteFile(bsPath, []byte(`{"state":"grace"} garbage`), 0o644)
	if listOut, err := runHost("list"); err != nil || !strings.Contains(listOut, "renew_only (bad status)") {
		t.Fatalf("trailing garbage billing-status.json should show renew_only (bad status): err=%v out=%s", err, listOut)
	}

	// Oversized (>4096B) -> renew_only (bad status).
	_ = os.WriteFile(bsPath, []byte(`{"state":"grace","pad":"`+strings.Repeat("a", 4100)+`"}`), 0o644)
	if listOut, err := runHost("list"); err != nil || !strings.Contains(listOut, "renew_only (bad status)") {
		t.Fatalf("oversized billing-status.json should show renew_only (bad status): err=%v out=%s", err, listOut)
	}

	// Non-grace state -> renew_only (bad status).
	_ = os.WriteFile(bsPath, []byte(`{"pen":"lab","state":"bogus"}`), 0o644)
	if listOut, err := runHost("list"); err != nil || !strings.Contains(listOut, "renew_only (bad status)") {
		t.Fatalf("non-grace billing-status.json should show renew_only (bad status): err=%v out=%s", err, listOut)
	}

	// Stale .renew-only marker without .renew-wake -> renew_only (marker).
	_ = os.Remove(bsPath)
	_ = os.WriteFile(markerPath, []byte("renew_only\n"), 0o644)
	if listOut, err := runHost("list"); err != nil || !strings.Contains(listOut, "renew_only (marker)") {
		t.Fatalf("stale .renew-only marker should show renew_only (marker): err=%v out=%s", err, listOut)
	}
}

func TestRenewWakeWatcherRetriesPendingWakeAndPromotesOwnerI7(t *testing.T) {
	b, home := newTestBroker(t, "")
	now := time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	b.nowFn = func() time.Time { return now }
	b.publicURL = "https://get.example.com"

	// Pen 1: paid renewal whose full wake transiently failed (state=active, pending_wake=true, pending_owner=alice).
	penDir := filepath.Join(home, "pens", "paidpen")
	_ = os.MkdirAll(filepath.Join(penDir, "data", "registrar"), 0o700)
	_ = os.WriteFile(filepath.Join(penDir, "data", "registrar", ".renew-only"), []byte("renew_only\n"), 0o644)
	_ = os.WriteFile(filepath.Join(penDir, "data", "registrar", "billing-status.json"), []byte(`{"pen":"paidpen","state":"renew_only"}`), 0o644)
	_ = savePenLifecycle(filepath.Join(penDir, "lifecycle.json"), &penLifecycle{
		Plan:         planPersonal,
		State:        stateActive,
		PaidUntil:    now.Add(365 * 24 * time.Hour).Unix(),
		PendingWake:  true,
		PendingOwner: "alice",
	})

	// Pen 2: unrelated active pen past PaidUntil — the 1-minute watcher MUST NOT move it to grace.
	otherDir := filepath.Join(home, "pens", "unrelated")
	_ = os.MkdirAll(filepath.Join(otherDir, "data", "registrar"), 0o700)
	_ = savePenLifecycle(filepath.Join(otherDir, "lifecycle.json"), &penLifecycle{
		Plan:      planPersonal,
		State:     stateActive,
		PaidUntil: now.Add(-10 * 24 * time.Hour).Unix(),
	})

	failFlag := filepath.Join(home, "fail-wake")
	_ = os.WriteFile(failFlag, []byte("1"), 0o600)
	logFile := filepath.Join(home, "calls.log")
	script := "#!/bin/sh\necho \"$*\" >> \"" + logFile + "\"\n" +
		"if [ \"$1\" = wake ] && [ -f \"" + failFlag + "\" ]; then echo 'transient error' >&2; exit 1; fi\n" +
		"exit 0\n"
	b.tool = filepath.Join(t.TempDir(), "hogman-host")
	_ = os.WriteFile(b.tool, []byte(script), 0o755)
	b.memberRoleFn = func(_ context.Context, _, handle string) (string, string, bool) {
		if handle == "alice" {
			return "admin", "active", true
		}
		return "", "", false
	}

	// First tick (t=0): wake fails transiently -> PendingWake stays true,
	// PendingWakeAttempts=1, backed off 1m; PendingOwner untouched.
	trs, err := b.sweepExpiredRenewWakes(context.Background(), now)
	if err != nil {
		t.Fatalf("first sweepExpiredRenewWakes: %v", err)
	}
	if len(trs) != 1 || trs[0].Pen != "paidpen" || trs[0].Woken {
		t.Fatalf("expected failed pending_wake transition for paidpen, got %+v", trs)
	}
	rec, _ := loadPenLifecycle(filepath.Join(penDir, "lifecycle.json"))
	if !rec.PendingWake || rec.PendingOwner != "alice" || rec.PendingWakeAttempts != 1 || rec.PendingWakeNextAt != now.Add(time.Minute).Unix() {
		t.Fatalf("failed wake retry must persist backoff and keep PendingWake/PendingOwner: %+v", rec)
	}
	// Unrelated pen must NOT have been touched by the 1-minute watcher.
	otherRec, _ := loadPenLifecycle(filepath.Join(otherDir, "lifecycle.json"))
	if otherRec.State != stateActive {
		t.Fatalf("1-minute watcher must not transition unrelated active pen to grace: %+v", otherRec)
	}

	// Still inside 1m backoff (+30s): watcher MUST skip paidpen.
	trs, err = b.sweepExpiredRenewWakes(context.Background(), now.Add(30*time.Second))
	if err != nil || len(trs) != 0 {
		t.Fatalf("expected skip during 1m backoff, got trs=%+v err=%v", trs, err)
	}

	// At +1m, host is still full -> attempt 2 fails and backs off 2m (to +3m).
	trs, err = b.sweepExpiredRenewWakes(context.Background(), now.Add(time.Minute))
	if err != nil || len(trs) != 1 || trs[0].Woken {
		t.Fatalf("expected second failed retry at +1m, got trs=%+v err=%v", trs, err)
	}
	rec, _ = loadPenLifecycle(filepath.Join(penDir, "lifecycle.json"))
	if rec.PendingWakeAttempts != 2 || rec.PendingWakeNextAt != now.Add(3*time.Minute).Unix() {
		t.Fatalf("second failure should set attempts=2 and next=+3m: %+v", rec)
	}

	// At +2m (inside 2m backoff): watcher MUST skip paidpen even though 1m elapsed.
	trs, err = b.sweepExpiredRenewWakes(context.Background(), now.Add(2*time.Minute))
	if err != nil || len(trs) != 0 {
		t.Fatalf("expected skip during 2m backoff at +2m, got trs=%+v err=%v", trs, err)
	}

	// At +3m, transient failure clears -> PendingWake & backoff clear, marker/status removed, alice promoted.
	_ = os.Remove(failFlag)
	trs, err = b.sweepExpiredRenewWakes(context.Background(), now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("recovery sweepExpiredRenewWakes: %v", err)
	}
	if len(trs) != 1 || trs[0].Pen != "paidpen" || !trs[0].Woken {
		t.Fatalf("expected successful pending_wake transition for paidpen, got %+v", trs)
	}
	rec, _ = loadPenLifecycle(filepath.Join(penDir, "lifecycle.json"))
	if rec.PendingWake || rec.PendingWakeAttempts != 0 || rec.PendingWakeNextAt != 0 || rec.PendingOwner != "" {
		t.Fatalf("successful wake retry should clear PendingWake, backoff, and PendingOwner: %+v", rec)
	}
	if _, err := os.Stat(filepath.Join(penDir, "data", "registrar", ".renew-only")); !os.IsNotExist(err) {
		t.Fatal(".renew-only must be cleared after successful pending_wake retry")
	}
	if _, err := os.Stat(filepath.Join(penDir, "data", "registrar", "billing-status.json")); !os.IsNotExist(err) {
		t.Fatal("billing-status.json must be cleared after successful pending_wake retry")
	}
	calls, _ := os.ReadFile(logFile)
	if !strings.Contains(string(calls), "pen paidpen member role alice owner") {
		t.Fatalf("expected pending_owner promotion after pending_wake retry, calls=%s", string(calls))
	}
}

func TestPendingWakeInFlightSkipsOverlappingWatcherAndSweepI7(t *testing.T) {
	b, home := newTestBroker(t, "")
	now := time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	b.nowFn = func() time.Time { return now }
	b.publicURL = "https://get.example.com"

	penDir := filepath.Join(home, "pens", "racepen")
	_ = os.MkdirAll(filepath.Join(penDir, "data", "registrar"), 0o700)
	_ = savePenLifecycle(filepath.Join(penDir, "lifecycle.json"), &penLifecycle{
		Plan:        planPersonal,
		State:       stateActive,
		PaidUntil:   now.Add(365 * 24 * time.Hour).Unix(),
		PendingWake: true,
	})

	startedFile := filepath.Join(home, "wake-started")
	releaseFile := filepath.Join(home, "wake-release")
	callsFile := filepath.Join(home, "wake-calls.log")
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> \"" + callsFile + "\"\n" +
		"if [ \"$1\" = wake ]; then\n" +
		"  touch \"" + startedFile + "\"\n" +
		"  i=0\n" +
		"  while [ ! -f \"" + releaseFile + "\" ] && [ $i -lt 200 ]; do\n" +
		"    sleep 0.05\n" +
		"    i=$((i+1))\n" +
		"  done\n" +
		"fi\n" +
		"exit 0\n"
	b.tool = filepath.Join(t.TempDir(), "hogman-host")
	_ = os.WriteFile(b.tool, []byte(script), 0o755)

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- b.finishRenewalWork(context.Background(), "racepen", true)
	}()

	// Wait until finishRenewalWork is actively inside `hogman-host wake racepen`.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(startedFile); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(startedFile); err != nil {
		t.Fatal("finishRenewalWork never started hogman-host wake")
	}

	// While finishRenewalWork's wake is in flight, both the 1-minute watcher and
	// the daily sweep MUST skip racepen instead of starting a second overlapping wake.
	trsWatcher, err := b.sweepExpiredRenewWakes(context.Background(), now)
	if err != nil || len(trsWatcher) != 0 {
		t.Fatalf("watcher must skip in-flight wake, got trs=%+v err=%v", trsWatcher, err)
	}
	trsSweep, err := b.sweepLifecycles(context.Background(), now, false)
	if err != nil || len(trsSweep) != 0 {
		t.Fatalf("daily sweep must skip in-flight wake, got trs=%+v err=%v", trsSweep, err)
	}

	// Release the in-flight wake and confirm it finishes cleanly with exactly 1 wake call.
	_ = os.WriteFile(releaseFile, []byte("go"), 0o600)
	if err := <-doneCh; err != nil {
		t.Fatalf("finishRenewalWork returned error: %v", err)
	}
	rec, _ := loadPenLifecycle(filepath.Join(penDir, "lifecycle.json"))
	if rec.PendingWake {
		t.Fatalf("finishRenewalWork should have cleared PendingWake: %+v", rec)
	}
	rawCalls, _ := os.ReadFile(callsFile)
	if got := strings.Count(string(rawCalls), "wake --no-lifecycle racepen"); got != 1 {
		t.Fatalf("expected exactly 1 wake invocation (no overlap), got %d:\n%s", got, string(rawCalls))
	}
}

func TestExpiredRenewWakeSleepSerializedWithConcurrentRenewalI7(t *testing.T) {
	b, home := newTestBroker(t, "")
	now := time.Date(2026, 12, 1, 12, 30, 0, 0, time.UTC)
	b.nowFn = func() time.Time { return now }
	b.publicURL = "https://get.example.com"

	penDir := filepath.Join(home, "pens", "payrace")
	_ = os.MkdirAll(filepath.Join(penDir, "data", "registrar"), 0o700)
	_ = os.WriteFile(filepath.Join(penDir, "data", "registrar", ".renew-only"), []byte("renew_only\n"), 0o644)
	_ = os.WriteFile(filepath.Join(penDir, "data", "registrar", "billing-status.json"), []byte(`{"pen":"payrace","state":"renew_only"}`), 0o644)
	oldSleep := now.Add(-60 * 24 * time.Hour).Unix()
	oldDelete := now.Add(305 * 24 * time.Hour).Unix()
	lcPath := filepath.Join(penDir, "lifecycle.json")
	_ = savePenLifecycle(lcPath, &penLifecycle{
		Plan:          planPersonal,
		State:         stateRenewOnly,
		SleepSince:    oldSleep,
		DeleteAfter:   oldDelete,
		WakeStartedAt: now.Add(-25 * time.Minute).Unix(),
		WakeUntil:     now.Add(-5 * time.Minute).Unix(),
		WakeCeiling:   now.Add(-5 * time.Minute).Unix(),
	})

	startedFile := filepath.Join(home, "sleep-started")
	releaseFile := filepath.Join(home, "sleep-release")
	callsFile := filepath.Join(home, "sleep-calls.log")
	// Fake hogman-host whose `sleep` blocks on a barrier AND rewrites lifecycle.json
	// to `sleeping` with the old delete_after (mirroring real `lifecycle_mark_sleeping`).
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> \"" + callsFile + "\"\n" +
		"if [ \"$1\" = sleep ]; then\n" +
		"  touch \"" + startedFile + "\"\n" +
		"  i=0\n" +
		"  while [ ! -f \"" + releaseFile + "\" ] && [ $i -lt 200 ]; do\n" +
		"    sleep 0.05\n" +
		"    i=$((i+1))\n" +
		"  done\n" +
		"  printf '{\"plan\":\"personal\",\"state\":\"sleeping\",\"sleep_since\":%d,\"delete_after\":%d}\\n' " +
		fmt.Sprintf("%d %d", oldSleep, oldDelete) + " > \"" + lcPath + "\"\n" +
		"fi\n" +
		"exit 0\n"
	b.tool = filepath.Join(t.TempDir(), "hogman-host")
	_ = os.WriteFile(b.tool, []byte(script), 0o755)

	watcherDone := make(chan error, 1)
	go func() {
		_, err := b.sweepExpiredRenewWakes(context.Background(), now)
		watcherDone <- err
	}()

	// Wait until `hogman-host sleep payrace` is actively executing inside the watcher.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(startedFile); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(startedFile); err != nil {
		t.Fatal("watcher never started hogman-host sleep")
	}

	// Land a renewal payment concurrently while `hogman-host sleep` is mid-flight.
	type renewRes struct {
		rec      *penLifecycle
		sleeping bool
		err      error
	}
	renewDone := make(chan renewRes, 1)
	go func() {
		rec, _, sleeping, err := b.recordRenewal("payrace", "cs_race_1", "sub_new_race", "cus_race", "", now)
		renewDone <- renewRes{rec: rec, sleeping: sleeping, err: err}
	}()

	// Verify recordRenewal is serialized behind lifecycleMu and has NOT returned yet.
	select {
	case res := <-renewDone:
		t.Fatalf("recordRenewal raced ahead of in-flight sleep: %+v", res)
	case <-time.After(150 * time.Millisecond):
	}

	// Release `hogman-host sleep`: watcher finishes writing sleeping, then
	// recordRenewal runs after it and transitions cleanly to active + pending_wake.
	_ = os.WriteFile(releaseFile, []byte("go"), 0o600)
	if err := <-watcherDone; err != nil {
		t.Fatalf("sweepExpiredRenewWakes error: %v", err)
	}
	res := <-renewDone
	if res.err != nil || !res.sleeping || res.rec == nil {
		t.Fatalf("recordRenewal failed after sleep: %+v", res)
	}
	finalRec, err := loadPenLifecycle(lcPath)
	if err != nil {
		t.Fatalf("load final lifecycle.json: %v", err)
	}
	if finalRec.State != stateActive || !finalRec.PendingWake || finalRec.DeleteAfter != 0 || finalRec.SleepSince != 0 {
		t.Fatalf("paid renewal must NOT be overwritten to sleeping by concurrent expired-wake sleep: %+v", finalRec)
	}
	// Follow-up finishRenewalWork immediately wakes the pen and clears PendingWake.
	if err := b.finishRenewalWork(context.Background(), "payrace", true); err != nil {
		t.Fatalf("finishRenewalWork after serialized sleep failed: %v", err)
	}
	finalRec, _ = loadPenLifecycle(lcPath)
	if finalRec.State != stateActive || finalRec.PendingWake {
		t.Fatalf("expected active pen with PendingWake=false after wake: %+v", finalRec)
	}
}

func TestHogmanHostNoLifecycleAndBrokerDelegationI12(t *testing.T) {
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
	_ = os.WriteFile(filepath.Join(binDir, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	_ = os.WriteFile(filepath.Join(home, "host.env"), []byte("MAX_PENS=4\nRENEW_WAKE_RESERVE=2\nSIGNUP_HOST=get.example.com\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(home, "front"), 0o700)
	penDir := filepath.Join(home, "pens", "lab")
	_ = os.MkdirAll(filepath.Join(penDir, "data", "registrar"), 0o700)
	_ = os.WriteFile(filepath.Join(penDir, ".env"), []byte("PUBLIC_HOST=lab.gate.example.com\nSTUN_PORT=3478\n"), 0o600)
	_ = os.WriteFile(filepath.Join(penDir, "hogman"), []byte("#!/bin/sh\nexit 0\n"), 0o755)

	lcPath := filepath.Join(penDir, "lifecycle.json")
	origLC := &penLifecycle{
		Plan:              planPersonal,
		State:             stateActive,
		PaidUntil:         1900000000,
		AppliedEvents:     []string{"evt_keep_1"},
		PendingCancelSubs: []pendingCancelSub{{SubscriptionID: "sub_old_keep"}},
		UpdatedAt:         1800000000,
	}
	if err := savePenLifecycle(lcPath, origLC); err != nil {
		t.Fatal(err)
	}
	origBytes, err := os.ReadFile(lcPath)
	if err != nil {
		t.Fatal(err)
	}

	runHost := func(args ...string) (string, error) {
		cmd := exec.Command("bash", append([]string{hostScript}, args...)...)
		cmd.Env = append(os.Environ(), "HOGMAN_HOME="+home, "PATH="+binDir+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// 1. --no-lifecycle on sleep, wake --renew-only, and wake NEVER modifies lifecycle.json.
	if out, err := runHost("sleep", "--no-lifecycle", "lab"); err != nil {
		t.Fatalf("sleep --no-lifecycle failed: err=%v out=%s", err, out)
	}
	if got, _ := os.ReadFile(lcPath); string(got) != string(origBytes) {
		t.Fatalf("sleep --no-lifecycle modified lifecycle.json:\ngot:  %s\nwant: %s", got, origBytes)
	}
	if out, err := runHost("wake", "--renew-only", "--no-lifecycle", "lab"); err != nil {
		t.Fatalf("wake --renew-only --no-lifecycle failed: err=%v out=%s", err, out)
	}
	if got, _ := os.ReadFile(lcPath); string(got) != string(origBytes) {
		t.Fatalf("wake --renew-only --no-lifecycle modified lifecycle.json:\ngot:  %s\nwant: %s", got, origBytes)
	}
	if out, err := runHost("wake", "--no-lifecycle", "lab"); err != nil {
		t.Fatalf("wake --no-lifecycle failed: err=%v out=%s", err, out)
	}
	if got, _ := os.ReadFile(lcPath); string(got) != string(origBytes) {
		t.Fatalf("wake --no-lifecycle modified lifecycle.json:\ngot:  %s\nwant: %s", got, origBytes)
	}

	// 2. When signup broker is configured and running, hand-run sleep/wake/wake --renew-only
	//    delegate to `docker compose exec -T broker hogman-signup lifecycle-transition <action> <pen>`.
	_ = os.MkdirAll(filepath.Join(home, "signup"), 0o700)
	_ = os.WriteFile(filepath.Join(home, "signup", "compose.yaml"), []byte("services:\n  broker: {}\n"), 0o600)
	dockerLog := filepath.Join(home, "docker.log")
	dockerStub := "#!/bin/sh\n" +
		"echo \"$*\" >> \"" + dockerLog + "\"\n" +
		"if [ \"$1\" = compose ] && [ \"$2\" = ps ]; then echo broker-cid-123; exit 0; fi\n" +
		"exit 0\n"
	_ = os.WriteFile(filepath.Join(binDir, "docker"), []byte(dockerStub), 0o755)

	for _, args := range [][]string{
		{"sleep", "lab"},
		{"wake", "--renew-only", "lab"},
		{"wake", "lab"},
	} {
		if out, err := runHost(args...); err != nil {
			t.Fatalf("delegated %v failed: err=%v out=%s", args, err, out)
		}
	}
	dlog, _ := os.ReadFile(dockerLog)
	for _, want := range []string{
		"compose exec -T broker hogman-signup lifecycle-transition sleep lab",
		"compose exec -T broker hogman-signup lifecycle-transition renew_only lab",
		"compose exec -T broker hogman-signup lifecycle-transition wake lab",
	} {
		if !strings.Contains(string(dlog), want) {
			t.Fatalf("expected delegated broker call %q in docker log:\n%s", want, string(dlog))
		}
	}
	if got, _ := os.ReadFile(lcPath); string(got) != string(origBytes) {
		t.Fatalf("delegated host commands must not touch lifecycle.json directly:\ngot: %s", got)
	}
}

func TestBrokerLifecycleTransitionEndpointI12(t *testing.T) {
	b, home := newTestBroker(t, "")
	now := time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	b.nowFn = func() time.Time { return now }
	b.publicURL = "https://get.example.com"
	b.wakeHealthInterval = 5 * time.Millisecond
	b.wakeHealthFn = func(context.Context, string) error { return nil }

	penDir := filepath.Join(home, "pens", "lab")
	_ = os.MkdirAll(filepath.Join(penDir, "data", "registrar"), 0o700)
	lcPath := filepath.Join(penDir, "lifecycle.json")
	_ = savePenLifecycle(lcPath, &penLifecycle{
		Plan:              planPersonal,
		State:             stateActive,
		PaidUntil:         now.Add(30 * 24 * time.Hour).Unix(),
		AppliedEvents:     []string{"evt_preserve_1"},
		PendingCancelSubs: []pendingCancelSub{{SubscriptionID: "sub_old_preserve"}},
	})

	callsLog := filepath.Join(home, "host-calls.log")
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> \"" + callsLog + "\"\n" +
		"if [ \"$1\" = capacity ]; then echo '{\"pens\":1,\"max\":8,\"open\":true,\"renew_wakes\":0,\"renew_reserve\":2}'; exit 0; fi\n" +
		"if [ \"$1\" = sleep ]; then touch \"" + penDir + "/.sleeping\"; rm -f \"" + penDir + "/.renew-wake\"; exit 0; fi\n" +
		"if [ \"$1\" = wake ] && [ \"$2\" = --renew-only ]; then touch \"" + penDir + "/.renew-wake\"; exit 0; fi\n" +
		"if [ \"$1\" = wake ]; then rm -f \"" + penDir + "/.sleeping\" \"" + penDir + "/.renew-wake\"; exit 0; fi\n" +
		"exit 0\n"
	b.tool = filepath.Join(t.TempDir(), "hogman-host")
	_ = os.WriteFile(b.tool, []byte(script), 0o755)

	callTransition := func(action string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"pen":"lab","action":%q}`, action)
		req := httptest.NewRequest("POST", "/lifecycle/transition", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+b.token)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		b.handler().ServeHTTP(rr, req)
		return rr
	}

	// 1. Sleep via broker endpoint reports first_delete_date=true on first sleep.
	rrSleep1 := callTransition("sleep")
	if rrSleep1.Code != 200 {
		t.Fatalf("transition sleep = %d: %s", rrSleep1.Code, rrSleep1.Body.String())
	}
	if !strings.Contains(rrSleep1.Body.String(), `"first_delete_date":true`) || !strings.Contains(rrSleep1.Body.String(), `"delete_after":"2027-12-01"`) {
		t.Fatalf("first sleep should report first_delete_date=true and delete_after: %s", rrSleep1.Body.String())
	}
	rec, _ := loadPenLifecycle(lcPath)
	if rec.State != stateSleeping || rec.SleepSince == 0 || rec.DeleteAfter == 0 ||
		!hasAppliedEvent(*rec, "evt_preserve_1") || len(rec.PendingCancelSubs) != 1 {
		t.Fatalf("sleep transition lost fields or state wrong: %+v", rec)
	}
	origSleep, origDelete := rec.SleepSince, rec.DeleteAfter

	// 2. Renew-only wake via broker endpoint preserves sleep_since/delete_after and writes marker+status.
	if rr := callTransition("renew_only"); rr.Code != 200 {
		t.Fatalf("transition renew_only = %d: %s", rr.Code, rr.Body.String())
	}
	rec, _ = loadPenLifecycle(lcPath)
	if rec.State != stateRenewOnly || rec.SleepSince != origSleep || rec.DeleteAfter != origDelete || rec.WakeCeiling == 0 {
		t.Fatalf("renew_only transition wrong: %+v", rec)
	}
	if _, err := os.Stat(filepath.Join(penDir, "data", "registrar", ".renew-only")); err != nil {
		t.Fatalf("renew_only transition must write .renew-only marker: %v", err)
	}
	// Sleeping back from renew_only preserves the original deletion date -> first_delete_date=false.
	rrSleep2 := callTransition("sleep")
	if rrSleep2.Code != 200 || !strings.Contains(rrSleep2.Body.String(), `"first_delete_date":false`) {
		t.Fatalf("repeat sleep should report first_delete_date=false: code=%d body=%s", rrSleep2.Code, rrSleep2.Body.String())
	}
	// Re-enter renew_only so step 4 still exercises wake from renew_only.
	if rr := callTransition("renew_only"); rr.Code != 200 {
		t.Fatalf("second transition renew_only = %d: %s", rr.Code, rr.Body.String())
	}

	// 3. In-flight guard returns 409 Conflict if another wake/sleep is running.
	if !b.tryBeginWake("lab") {
		t.Fatal("tryBeginWake failed")
	}
	if rr := callTransition("wake"); rr.Code != 409 {
		b.endWake("lab")
		t.Fatalf("expected 409 when wake in flight, got %d: %s", rr.Code, rr.Body.String())
	}
	b.endWake("lab")

	// 4. Full wake via broker endpoint restores active while preserving applied_events & pending_cancel_subs.
	if rr := callTransition("wake"); rr.Code != 200 {
		t.Fatalf("transition wake = %d: %s", rr.Code, rr.Body.String())
	}
	rec, _ = loadPenLifecycle(lcPath)
	if rec.State != stateActive || rec.SleepSince != 0 || rec.DeleteAfter != 0 ||
		!hasAppliedEvent(*rec, "evt_preserve_1") || len(rec.PendingCancelSubs) != 1 {
		t.Fatalf("wake transition lost fields or failed to clear sleep dates: %+v", rec)
	}

	calls, _ := os.ReadFile(callsLog)
	for _, want := range []string{
		"sleep --no-lifecycle lab",
		"wake --renew-only --no-lifecycle lab",
		"wake --no-lifecycle lab",
	} {
		if !strings.Contains(string(calls), want) {
			t.Fatalf("expected broker to pass --no-lifecycle (%q) in calls:\n%s", want, string(calls))
		}
	}
}

func TestConcurrentBrokerSaveAndHostRewriteKeepBothChangesI12(t *testing.T) {
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
	_ = os.WriteFile(filepath.Join(binDir, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	_ = os.WriteFile(filepath.Join(home, "host.env"), []byte("MAX_PENS=4\nRENEW_WAKE_RESERVE=2\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(home, "front"), 0o700)
	penDir := filepath.Join(home, "pens", "lab")
	_ = os.MkdirAll(filepath.Join(penDir, "data", "registrar"), 0o700)
	_ = os.WriteFile(filepath.Join(penDir, ".env"), []byte("PUBLIC_HOST=lab.gate.example.com\nSTUN_PORT=3478\n"), 0o600)

	downDone := filepath.Join(home, "down-done")
	_ = os.WriteFile(filepath.Join(penDir, "hogman"), []byte("#!/bin/sh\ntouch \""+downDone+"\"\nexit 0\n"), 0o755)

	lcPath := filepath.Join(penDir, "lifecycle.json")
	if err := savePenLifecycle(lcPath, &penLifecycle{
		Plan:      planPersonal,
		State:     stateGrace,
		PaidUntil: 1800000000,
	}); err != nil {
		t.Fatal(err)
	}

	// Hold the shared per-pen advisory flock from the broker while starting a
	// standalone/fallback `hogman-host sleep lab` concurrently.
	lockHeld := make(chan struct{})
	releaseLock := make(chan struct{})
	brokerDone := make(chan error, 1)
	go func() {
		brokerDone <- withPenLifecycleFileLock(lcPath, func() error {
			close(lockHeld)
			<-releaseLock
			rec, err := loadPenLifecycle(lcPath)
			if err != nil {
				return err
			}
			recordAppliedEvent(rec, "evt_concurrent_broker_1")
			rec.PendingCancelSubs = append(rec.PendingCancelSubs, pendingCancelSub{SubscriptionID: "sub_concurrent_1"})
			rec.UpdatedAt = 1850000000
			return savePenLifecycle(lcPath, rec)
		})
	}()
	<-lockHeld

	hostDone := make(chan error, 1)
	var hostOut string
	go func() {
		cmd := exec.Command("bash", hostScript, "sleep", "lab")
		cmd.Env = append(os.Environ(), "HOGMAN_HOME="+home, "PATH="+binDir+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		hostOut = string(out)
		hostDone <- err
	}()

	// Wait until `hogman-host sleep` has finished `./hogman down` and reached
	// `lifecycle_mark_sleeping` (now blocked on .lifecycle.lock).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(downDone); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(downDone); err != nil {
		close(releaseLock)
		t.Fatal("hogman-host sleep never reached ./hogman down")
	}
	// Confirm hogman-host sleep is blocked waiting for our flock and has NOT exited early.
	select {
	case err := <-hostDone:
		close(releaseLock)
		t.Fatalf("hogman-host sleep bypassed .lifecycle.lock while broker held it (err=%v, out=%s)", err, hostOut)
	case <-time.After(200 * time.Millisecond):
	}

	// Broker writes its update and releases the lock; hogman-host sleep then
	// acquires the lock, reads the broker's saved JSON, and applies sleeping on top.
	close(releaseLock)
	if err := <-brokerDone; err != nil {
		t.Fatalf("broker locked update failed: %v", err)
	}
	if err := <-hostDone; err != nil {
		t.Fatalf("hogman-host sleep failed: err=%v out=%s", err, hostOut)
	}

	finalRec, err := loadPenLifecycle(lcPath)
	if err != nil {
		t.Fatalf("load final lifecycle.json: %v", err)
	}
	if finalRec.State != stateSleeping || finalRec.SleepSince == 0 || finalRec.DeleteAfter == 0 {
		t.Fatalf("expected host sleep state in final record, got %+v", finalRec)
	}
	if !hasAppliedEvent(*finalRec, "evt_concurrent_broker_1") ||
		len(finalRec.PendingCancelSubs) != 1 || finalRec.PendingCancelSubs[0].SubscriptionID != "sub_concurrent_1" {
		t.Fatalf("concurrent host rewrite clobbered broker updates! final=%+v", finalRec)
	}
	if !strings.Contains(hostOut, "scheduled for automatic deletion after ") {
		t.Fatalf("first hogman-host sleep should announce the scheduled deletion date; out=%s", hostOut)
	}

	// Subsequent sleep on an already-sleeping pen does NOT announce a new deletion date,
	// and running without flock or python3 in PATH prints an unlocked-fallback warning.
	noLockBin := filepath.Join(home, "nolock-bin")
	_ = os.MkdirAll(noLockBin, 0o700)
	_ = os.WriteFile(filepath.Join(noLockBin, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	for _, tool := range []string{"awk", "basename", "bash", "cat", "chmod", "cp", "cut", "date", "dirname", "find", "grep", "head", "id", "install", "ls", "mkdir", "mktemp", "mv", "rm", "sed", "sh", "sort", "stat", "tail", "tee", "touch", "tr", "wc"} {
		if p, err := exec.LookPath(tool); err == nil {
			_ = os.Symlink(p, filepath.Join(noLockBin, tool))
		}
	}
	cmd2 := exec.Command("bash", hostScript, "sleep", "lab")
	cmd2.Env = []string{"HOME=" + home, "HOGMAN_HOME=" + home, "PATH=" + noLockBin}
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("unlocked fallback sleep failed: err=%v out=%s", err, string(out2))
	}
	if !strings.Contains(string(out2), "warning: neither flock nor python3 found") {
		t.Fatalf("expected unlocked-fallback warning when flock and python3 are absent; out=%s", string(out2))
	}
	if strings.Contains(string(out2), "scheduled for automatic deletion after ") {
		t.Fatalf("repeat sleep should not announce a first deletion date again; out=%s", string(out2))
	}
}
