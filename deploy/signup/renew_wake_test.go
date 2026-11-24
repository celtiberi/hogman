package main

import (
	"context"
	"encoding/json"
	"errors"
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
}
