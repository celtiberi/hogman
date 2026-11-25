package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSetPolicyLatencyAlertsI30(t *testing.T) {
	var mu sync.Mutex
	var alerts []string
	ntfySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		alerts = append(alerts, string(body))
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer ntfySrv.Close()

	b, home := newTestBroker(t, "")
	b.ntfy = ntfySrv.URL
	// Use REAL default healthNotify (1/hr) and opsNotify (4/hr) limiters!
	var nowMu sync.Mutex
	curNow := time.Date(2028, 3, 1, 12, 0, 0, 0, time.UTC)
	b.nowFn = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}
	setNow := func(ts time.Time) {
		nowMu.Lock()
		curNow = ts
		nowMu.Unlock()
	}

	snapDir := filepath.Join(home, "ops")
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatal(err)
	}
	b.opsSnapshotPath = filepath.Join(snapDir, "snapshot.json")

	// 1. Missing snapshot file is silently ignored.
	if got := b.checkSetPolicyLatencyAlerts(curNow); len(got) != 0 {
		t.Fatalf("missing snapshot alerted: %v", got)
	}

	writeSnap := func(genAt time.Time, pensJSON string) {
		t.Helper()
		raw := fmt.Sprintf(`{"generated_at":%q,"pens":[%s]}`, genAt.UTC().Format(time.RFC3339), pensJSON)
		tmp := b.opsSnapshotPath + ".tmp"
		if err := os.WriteFile(tmp, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, b.opsSnapshotPath); err != nil {
			t.Fatal(err)
		}
	}

	// 2. Boundary p95 == 5000ms, sleeping pen > 5000ms, and 0-sample pen do NOT alert.
	writeSnap(curNow, `
		{"name":"okpen","state":"running","setpolicy_samples":10,"setpolicy_last_ms":400,"setpolicy_p95_ms":5000},
		{"name":"sleeppen","state":"sleeping","setpolicy_samples":10,"setpolicy_last_ms":6500,"setpolicy_p95_ms":7000},
		{"name":"quietpen","state":"running","setpolicy_samples":0,"setpolicy_last_ms":0,"setpolicy_p95_ms":9000}
	`)
	if got := b.checkSetPolicyLatencyAlerts(curNow); len(got) != 0 {
		t.Fatalf("expected 0 alerts at boundary/sleeping/quiet, got %v", got)
	}

	// 3. Stale (>10m) AND future-skewed (>2m ahead) snapshots do NOT alert.
	writeSnap(curNow.Add(-11*time.Minute), `{"name":"slowpen","state":"running","setpolicy_samples":20,"setpolicy_last_ms":5400,"setpolicy_p95_ms":6200}`)
	if got := b.checkSetPolicyLatencyAlerts(curNow); len(got) != 0 {
		t.Fatalf("stale snapshot must not alert, got %v", got)
	}
	writeSnap(curNow.Add(3*time.Minute), `{"name":"slowpen","state":"running","setpolicy_samples":20,"setpolicy_last_ms":5400,"setpolicy_p95_ms":6200}`)
	if got := b.checkSetPolicyLatencyAlerts(curNow); len(got) != 0 {
		t.Fatalf("future-skewed snapshot must not alert, got %v", got)
	}

	// 4. Exhausting the 1/hr "health" limiter must NOT starve "ops" alerts, and
	//    multiple slow pens in one pass are aggregated into ONE ntfy push!
	if !b.notifyKind("health", "unrelated health alert") {
		t.Fatal("first health alert should pass")
	}
	if b.notifyKind("health", "second health alert within 1h") {
		t.Fatal("default healthNotify should enforce 1/hr")
	}
	writeSnap(curNow, `
		{"name":"pen-a","state":"running","setpolicy_samples":20,"setpolicy_last_ms":5400,"setpolicy_p95_ms":6200},
		{"name":"pen-b","state":"running","setpolicy_samples":15,"setpolicy_last_ms":6100,"setpolicy_p95_ms":7100},
		{"name":"pen-c","state":"running","setpolicy_samples":8,"setpolicy_last_ms":5100,"setpolicy_p95_ms":5400}
	`)
	if got := b.checkSetPolicyLatencyAlerts(curNow); len(got) != 3 {
		t.Fatalf("expected 3 alerted pens in one aggregated push, got %v", got)
	}
	b.bgWG.Wait()
	mu.Lock()
	var opsPushes []string
	for _, a := range alerts {
		if strings.Contains(a, "Slow SetPolicy") {
			opsPushes = append(opsPushes, a)
		}
	}
	mu.Unlock()
	if len(opsPushes) != 1 || !strings.Contains(opsPushes[0], "pen-a") || !strings.Contains(opsPushes[0], "pen-b") || !strings.Contains(opsPushes[0], "pen-c") {
		t.Fatalf("expected 1 aggregated ntfy alert covering all 3 pens, got %v", opsPushes)
	}

	// 5. Repeat check inside 6h cooldown must NOT spam.
	t5m := curNow.Add(5 * time.Minute)
	setNow(t5m)
	writeSnap(t5m, `{"name":"pen-a","state":"running","setpolicy_samples":25,"setpolicy_last_ms":5800,"setpolicy_p95_ms":6300}`)
	if got := b.checkSetPolicyLatencyAlerts(t5m); len(got) != 0 {
		t.Fatalf("expected cooldown suppression, got %v", got)
	}

	// 6. After 6h cooldown, still slow -> alerts again.
	t6h := curNow.Add(6 * time.Hour)
	setNow(t6h)
	writeSnap(t6h, `{"name":"pen-a","state":"running","setpolicy_samples":30,"setpolicy_last_ms":5900,"setpolicy_p95_ms":6400}`)
	if got := b.checkSetPolicyLatencyAlerts(t6h); len(got) != 1 || got[0] != "pen-a" {
		t.Fatalf("expected repeat alert after 6h cooldown, got %v", got)
	}

	// 7. Recovery (p95 <= 5000ms) clears cooldown so a new spike alerts immediately.
	tRec := t6h.Add(2 * time.Minute)
	setNow(tRec)
	writeSnap(tRec, `{"name":"pen-a","state":"running","setpolicy_samples":30,"setpolicy_last_ms":300,"setpolicy_p95_ms":800}`)
	if got := b.checkSetPolicyLatencyAlerts(tRec); len(got) != 0 {
		t.Fatalf("expected 0 alerts on recovery, got %v", got)
	}
	tSpike := tRec.Add(2 * time.Minute)
	setNow(tSpike)
	writeSnap(tSpike, `{"name":"pen-a","state":"running","setpolicy_samples":30,"setpolicy_last_ms":5500,"setpolicy_p95_ms":5500}`)
	if got := b.checkSetPolicyLatencyAlerts(tSpike); len(got) != 1 || got[0] != "pen-a" {
		t.Fatalf("expected immediate alert on new spike after recovery, got %v", got)
	}

	// 8. Rate-limited drop on opsNotify must NOT arm the 6h cooldown: once the
	//    opsNotify window passes, the dropped pen still alerts!
	b.opsNotify = newLimiterWithCap(1, time.Hour, 4)
	tLim := tSpike.Add(2 * time.Hour)
	setNow(tLim)
	if !b.notifyKind("ops", "consume sole ops slot") {
		t.Fatal("failed to consume ops slot")
	}
	writeSnap(tLim, `{"name":"pen-dropped","state":"running","setpolicy_samples":10,"setpolicy_last_ms":6000,"setpolicy_p95_ms":6000}`)
	if got := b.checkSetPolicyLatencyAlerts(tLim); len(got) != 0 {
		t.Fatalf("expected rate-limited drop to return 0 alerted pens, got %v", got)
	}
	tAfterLim := tLim.Add(61 * time.Minute)
	setNow(tAfterLim)
	writeSnap(tAfterLim, `{"name":"pen-dropped","state":"running","setpolicy_samples":12,"setpolicy_last_ms":6100,"setpolicy_p95_ms":6100}`)
	if got := b.checkSetPolicyLatencyAlerts(tAfterLim); len(got) != 1 || got[0] != "pen-dropped" {
		t.Fatalf("rate-limited pen must alert once limiter reopens (no 6h blackout), got %v", got)
	}
}
