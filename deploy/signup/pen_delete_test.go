package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"testing"
	"time"
)

func makeTestSignedToken(key []byte, purpose, pen, handle, role string, exp int64, nonce string) string {
	rawPayload := fmt.Sprintf("v1|%s|%s|%s|%d|%s", pen, handle, role, exp, nonce)
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(rawPayload))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(purpose))
	mac.Write([]byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payloadB64 + "." + sigB64
}

func TestSelfServicePenDeleteFlowI24(t *testing.T) {
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

	b, home := newTestBroker(t, "")
	b.ntfy = ntfySrv.URL
	b.healthNotify = newLimiterWithCap(20, time.Minute, 32)
	b.raiseNotify = newLimiterWithCap(20, time.Minute, 32)
	b.publicURL = "https://get.example.com"

	now := time.Date(2028, 6, 1, 12, 0, 0, 0, time.UTC)
	b.nowFn = func() time.Time { return now }

	// Stub hogman-host tool that simulates purge --owner-delete (and fails for pen "failpurge").
	b.tool = filepath.Join(t.TempDir(), "hogman-host")
	if err := os.WriteFile(b.tool, []byte(`#!/bin/sh
echo "$*" >> "$HOGMAN_HOME/tool.log"
if [ "$1" = "purge" ] && [ "$2" = "--owner-delete" ]; then
  pen="$3"
  if [ "$pen" = "failpurge" ]; then
    echo "simulated final backup failure" >&2
    exit 1
  fi
  rm -rf "$HOGMAN_HOME/pens/$pen/data" "$HOGMAN_HOME/pens/$pen/.env" "$HOGMAN_HOME/pens/$pen/.sleeping" "$HOGMAN_HOME/pens/$pen/.renew-wake"
  touch "$HOGMAN_HOME/pens/$pen/.removed"
  printf 'deleted_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$HOGMAN_HOME/pens/$pen/.retired"
  exit 0
fi
exit 0
`), 0o755); err != nil {
		t.Fatal(err)
	}

	_ = os.WriteFile(filepath.Join(home, "host.env"), []byte("MAX_PENS=4\n"), 0o600)

	owners := map[string]string{
		"paidpen:alice":    "owner",
		"paidpen:dan":      "admin",
		"freepen:alice":    "owner",
		"failcancel:alice": "owner",
		"failpurge:alice":  "owner",
		"sleeppen:alice":   "owner",
		"wakepen:alice":    "owner",
	}
	b.memberRoleFn = func(_ context.Context, pen, handle string) (string, string, bool) {
		if r, ok := owners[pen+":"+handle]; ok {
			return r, "active", true
		}
		return "", "", false
	}

	setupPen := func(pen string, lc *penLifecycle) []byte {
		pdir := filepath.Join(home, "pens", pen)
		regDir := filepath.Join(pdir, "data", "registrar")
		if err := os.MkdirAll(regDir, 0o700); err != nil {
			t.Fatal(err)
		}
		key := sha256.Sum256([]byte("test-key-" + pen))
		if err := os.WriteFile(b.renewKeyPath(pen), []byte(hex.EncodeToString(key[:])+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if lc != nil {
			if err := savePenLifecycle(b.lifecyclePath(pen), lc); err != nil {
				t.Fatal(err)
			}
		}
		return key[:]
	}

	paidKey := setupPen("paidpen", &penLifecycle{
		Plan:           planPersonal,
		State:          stateActive,
		PaidUntil:      now.Add(180 * 24 * time.Hour).Unix(),
		SubscriptionID: "sub_live_1",
		PendingCancelSubs: []pendingCancelSub{
			{SubscriptionID: "sub_old_replaced"},
		},
	})
	freeKey := setupPen("freepen", nil) // legacy free pen without lifecycle.json
	failCancelKey := setupPen("failcancel", &penLifecycle{
		Plan:           planWork,
		State:          stateGrace,
		SubscriptionID: "sub_fail_cancel",
	})
	failPurgeKey := setupPen("failpurge", &penLifecycle{
		Plan:           planPersonal,
		State:          stateActive,
		PaidUntil:      now.Add(90 * 24 * time.Hour).Unix(),
		SubscriptionID: "sub_partial_fail",
	})
	sleepKey := setupPen("sleeppen", &penLifecycle{
		Plan:  planPersonal,
		State: stateSleeping,
	})
	_ = os.WriteFile(filepath.Join(home, "pens", "sleeppen", ".sleeping"), nil, 0o600)
	wakeKey := setupPen("wakepen", &penLifecycle{
		Plan:           planPersonal,
		State:          stateRenewOnly,
		SubscriptionID: "sub_wake_1",
	})
	_ = os.WriteFile(filepath.Join(home, "pens", "wakepen", ".renew-wake"), nil, 0o600)

	// Verify syncAllRegistrarHostMeta writes host-meta.json for active, grace, and renew_only pens.
	b.syncAllRegistrarHostMeta()
	if raw, err := os.ReadFile(b.registrarHostMetaPath("paidpen")); err != nil || !strings.Contains(string(raw), `"has_subscription": true`) || !strings.Contains(string(raw), `"delete_url": "https://get.example.com"`) {
		t.Fatalf("paidpen host-meta.json unexpected: err=%v raw=%s", err, raw)
	}
	if raw, err := os.ReadFile(b.registrarHostMetaPath("freepen")); err != nil || strings.Contains(string(raw), `"has_subscription": true`) || !strings.Contains(string(raw), `"delete_url": "https://get.example.com"`) {
		t.Fatalf("freepen host-meta.json unexpected: err=%v raw=%s", err, raw)
	}

	var cancelMu sync.Mutex
	var cancelledSubs []string
	bsrv := httptest.NewServer(b.handler())
	defer bsrv.Close()

	wb := newWeb(bsrv.URL, testToken, "gate.example.com")
	wb.deletes = newLimiter(50, time.Hour)
	wb.stripe = &stripeCheckout{
		publicURL: "https://get.example.com",
		cancelSubFn: func(_ context.Context, subID string) error {
			if subID == "sub_fail_cancel" {
				return errors.New("stripe 500 boom")
			}
			cancelMu.Lock()
			cancelledSubs = append(cancelledSubs, subID)
			cancelMu.Unlock()
			return nil
		},
	}
	wh := wb.handler()

	postDelete := func(tok, ip string) (int, map[string]any) {
		body, _ := json.Marshal(map[string]string{"token": tok})
		req := httptest.NewRequest("POST", "https://get.example.com/api/delete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://get.example.com")
		req.Header.Set("X-Forwarded-For", ip)
		rr := httptest.NewRecorder()
		wh.ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	exp := now.Add(15 * time.Minute).Unix()

	// 1. Security rejections: renew token, tampered sig, expired, admin role, sleeping pen.
	renewTok := makeTestSignedToken(paidKey, renewTokenPurpose, "paidpen", "alice", "owner", exp, "aaaaaaaaaaaaaaaa")
	if code, _ := postDelete(renewTok, "198.51.100.1"); code != 403 {
		t.Fatalf("renew token accepted as delete token: %d", code)
	}
	expiredTok := makeTestSignedToken(paidKey, deleteTokenPurpose, "paidpen", "alice", "owner", now.Add(-time.Minute).Unix(), "bbbbbbbbbbbbbbbb")
	if code, _ := postDelete(expiredTok, "198.51.100.1"); code != 403 {
		t.Fatalf("expired delete token = %d, want 403", code)
	}
	adminTok := makeTestSignedToken(paidKey, deleteTokenPurpose, "paidpen", "dan", "owner", exp, "cccccccccccccccc")
	if code, _ := postDelete(adminTok, "198.51.100.1"); code != 403 {
		t.Fatalf("admin masquerading as owner = %d, want 403", code)
	}
	sleepTok := makeTestSignedToken(sleepKey, deleteTokenPurpose, "sleeppen", "alice", "owner", exp, "dddddddddddddddd")
	if code, _ := postDelete(sleepTok, "198.51.100.1"); code != 409 {
		t.Fatalf("sleeping pen delete = %d, want 409", code)
	}

	// 2. Billing-first invariant: if Stripe cancel fails, purge MUST NOT run and pen stays intact.
	failCancelTok := makeTestSignedToken(failCancelKey, deleteTokenPurpose, "failcancel", "alice", "owner", exp, "eeeeeeeeeeeeeeee")
	if code, out := postDelete(failCancelTok, "198.51.100.2"); code != 502 {
		t.Fatalf("stripe cancel failure = %d (%v), want 502", code, out)
	}
	if _, err := os.Stat(filepath.Join(home, "pens", "failcancel", ".retired")); !os.IsNotExist(err) {
		t.Fatal("failcancel pen must NOT be purged when Stripe cancel fails")
	}

	// 3. Paid pen happy path: cancels BOTH active sub + pending cancel sub, purges, marks deleted, frees slot.
	paidTok := makeTestSignedToken(paidKey, deleteTokenPurpose, "paidpen", "alice", "owner", exp, "1111111111111111")
	code, out := postDelete(paidTok, "198.51.100.3")
	if code != 200 || out["ok"] != true || out["pen"] != "paidpen" || out["had_subscription"] != true {
		t.Fatalf("paidpen delete = %d %v", code, out)
	}
	cancelMu.Lock()
	gotCancelled := append([]string(nil), cancelledSubs...)
	cancelMu.Unlock()
	if !strings.Contains(strings.Join(gotCancelled, ","), "sub_live_1") || !strings.Contains(strings.Join(gotCancelled, ","), "sub_old_replaced") {
		t.Fatalf("expected both subs cancelled, got %v", gotCancelled)
	}
	if raw, err := os.ReadFile(filepath.Join(home, "pens", "paidpen", ".retired")); err != nil || !strings.Contains(string(raw), "deleted_at=") {
		t.Fatalf("paidpen .retired missing deleted_at: err=%v raw=%s", err, raw)
	}
	if rec, err := loadPenLifecycle(b.lifecyclePath("paidpen")); err != nil || rec.State != stateDeleted || rec.CancelledAt == 0 {
		t.Fatalf("paidpen lifecycle after delete: err=%v rec=%+v", err, rec)
	}
	// Replaying the same delete token is refused (403/409).
	if code, _ := postDelete(paidTok, "198.51.100.3"); code != 403 && code != 409 {
		t.Fatalf("replay of paidTok = %d, want 403 or 409", code)
	}

	// 4. Renew-only woken pen can also be deleted from portal.
	wakeTok := makeTestSignedToken(wakeKey, deleteTokenPurpose, "wakepen", "alice", "owner", exp, "2222222222222222")
	if code, out := postDelete(wakeTok, "198.51.100.3"); code != 200 || out["had_subscription"] != true {
		t.Fatalf("wakepen (renew_only) delete = %d %v", code, out)
	}

	// 5. Free pen (no lifecycle.json, no Stripe sub) purges cleanly without calling Stripe.
	freeTok := makeTestSignedToken(freeKey, deleteTokenPurpose, "freepen", "alice", "owner", exp, "3333333333333333")
	code, out = postDelete(freeTok, "198.51.100.4")
	if code != 200 || out["ok"] != true || out["had_subscription"] != false {
		t.Fatalf("freepen delete = %d %v", code, out)
	}
	if _, err := os.Stat(filepath.Join(home, "pens", "freepen", ".retired")); err != nil {
		t.Fatalf("freepen not retired: %v", err)
	}

	// 6. Partial failure after Stripe cancel succeeds: returns 500 with billing_cancelled=true,
	//    pen_removed=false, leaves pen intact with CancelledAt recorded, and alerts operator via ntfy.
	failPurgeTok := makeTestSignedToken(failPurgeKey, deleteTokenPurpose, "failpurge", "alice", "owner", exp, "4444444444444444")
	code, out = postDelete(failPurgeTok, "198.51.100.5")
	if code != 500 || out["billing_cancelled"] != true || out["pen_removed"] != false {
		t.Fatalf("partial failure = %d %v, want 500 billing_cancelled=true pen_removed=false", code, out)
	}
	if errMsg, _ := out["error"].(string); !strings.Contains(errMsg, "cancelled") || !strings.Contains(errMsg, "intact") {
		t.Fatalf("partial failure message unclear: %q", errMsg)
	}
	if _, err := os.Stat(filepath.Join(home, "pens", "failpurge", ".retired")); !os.IsNotExist(err) {
		t.Fatal("failpurge pen must remain intact on purge failure")
	}
	if rec, err := loadPenLifecycle(b.lifecyclePath("failpurge")); err != nil || rec.CancelledAt == 0 || rec.State != stateActive {
		t.Fatalf("failpurge lifecycle should record CancelledAt and stay active for normal lifecycle: err=%v rec=%+v", err, rec)
	}
	if !hasAlert("failpurge") || !hasAlert("Stripe subscription cancelled") {
		t.Fatalf("expected operator ntfy alert on partial failure, got alerts=%v", alerts)
	}

	// 7. Broker-enforced billing-first guard: direct /pen-delete/commit MUST refuse (409)
	//    and leave the pen intact unless EVERY subscription ID recorded at /pen-delete/prepare
	//    is present in cancelled_subs.
	owners["unconfirmed:alice"] = "owner"
	unconfKey := setupPen("unconfirmed", &penLifecycle{
		Plan:           planPersonal,
		State:          stateActive,
		PaidUntil:      now.Add(180 * 24 * time.Hour).Unix(),
		SubscriptionID: "sub_req_1",
		PendingCancelSubs: []pendingCancelSub{
			{SubscriptionID: "sub_req_2"},
		},
	})
	unconfTok := makeTestSignedToken(unconfKey, deleteTokenPurpose, "unconfirmed", "alice", "owner", exp, "5555555555555555")
	brokerCall := func(path string, payload any) (int, map[string]any) {
		raw, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", bsrv.URL+path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	pcode, pout := brokerCall("/pen-delete/prepare", map[string]string{"token": unconfTok})
	if pcode != 200 {
		t.Fatalf("prepare unconfirmed = %d %v", pcode, pout)
	}
	unconfNonce, _ := pout["delete_nonce"].(string)
	// Empty cancelled_subs -> 409, no purge.
	if ccode, cout := brokerCall("/pen-delete/commit", map[string]any{"pen": "unconfirmed", "delete_nonce": unconfNonce}); ccode != 409 {
		t.Fatalf("commit with empty cancelled_subs = %d (%v), want 409", ccode, cout)
	}
	if _, err := os.Stat(filepath.Join(home, "pens", "unconfirmed", ".retired")); !os.IsNotExist(err) {
		t.Fatal("unconfirmed pen must NOT be purged when cancelled_subs is empty")
	}
	// Partial cancelled_subs (missing sub_req_2) -> 409, no purge.
	if ccode, cout := brokerCall("/pen-delete/commit", map[string]any{
		"pen": "unconfirmed", "delete_nonce": unconfNonce, "cancelled_subs": []string{"sub_req_1"},
	}); ccode != 409 {
		t.Fatalf("commit with partial cancelled_subs = %d (%v), want 409", ccode, cout)
	}
	if _, err := os.Stat(filepath.Join(home, "pens", "unconfirmed", ".retired")); !os.IsNotExist(err) {
		t.Fatal("unconfirmed pen must NOT be purged when cancelled_subs is incomplete")
	}
	// All required subs confirmed -> 200 and purged.
	if ccode, cout := brokerCall("/pen-delete/commit", map[string]any{
		"pen": "unconfirmed", "delete_nonce": unconfNonce, "cancelled_subs": []string{"sub_req_1", "sub_req_2"},
	}); ccode != 200 || cout["ok"] != true {
		t.Fatalf("commit with all required cancelled_subs = %d %v, want 200", ccode, cout)
	}
	if _, err := os.Stat(filepath.Join(home, "pens", "unconfirmed", ".retired")); err != nil {
		t.Fatalf("unconfirmed pen should be retired after full confirmation: %v", err)
	}

	// 8. Per-IP rate limiting on POST /api/delete.
	wb.deletes = newLimiter(2, time.Hour)
	for i := 0; i < 2; i++ {
		_, _ = postDelete("not-a-valid-token-at-all-1234567890", "198.51.100.99")
	}
	if code, _ := postDelete("not-a-valid-token-at-all-1234567890", "198.51.100.99"); code != 429 {
		t.Fatalf("3rd /api/delete from same IP = %d, want 429", code)
	}
}

// TestHogmanHostPurgeOwnerDeleteWritesDeletedAt verifies the real deploy/hogman-host
// `purge --owner-delete` path writes deleted_at= in .retired (D-37), refuses sleeping
// pens without .renew-wake, refuses --yes, and refuses combining mode flags.
func TestHogmanHostPurgeOwnerDeleteWritesDeletedAt(t *testing.T) {
	home := t.TempDir()
	binDir := t.TempDir()
	// Minimal stub docker binary so cmd_purge can run without Docker daemon.
	if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	hostEnv := "PENS_DOMAIN=pens.example.test\nSITES_DOMAIN=pens.example.test\nACME_EMAIL=ops@example.test\nMAX_PENS=4\n"
	if err := os.WriteFile(filepath.Join(home, "host.env"), []byte(hostEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "front"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "pens"), 0o700); err != nil {
		t.Fatal(err)
	}

	hostScript, err := filepath.Abs("../hogman-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hostScript); err != nil {
		t.Skip("deploy/hogman-host not found")
	}

	makePen := func(name string) string {
		p := filepath.Join(home, "pens", name)
		_ = os.MkdirAll(filepath.Join(p, "data", "registrar"), 0o700)
		_ = os.WriteFile(filepath.Join(p, ".env"), []byte("PUBLIC_HOST="+name+".gate.example.test\nSTUN_PORT=3478\n"), 0o600)
		_ = os.WriteFile(filepath.Join(p, "hogman"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
		return p
	}

	activeDir := makePen("activepen")
	sleepDir := makePen("sleeppen")
	_ = os.WriteFile(filepath.Join(sleepDir, ".sleeping"), nil, 0o600)

	runHost := func(args ...string) (string, error) {
		cmd := exec.Command("bash", append([]string{hostScript}, args...)...)
		cmd.Env = append(os.Environ(),
			"HOGMAN_HOME="+home,
			"PATH="+binDir+":"+os.Getenv("PATH"),
		)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// --yes remains refused.
	if out, err := runHost("purge", "--yes", "activepen"); err == nil || !strings.Contains(out, "cannot be bypassed") {
		t.Fatalf("purge --yes should fail: err=%v out=%s", err, out)
	}
	// Combining --owner-delete and --due is refused.
	if out, err := runHost("purge", "--owner-delete", "--due", "activepen"); err == nil {
		t.Fatalf("combining --owner-delete --due should fail: out=%s", out)
	}
	// Sleeping pen without .renew-wake is refused.
	if out, err := runHost("purge", "--owner-delete", "sleeppen"); err == nil || !strings.Contains(out, "sleeping pen") {
		t.Fatalf("purge --owner-delete on sleeping pen should fail: err=%v out=%s", err, out)
	}

	// Active pen succeeds, removes data/.env, and writes deleted_at= in .retired.
	if out, err := runHost("purge", "--owner-delete", "activepen"); err != nil {
		t.Fatalf("purge --owner-delete activepen failed: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(activeDir, ".retired"))
	if err != nil {
		t.Fatalf("missing .retired: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "deleted_at=") {
		t.Fatalf(".retired missing deleted_at=: %q", string(raw))
	}
	if _, err := os.Stat(filepath.Join(activeDir, ".removed")); err != nil {
		t.Fatalf("missing .removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(activeDir, "data")); !os.IsNotExist(err) {
		t.Fatal("data/ should have been removed")
	}
}
