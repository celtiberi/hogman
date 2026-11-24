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
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Pen lifecycle state machine (D-35):
//
//   Paid pen (personal $50/yr, work $120/yr):
//     active   --(now >= paid_until [+ 3d auto-renew buffer if sub active])-->
//       grace  (30 full days from the moment grace becomes visible; all-member banner in /api/me)
//     grace    --(now >= grace_until)-->
//       sleeping (stopped, no slot used, state kept for 1 year)
//     sleeping --(now >= delete_after)-->
//       deleted  (final backup if configured, state purged, name stays retired per D-21)
//
//   Renewal starts a fresh 365-day year from the day of payment by default
//   (no backdating, D-35). The backdating toggle defaults to off.
//   Free pens ($0) are best-effort and never enter paid grace automatically.

const (
	planFree = "free"

	stateActive    = "active"
	stateGrace     = "grace"
	stateSleeping  = "sleeping"
	stateRenewOnly = "renew_only"
	stateDeleted   = "deleted"

	lifecycleGraceDuration        = 30 * 24 * time.Hour
	lifecycleSleepDuration        = 365 * 24 * time.Hour
	lifecycleYearDuration         = 365 * 24 * time.Hour
	lifecycleAutoRenewBuffer      = 3 * 24 * time.Hour // leap year + Stripe invoice finalisation grace
	lifecyclePreAlertLead         = 30 * 24 * time.Hour
	lifecycleFinalLead            = 7 * 24 * time.Hour
	maxAppliedEvents              = 50
	renewWakeWindow               = 10 * time.Minute
	renewWakeCeiling              = 20 * time.Minute
	renewWakeMaxPerDay            = 3
	renewWakeMaxPerMonth          = 10
	renewWakeDefaultMaxConcurrent = 2
	renewWakeDefaultReserve       = 2
	renewWakeHistoryTTL           = 30 * 24 * time.Hour
	renewWakeGlobalCapAlertAfter  = 5 * time.Minute
)

var errNoLifecycle = errors.New("pen has no lifecycle.json")

const (
	renewTokenPurpose    = "hogman-renew-v1:"
	renewTokenMaxTTL     = 20 * time.Minute
	renewNonceRetainTTL  = 24 * time.Hour // matches Stripe Checkout session max lifetime
	cancelAlertCooldown  = 24 * time.Hour
	replacedSubRetainTTL = 90 * 24 * time.Hour
)

type pendingCancelSub struct {
	SubscriptionID string `json:"subscription_id"`
	Attempts       int    `json:"attempts,omitempty"`
	NextAttemptAt  int64  `json:"next_attempt_at,omitempty"`
	LastAlertAt    int64  `json:"last_alert_at,omitempty"`
	LastError      string `json:"last_error,omitempty"`
}

func cancelRetryBackoff(attempts int) time.Duration {
	switch {
	case attempts <= 1:
		return 5 * time.Minute
	case attempts == 2:
		return 15 * time.Minute
	case attempts == 3:
		return time.Hour
	case attempts == 4:
		return 6 * time.Hour
	default:
		return 24 * time.Hour
	}
}

type renewNonceRecord struct {
	Handle    string `json:"handle"`
	Exp       int64  `json:"exp"`
	RetainExp int64  `json:"retain_exp"`
	Consumed  bool   `json:"consumed,omitempty"`
}

type penLifecycle struct {
	Plan                string                      `json:"plan"` // "free" | "personal" | "work"
	State               string                      `json:"state"`
	PaidUntil           int64                       `json:"paid_until,omitempty"`
	GraceUntil          int64                       `json:"grace_until,omitempty"`
	SleepSince          int64                       `json:"sleep_since,omitempty"`
	DeleteAfter         int64                       `json:"delete_after,omitempty"`
	WakeStartedAt       int64                       `json:"wake_started_at,omitempty"`
	WakeReadyAt         int64                       `json:"wake_ready_at,omitempty"`
	WakeUntil           int64                       `json:"wake_until,omitempty"`
	WakeCeiling         int64                       `json:"wake_ceiling,omitempty"`
	WakeHistory         []int64                     `json:"wake_history,omitempty"`
	SubscriptionID      string                      `json:"subscription_id,omitempty"`
	CustomerID          string                      `json:"customer_id,omitempty"`
	CancelledAt         int64                       `json:"cancelled_at,omitempty"`
	BackdateRenewal     bool                        `json:"backdate_renewal"` // D-35 default: false
	PendingWake         bool                        `json:"pending_wake,omitempty"`
	PendingWakeAttempts int                         `json:"pending_wake_attempts,omitempty"`
	PendingWakeNextAt   int64                       `json:"pending_wake_next_at,omitempty"`
	PendingOwner        string                      `json:"pending_owner,omitempty"`
	PendingCancelSubs   []pendingCancelSub          `json:"pending_cancel_subs,omitempty"` // I-6: replaced Stripe sub IDs awaiting cancel by web
	ReplacedSubs        map[string]int64            `json:"replaced_subs,omitempty"`       // I-6: recently replaced sub IDs -> replaced_at unix (for double-charge invoice alerts)
	AppliedEvents       []string                    `json:"applied_events,omitempty"`
	RenewNonces         map[string]renewNonceRecord `json:"renew_nonces,omitempty"` // broker-verified nonces; pruned by RetainExp
	AlertEmails         []string                    `json:"alert_emails,omitempty"`
	AlertsSent          map[string]int64            `json:"alerts_sent,omitempty"`
	RenewURL            string                      `json:"renew_url,omitempty"`
	UpdatedAt           int64                       `json:"updated_at,omitempty"`
}

type portalBillingStatus struct {
	Pen        string `json:"pen,omitempty"`
	State      string `json:"state"`
	PaidUntil  string `json:"paid_until,omitempty"`
	GraceUntil string `json:"grace_until,omitempty"`
	WakeUntil  string `json:"wake_until,omitempty"`
	RenewURL   string `json:"renew_url,omitempty"`
}

type lifecycleTransition struct {
	Pen        string `json:"pen"`
	From       string `json:"from"`
	To         string `json:"to"`
	DryRun     bool   `json:"dry_run,omitempty"`
	AlertSent  string `json:"alert_sent,omitempty"`
	Woken      bool   `json:"woken,omitempty"`
	ActionNote string `json:"note,omitempty"`
}

func (b *broker) lifecyclePath(pen string) string {
	return filepath.Join(b.home, "pens", pen, "lifecycle.json")
}

// registrarBillingPath is mounted inside the registrar container as
// /var/lib/registrar/billing-status.json and served to members via GET /api/me.
func (b *broker) registrarBillingPath(pen string) string {
	return filepath.Join(b.home, "pens", pen, "data", "registrar", "billing-status.json")
}

// renewKeyPath is the per-pen 256-bit HMAC key written by registrar (0600) and
// read by broker to verify short-lived in-pen renewal tokens. Never served.
func (b *broker) renewKeyPath(pen string) string {
	return filepath.Join(b.home, "pens", pen, "data", "registrar", "renew.key")
}

// renewOriginForPen returns the HTTPS origin of the signup host for this pen's
// plan (no pen name or secret in URL; registrar appends /#renew=<signed-token>).
func (b *broker) renewOriginForPen(plan string) string {
	base := strings.TrimRight(strings.TrimSpace(b.publicURL), "/")
	if plan == planWork {
		if wh := strings.TrimSpace(b.workSignupHost); wh != "" {
			base = "https://" + strings.TrimPrefix(strings.TrimPrefix(wh, "https://"), "http://")
		}
	}
	u, err := url.Parse(sanitizeHTTPSURL(base))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return "https://" + u.Host
}

func hasAppliedEvent(rec penLifecycle, eventID string) bool {
	if eventID == "" {
		return false
	}
	for _, id := range rec.AppliedEvents {
		if id == eventID {
			return true
		}
	}
	return false
}

func recordAppliedEvent(rec *penLifecycle, eventID string) {
	if eventID == "" || hasAppliedEvent(*rec, eventID) {
		return
	}
	rec.AppliedEvents = append(rec.AppliedEvents, eventID)
	if len(rec.AppliedEvents) > maxAppliedEvents {
		rec.AppliedEvents = rec.AppliedEvents[len(rec.AppliedEvents)-maxAppliedEvents:]
	}
}

// withPenLifecycleFileLock takes an exclusive POSIX advisory flock on
// <penDir>/.lifecycle.lock around a read-modify-write of lifecycle.json (I-12).
// Both the broker and standalone/fallback hogman-host shell commands take this
// same lock so concurrent updates never clobber each other. Callers must NEVER
// hold this lock across slow subprocesses (e.g. hogman-host sleep/wake).
func withPenLifecycleFileLock(lifecyclePath string, fn func() error) error {
	dir := filepath.Dir(lifecyclePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	lockPath := filepath.Join(dir, ".lifecycle.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func loadPenLifecycle(path string) (*penLifecycle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec penLifecycle
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	if rec.State == "" {
		rec.State = stateActive
	}
	return &rec, nil
}

func savePenLifecycle(path string, rec *penLifecycle) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".lifecycle-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func registrarRenewOnlyMarkerPath(billingPath string) string {
	if billingPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(billingPath), ".renew-only")
}

func syncRegistrarBillingBanner(pen, billingPath string, rec *penLifecycle, fallbackRenewOrigin string) error {
	markerPath := registrarRenewOnlyMarkerPath(billingPath)
	if rec.State != stateGrace && rec.State != stateRenewOnly {
		if markerPath != "" {
			if err := os.Remove(markerPath); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		err := os.Remove(billingPath)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dir := filepath.Dir(billingPath)
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		// B2: For renew_only, a missing registrar volume MUST fail closed rather
		// than silently returning nil and letting the pen wake in normal mode.
		if rec.State == stateRenewOnly {
			return fmt.Errorf("registrar data dir %s unavailable: %v", dir, err)
		}
		return nil
	}
	if rec.State == stateRenewOnly {
		if err := os.WriteFile(markerPath, []byte("renew_only\n"), 0o644); err != nil {
			return fmt.Errorf("write .renew-only marker: %w", err)
		}
	} else if markerPath != "" {
		if err := os.Remove(markerPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	renewOrigin := sanitizeHTTPSOrigin(rec.RenewURL)
	if renewOrigin == "" {
		renewOrigin = sanitizeHTTPSOrigin(fallbackRenewOrigin)
	}
	st := portalBillingStatus{
		Pen:      pen,
		State:    rec.State,
		RenewURL: renewOrigin,
	}
	if rec.PaidUntil > 0 {
		st.PaidUntil = time.Unix(rec.PaidUntil, 0).UTC().Format(time.RFC3339)
	}
	if rec.GraceUntil > 0 {
		st.GraceUntil = time.Unix(rec.GraceUntil, 0).UTC().Format(time.RFC3339)
	}
	if rec.State == stateRenewOnly {
		until := rec.WakeUntil
		if until == 0 || (rec.WakeCeiling > 0 && rec.WakeCeiling < until) {
			until = rec.WakeCeiling
		}
		if until > 0 {
			st.WakeUntil = time.Unix(until, 0).UTC().Format(time.RFC3339)
		}
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(billingPath), ".billing-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	_ = tmp.Chmod(0o644)
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, billingPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func sanitizeHTTPSURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return ""
	}
	return u.String()
}

func sanitizeHTTPSOrigin(raw string) string {
	s := sanitizeHTTPSURL(raw)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	return "https://" + u.Host
}

// evaluateLifecycle computes at most ONE D-35 lifecycle transition for rec at
// now without mutating external systems:
//   - active -> grace: waits an extra 3-day buffer while an uncancelled Stripe
//     subscription is live (avoiding false banners from leap years / invoice
//     finalisation), and always sets GraceUntil = now + 30d so members always
//     get a full 30 days of visible notice (never jumping active -> sleeping).
//   - grace -> sleeping: after GraceUntil, sets SleepSince = now, DeleteAfter = now + 365d.
//   - sleeping -> deleted: after DeleteAfter.
func evaluateLifecycle(rec penLifecycle, now time.Time) (next penLifecycle, transitioned bool) {
	next = rec
	nowUTC := now.UTC()
	nowUnix := nowUTC.Unix()
	if next.State == "" {
		next.State = stateActive
	}
	if next.State == stateDeleted {
		return next, false
	}

	// I-7 Part 2: renew_only ONLY ever transitions back to sleeping once its
	// persisted deadline (min(WakeUntil, WakeCeiling)) expires, preserving the
	// original SleepSince and DeleteAfter timestamps untouched.
	if next.State == stateRenewOnly {
		deadline := next.WakeUntil
		if deadline == 0 || (next.WakeCeiling > 0 && next.WakeCeiling < deadline) {
			deadline = next.WakeCeiling
		}
		if deadline == 0 || nowUnix >= deadline {
			next.State = stateSleeping
			next.WakeStartedAt = 0
			next.WakeReadyAt = 0
			next.WakeUntil = 0
			next.WakeCeiling = 0
			next.UpdatedAt = nowUnix
			return next, true
		}
		return next, false
	}

	if next.Plan == planPersonal || next.Plan == planWork {
		if next.State == stateActive && next.PaidUntil > 0 {
			graceStart := next.PaidUntil
			if next.SubscriptionID != "" && next.CancelledAt == 0 {
				graceStart += int64(lifecycleAutoRenewBuffer.Seconds())
			}
			if nowUnix >= graceStart {
				next.State = stateGrace
				next.GraceUntil = nowUTC.Add(lifecycleGraceDuration).Unix()
				next.UpdatedAt = nowUnix
				return next, true
			}
			return next, false
		}
		if next.State == stateGrace && next.GraceUntil > 0 && nowUnix >= next.GraceUntil {
			next.State = stateSleeping
			next.SleepSince = nowUnix
			next.DeleteAfter = nowUTC.Add(lifecycleSleepDuration).Unix()
			next.UpdatedAt = nowUnix
			return next, true
		}
	}

	if next.State == stateSleeping && next.DeleteAfter > 0 && nowUnix >= next.DeleteAfter {
		next.State = stateDeleted
		next.UpdatedAt = nowUnix
		return next, true
	}
	return next, false
}

// applyRenewal advances a pen's paid_until by one year under D-35.
//   - Early renewal (now < paid_until): extends from paid_until so no paid time is lost.
//   - Late renewal (grace or sleeping, now >= paid_until):
//   - backdate == false (D-35 default): fresh year from day of payment (now + 365d).
//   - backdate == true  (opt-in toggle): extends from old paid_until + 365d
//     (clamped to now + 365d if already more than a year past due).
func applyRenewal(rec penLifecycle, now time.Time, backdate bool) (next penLifecycle, wasSleeping bool) {
	next = rec
	wasSleeping = rec.State == stateSleeping || rec.State == stateRenewOnly
	nowUTC := now.UTC()
	nowUnix := nowUTC.Unix()

	var base time.Time
	if rec.PaidUntil > nowUnix {
		base = time.Unix(rec.PaidUntil, 0).UTC()
	} else if backdate && rec.PaidUntil > 0 {
		candidate := time.Unix(rec.PaidUntil, 0).UTC().Add(lifecycleYearDuration)
		if candidate.After(nowUTC) {
			base = time.Unix(rec.PaidUntil, 0).UTC()
		} else {
			base = nowUTC
		}
	} else {
		base = nowUTC
	}

	next.State = stateActive
	next.PaidUntil = base.Add(lifecycleYearDuration).Unix()
	next.GraceUntil = 0
	next.SleepSince = 0
	next.DeleteAfter = 0
	next.WakeStartedAt = 0
	next.WakeReadyAt = 0
	next.WakeUntil = 0
	next.WakeCeiling = 0
	next.CancelledAt = 0
	next.PendingWake = wasSleeping
	next.PendingWakeAttempts = 0
	next.PendingWakeNextAt = 0
	next.AlertsSent = nil
	next.UpdatedAt = nowUnix
	return next, wasSleeping
}

// dueBillingAlert returns the milestone key and human message for an opt-in
// owner/admin billing alert email if one is due and hasn't been sent yet.
func dueBillingAlert(pen string, rec penLifecycle, now time.Time) (milestone, subject, body string, due bool) {
	if len(rec.AlertEmails) == 0 || (rec.Plan != planPersonal && rec.Plan != planWork) {
		return "", "", "", false
	}
	sent := func(k string) bool { return rec.AlertsSent != nil && rec.AlertsSent[k] > 0 }
	nowUnix := now.Unix()

	switch rec.State {
	case stateActive:
		if rec.PaidUntil > 0 && nowUnix >= rec.PaidUntil-int64(lifecyclePreAlertLead.Seconds()) && !sent("30d-before") {
			dueDate := time.Unix(rec.PaidUntil, 0).UTC().Format("2006-01-02")
			return "30d-before",
				fmt.Sprintf("Hogman pen %s renews on %s", pen, dueDate),
				fmt.Sprintf("Your Hogman pen (%s) is paid through %s.\nIf auto-renewal is off, any owner or admin can renew from the pen's home page before %s to avoid the 30-day grace period (an admin who pays becomes an owner).", pen, dueDate, dueDate),
				true
		}
	case stateGrace:
		// Always send grace-start before grace-day-23.
		if !sent("grace-start") {
			sleepDate := time.Unix(rec.GraceUntil, 0).UTC().Format("2006-01-02")
			return "grace-start",
				fmt.Sprintf("Hogman pen %s entered its 30-day grace period", pen),
				fmt.Sprintf("Your Hogman pen (%s) passed its paid-until date and is now in its 30-day grace period (stays awake until %s).\nAny owner or admin can renew from the pen's home page for a fresh year starting from the day of payment (an admin who pays becomes an owner).", pen, sleepDate),
				true
		}
		if rec.GraceUntil > 0 && nowUnix >= rec.GraceUntil-int64(lifecycleFinalLead.Seconds()) && !sent("grace-day-23") {
			sleepDate := time.Unix(rec.GraceUntil, 0).UTC().Format("2006-01-02")
			return "grace-day-23",
				fmt.Sprintf("Hogman pen %s goes to sleep on %s", pen, sleepDate),
				fmt.Sprintf("Your Hogman pen (%s) is in its 30-day grace period and will go to sleep on %s.\nAny owner or admin can renew from the pen's home page for a fresh year to keep it awake (an admin who pays becomes an owner).", pen, sleepDate),
				true
		}
	case stateSleeping:
		if !sent("sleeping") {
			delDate := time.Unix(rec.DeleteAfter, 0).UTC().Format("2006-01-02")
			return "sleeping",
				fmt.Sprintf("Hogman pen %s is now asleep", pen),
				fmt.Sprintf("Your Hogman pen (%s) has been put to sleep after 30 days unpaid. Its state is kept until %s; contact your host operator if an owner or admin wants to wake it for renewal.", pen, delDate),
				true
		}
	}
	return "", "", "", false
}

// sendBillingAlert returns (true, nil) only when an email was actually sent;
// returns (false, nil) when email delivery is not configured so milestones are
// not falsely marked as sent.
func (b *broker) sendBillingAlert(ctx context.Context, to []string, subject, text string) (bool, error) {
	if b.alertSendFn != nil {
		if err := b.alertSendFn(ctx, to, subject, text); err != nil {
			return false, err
		}
		return true, nil
	}
	if b.resendAPIKey == "" || b.billingFrom == "" {
		return false, nil
	}
	var valid []string
	for _, addr := range to {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if validEmail(addr) {
			valid = append(valid, addr)
		}
	}
	if len(valid) == 0 {
		return false, nil
	}
	payload, err := json.Marshal(map[string]any{
		"from":    b.billingFrom,
		"to":      valid,
		"subject": subject,
		"text":    text,
	})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.resend.com/emails", bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+b.resendAPIKey)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("resend returned HTTP %d", resp.StatusCode)
	}
	return true, nil
}

// initPenLifecycle writes the initial lifecycle.json when a pen is raised.
func (b *broker) initPenLifecycle(pen, plan, code string, paid bool, now time.Time) error {
	rec := &penLifecycle{
		Plan:            planFree,
		State:           stateActive,
		BackdateRenewal: b.backdateRenewal, // D-35 default: false
		UpdatedAt:       now.UTC().Unix(),
	}
	if paid {
		if plan == planWork {
			rec.Plan = planWork
		} else {
			rec.Plan = planPersonal
		}
		rec.PaidUntil = now.UTC().Add(lifecycleYearDuration).Unix()
		rec.RenewURL = b.renewOriginForPen(rec.Plan)
		if p, ok, err := b.findPaymentByCode(code); err == nil && ok {
			if p.subscription != "" && p.subscription != "-" {
				rec.SubscriptionID = p.subscription
			}
			if p.customer != "" && p.customer != "-" {
				rec.CustomerID = p.customer
			}
		}
	}
	path := b.lifecyclePath(pen)
	return withPenLifecycleFileLock(path, func() error {
		return savePenLifecycle(path, rec)
	})
}

// recordRenewal idempotently records a Stripe renewal event (invoice or checkout
// session) into lifecycle.json and clears the grace banner. If renewNonce
// matches a broker-recorded entry in RenewNonces (from /renew-verify), the
// broker-verified handle is persisted as PendingOwner so promotion survives
// broker restarts and transient wake delays (B9) without trusting web metadata.
func (b *broker) recordRenewal(pen, eventID, subID, custID, renewNonce string, now time.Time) (next *penLifecycle, alreadyApplied bool, wasSleeping bool, err error) {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

	path := b.lifecyclePath(pen)
	var updated penLifecycle
	var sleeping bool
	var backdate bool
	lockErr := withPenLifecycleFileLock(path, func() error {
		rec, lerr := loadPenLifecycle(path)
		if os.IsNotExist(lerr) {
			return errNoLifecycle
		}
		if lerr != nil {
			return lerr
		}
		if hasAppliedEvent(*rec, eventID) {
			next = rec
			alreadyApplied = true
			return nil
		}
		if rec.State == stateDeleted {
			return fmt.Errorf("pen %s has already been deleted", pen)
		}
		backdate = b.backdateRenewal || rec.BackdateRenewal
		updated, sleeping = applyRenewal(*rec, now, backdate)
		recordAppliedEvent(&updated, eventID)
		// Resolve payer handle strictly from the broker's own recorded nonce (never
		// from web-supplied Stripe metadata).
		nonce := strings.ToLower(strings.TrimSpace(renewNonce))
		if nonce != "" && updated.RenewNonces != nil {
			if nr, ok := updated.RenewNonces[nonce]; ok && !nr.Consumed && nr.Handle != "" {
				if _, valid := validHandle(nr.Handle); valid {
					updated.PendingOwner = nr.Handle
				}
				nr.Consumed = true
				updated.RenewNonces[nonce] = nr
			}
		}
		pruneRenewNonces(&updated, now.UTC().Unix())
		if subID != "" && subID != "-" {
			// I-6: if a manual renewal created a new Stripe subscription while a
			// previous still-active subscription_id existed (CancelledAt == 0),
			// queue the old one for cancellation by signup-web (which holds the
			// Stripe key) so it cannot double-charge. Already-cancelled old
			// subscriptions (CancelledAt != 0) are not queued.
			if rec.SubscriptionID != "" && rec.SubscriptionID != "-" && rec.SubscriptionID != subID {
				if updated.ReplacedSubs == nil {
					updated.ReplacedSubs = map[string]int64{}
				}
				updated.ReplacedSubs[rec.SubscriptionID] = now.UTC().Unix()
				pruneReplacedSubs(&updated, now.UTC().Unix())
				if rec.CancelledAt == 0 {
					alreadyQueued := false
					for _, q := range updated.PendingCancelSubs {
						if q.SubscriptionID == rec.SubscriptionID {
							alreadyQueued = true
							break
						}
					}
					if !alreadyQueued {
						updated.PendingCancelSubs = append(updated.PendingCancelSubs, pendingCancelSub{
							SubscriptionID: rec.SubscriptionID,
						})
					}
				}
				// The pen now has a brand-new active subscription.
				updated.CancelledAt = 0
			}
			updated.SubscriptionID = subID
		}
		if custID != "" && custID != "-" {
			updated.CustomerID = custID
		}
		if updated.RenewURL == "" {
			updated.RenewURL = b.renewOriginForPen(updated.Plan)
		}
		return savePenLifecycle(path, &updated)
	})
	if lockErr != nil {
		return nil, false, false, lockErr
	}
	if alreadyApplied {
		return next, true, false, nil
	}
	if err := syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), &updated, b.renewOriginForPen(updated.Plan)); err != nil {
		log.Printf("lifecycle %s: clear grace banner: %v", pen, err)
	}
	b.ledger(fmt.Sprintf("%s renewed %s until %s (event=%s, backdate=%v, pending_wake=%v, pending_owner=%s)",
		now.UTC().Format(time.RFC3339), pen, time.Unix(updated.PaidUntil, 0).UTC().Format("2006-01-02"), eventID, backdate, sleeping, updated.PendingOwner))
	return &updated, false, sleeping, nil
}

func pruneRenewNonces(rec *penLifecycle, nowUnix int64) {
	if len(rec.RenewNonces) == 0 {
		return
	}
	for n, nr := range rec.RenewNonces {
		exp := nr.RetainExp
		if exp == 0 {
			exp = nr.Exp
		}
		if exp < nowUnix {
			delete(rec.RenewNonces, n)
		}
	}
	if len(rec.RenewNonces) == 0 {
		rec.RenewNonces = nil
	}
}

// memberRole looks up handle's current role and status via `hogman-host pen <pen> member list`.
// Returns transient=true if the pen could not be queried (e.g. still starting after wake).
func (b *broker) memberRole(ctx context.Context, pen, handle string) (role, status string, ok bool, transient bool) {
	if b.memberRoleFn != nil {
		r, st, found := b.memberRoleFn(ctx, pen, handle)
		return r, st, found, false
	}
	out, code, _ := b.run(ctx, "pen", pen, "member", "list")
	if code != 0 {
		return "", "", false, true
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// `registrar member list` columns: ID HANDLE ROLE STATUS ...
		if len(f) >= 4 && strings.EqualFold(f[1], handle) {
			return f[2], f[3], true, false
		}
	}
	return "", "", false, false
}

func (b *broker) isPenAdminOrOwner(ctx context.Context, pen, handle string) bool {
	role, status, ok, _ := b.memberRole(ctx, pen, handle)
	return ok && (role == "admin" || role == "owner") && status == "active"
}

// applyPendingOwner promotes rec.PendingOwner to owner if they are currently an
// active admin of pen, clearing PendingOwner on success or permanent refusal,
// and keeping PendingOwner + alerting the operator on transient failures (B9).
func (b *broker) applyPendingOwner(ctx context.Context, pen, handle string) (done bool, err error) {
	h := strings.ToLower(strings.TrimSpace(handle))
	if h == "" {
		return true, nil
	}
	if _, ok := validHandle(h); !ok {
		return true, nil
	}
	role, status, found, transient := b.memberRole(ctx, pen, h)
	if transient {
		err := fmt.Errorf("member list failed while promoting %s on %s (will retry)", h, pen)
		b.notifyKind("health", fmt.Sprintf("Pen %s renewed, pending owner promotion for %s deferred: %v", pen, h, err))
		return false, err
	}
	if !found || status != "active" || (role != "admin" && role != "owner") {
		log.Printf("lifecycle %s: not promoting %q to owner (role=%q status=%q found=%v)", pen, h, role, status, found)
		return true, nil
	}
	if role == "owner" {
		return true, nil
	}
	_, code, stderr := b.runUnbounded(ctx, "pen", pen, "member", "role", h, "owner")
	if code != 0 {
		err := fmt.Errorf("promote admin %s to owner on %s failed (exit %d): %s", h, pen, code, strings.TrimSpace(stderr))
		b.notifyKind("health", fmt.Sprintf("Pen %s renewed, but promoting admin %s to owner failed: %v", pen, h, err))
		return false, err
	}
	return true, nil
}

// tryBeginWake claims the in-memory per-pen wake/sleep flight slot so two
// concurrent `hogman-host wake` or `sleep` calls (e.g. finishRenewalWork and
// the 1-minute watcher) never overlap on the same pen.
func (b *broker) tryBeginWake(pen string) bool {
	b.wakeFlightMu.Lock()
	defer b.wakeFlightMu.Unlock()
	if b.wakesInFlight == nil {
		b.wakesInFlight = map[string]bool{}
	}
	if b.wakesInFlight[pen] {
		return false
	}
	b.wakesInFlight[pen] = true
	return true
}

func (b *broker) endWake(pen string) {
	b.wakeFlightMu.Lock()
	delete(b.wakesInFlight, pen)
	b.wakeFlightMu.Unlock()
}

// pendingWakeBackoff returns the retry delay after the given number of failed
// paid-renewal wake attempts (1m -> 2m -> 5m -> 15m -> 30m -> 1h) so a full
// host does not fork `hogman-host wake` every minute.
func pendingWakeBackoff(attempts int) time.Duration {
	switch {
	case attempts <= 1:
		return time.Minute
	case attempts == 2:
		return 2 * time.Minute
	case attempts == 3:
		return 5 * time.Minute
	case attempts == 4:
		return 15 * time.Minute
	case attempts == 5:
		return 30 * time.Minute
	default:
		return time.Hour
	}
}

// finishRenewalWork executes post-webhook wake and persisted PendingOwner
// promotion (D-35, B9) outside the webhook's synchronous response path.
func (b *broker) finishRenewalWork(ctx context.Context, pen string, wake bool) error {
	path := b.lifecyclePath(pen)
	if wake {
		if !b.tryBeginWake(pen) {
			// Another wake is already in flight for this pen; PendingWake stays
			// persisted so the 1-minute watcher will retry if it did not complete.
			return nil
		}
		wakeErr := func() error {
			defer b.endWake(pen)
			_, code, stderr := b.runUnbounded(ctx, "wake", "--no-lifecycle", pen)
			b.invalidateCapacityCache()
			now := b.now().UTC()
			if code != 0 {
				err := fmt.Errorf("wake %s failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
				b.notifyKind("health", fmt.Sprintf("Pen %s was renewed and paid, but wake failed: %v", pen, err))
				b.lifecycleMu.Lock()
				_ = withPenLifecycleFileLock(path, func() error {
					if rec, lerr := loadPenLifecycle(path); lerr == nil && rec.PendingWake {
						rec.PendingWakeAttempts++
						rec.PendingWakeNextAt = now.Add(pendingWakeBackoff(rec.PendingWakeAttempts)).Unix()
						rec.UpdatedAt = now.Unix()
						return savePenLifecycle(path, rec)
					}
					return nil
				})
				b.lifecycleMu.Unlock()
				return err
			}
			b.lifecycleMu.Lock()
			var syncedRec *penLifecycle
			_ = withPenLifecycleFileLock(path, func() error {
				if rec, lerr := loadPenLifecycle(path); lerr == nil && rec.PendingWake {
					rec.PendingWake = false
					rec.PendingWakeAttempts = 0
					rec.PendingWakeNextAt = 0
					rec.UpdatedAt = now.Unix()
					if serr := savePenLifecycle(path, rec); serr != nil {
						return serr
					}
					syncedRec = rec
				}
				return nil
			})
			if syncedRec != nil {
				_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), syncedRec, b.renewOriginForPen(syncedRec.Plan))
			}
			b.lifecycleMu.Unlock()
			return nil
		}()
		if wakeErr != nil {
			return wakeErr
		}
	}

	b.lifecycleMu.Lock()
	var pendingOwner string
	if rec, err := loadPenLifecycle(path); err == nil && !rec.PendingWake {
		pendingOwner = rec.PendingOwner
	}
	b.lifecycleMu.Unlock()
	if pendingOwner == "" {
		return nil
	}
	done, err := b.applyPendingOwner(ctx, pen, pendingOwner)
	if done {
		b.lifecycleMu.Lock()
		_ = withPenLifecycleFileLock(path, func() error {
			if rec, lerr := loadPenLifecycle(path); lerr == nil && rec.PendingOwner == pendingOwner {
				rec.PendingOwner = ""
				rec.UpdatedAt = b.now().UTC().Unix()
				return savePenLifecycle(path, rec)
			}
			return nil
		})
		b.lifecycleMu.Unlock()
	}
	return err
}

// findPenBySubscription locates a pen whose lifecycle.json matches subID.
func (b *broker) findPenBySubscription(subID string) (string, bool) {
	if subID == "" || subID == "-" {
		return "", false
	}
	entries, err := os.ReadDir(filepath.Join(b.home, "pens"))
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rec, err := loadPenLifecycle(b.lifecyclePath(e.Name()))
		if err != nil {
			continue
		}
		if rec.SubscriptionID == subID {
			return e.Name(), true
		}
	}
	return "", false
}

// sweepLifecycles evaluates every pen's lifecycle.json at now, retries any
// PendingWake, applies at most one D-35 transition per pen, and sends due
// opt-in alerts. Uses lifecycleMu (never b.mu) so signups/webhooks stay unblocked.
func (b *broker) sweepLifecycles(ctx context.Context, now time.Time, dryRun bool) ([]lifecycleTransition, error) {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

	pensDir := filepath.Join(b.home, "pens")
	entries, err := os.ReadDir(pensDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var out []lifecycleTransition
	for _, pen := range names {
		path := b.lifecyclePath(pen)
		rec, err := loadPenLifecycle(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			log.Printf("lifecycle %s: unreadable lifecycle.json: %v", pen, err)
			continue
		}

		// Retry any pending wake from a previously applied renewal.
		if rec.State == stateActive && rec.PendingWake {
			tr := lifecycleTransition{Pen: pen, From: stateSleeping, To: stateActive, DryRun: dryRun, Woken: true}
			if !dryRun {
				if !b.tryBeginWake(pen) {
					continue
				}
				func() {
					defer b.endWake(pen)
					_, code, stderr := b.runUnbounded(ctx, "wake", "--no-lifecycle", pen)
					b.invalidateCapacityCache()
					if code != 0 {
						log.Printf("lifecycle %s: retry wake failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
						b.notifyKind("health", fmt.Sprintf("Pen %s paid renewal wake retry failed (exit %d): %s", pen, code, strings.TrimSpace(stderr)))
						_ = withPenLifecycleFileLock(path, func() error {
							cur, cerr := loadPenLifecycle(path)
							if cerr != nil {
								return cerr
							}
							cur.PendingWakeAttempts++
							cur.PendingWakeNextAt = now.UTC().Add(pendingWakeBackoff(cur.PendingWakeAttempts)).Unix()
							cur.UpdatedAt = now.UTC().Unix()
							rec = cur
							return savePenLifecycle(path, cur)
						})
						tr.Woken = false
						tr.ActionNote = "wake retry failed"
					} else {
						_ = withPenLifecycleFileLock(path, func() error {
							cur, cerr := loadPenLifecycle(path)
							if cerr != nil {
								return cerr
							}
							cur.PendingWake = false
							cur.PendingWakeAttempts = 0
							cur.PendingWakeNextAt = 0
							cur.UpdatedAt = now.UTC().Unix()
							rec = cur
							return savePenLifecycle(path, cur)
						})
						_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), rec, b.renewOriginForPen(rec.Plan))
					}
				}()
			}
			out = append(out, tr)
			if rec.PendingWake {
				continue
			}
		}

		// B9: Retry any pending admin-to-owner promotion persisted from a verified renewal.
		if rec.State == stateActive && !rec.PendingWake && rec.PendingOwner != "" {
			tr := lifecycleTransition{Pen: pen, From: stateActive, To: stateActive, DryRun: dryRun, ActionNote: "promote:" + rec.PendingOwner}
			if !dryRun {
				done, perr := b.applyPendingOwner(ctx, pen, rec.PendingOwner)
				if perr != nil {
					log.Printf("lifecycle %s: retry pending_owner %s: %v", pen, rec.PendingOwner, perr)
					tr.ActionNote = "promote_retry_failed:" + rec.PendingOwner
				}
				if done {
					_ = withPenLifecycleFileLock(path, func() error {
						cur, cerr := loadPenLifecycle(path)
						if cerr != nil {
							return cerr
						}
						cur.PendingOwner = ""
						cur.UpdatedAt = now.UTC().Unix()
						rec = cur
						return savePenLifecycle(path, cur)
					})
				}
			}
			out = append(out, tr)
		}

		next, changed := evaluateLifecycle(*rec, now)
		if next.RenewURL == "" && (next.Plan == planPersonal || next.Plan == planWork) {
			next.RenewURL = b.renewOriginForPen(next.Plan)
		}
		tr := lifecycleTransition{Pen: pen, From: rec.State, To: next.State, DryRun: dryRun}

		if changed {
			if !dryRun {
				switch next.State {
				case stateGrace:
					if err := withPenLifecycleFileLock(path, func() error { return savePenLifecycle(path, &next) }); err != nil {
						log.Printf("lifecycle %s: save grace: %v", pen, err)
						continue
					}
					if err := syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), &next, b.renewOriginForPen(next.Plan)); err != nil {
						log.Printf("lifecycle %s: write grace banner: %v", pen, err)
					}
					b.ledger(fmt.Sprintf("%s lifecycle %s: active -> grace (until %s)",
						now.UTC().Format(time.RFC3339), pen, time.Unix(next.GraceUntil, 0).UTC().Format("2006-01-02")))
				case stateSleeping:
					_, code, stderr := b.runUnbounded(ctx, "sleep", "--no-lifecycle", pen)
					b.invalidateCapacityCache()
					if code != 0 {
						log.Printf("lifecycle %s: sleep failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
						continue
					}
					if err := withPenLifecycleFileLock(path, func() error { return savePenLifecycle(path, &next) }); err != nil {
						log.Printf("lifecycle %s: save sleeping: %v", pen, err)
						continue
					}
					_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), &next, "")
					b.ledger(fmt.Sprintf("%s lifecycle %s: %s -> sleeping (delete after %s)",
						now.UTC().Format(time.RFC3339), pen, rec.State, time.Unix(next.DeleteAfter, 0).UTC().Format("2006-01-02")))
				case stateDeleted:
					_, code, stderr := b.runUnbounded(ctx, "purge", "--due", pen)
					b.invalidateCapacityCache()
					if code != 0 {
						log.Printf("lifecycle %s: purge --due failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
						continue
					}
					if err := withPenLifecycleFileLock(path, func() error { return savePenLifecycle(path, &next) }); err != nil {
						log.Printf("lifecycle %s: save deleted: %v", pen, err)
					}
					b.ledger(fmt.Sprintf("%s lifecycle %s: sleeping -> deleted (name stays retired per D-21)",
						now.UTC().Format(time.RFC3339), pen))
				}
			}
			out = append(out, tr)
		}

		if milestone, subj, body, due := dueBillingAlert(pen, next, now); due {
			sent := false
			if !dryRun {
				var serr error
				sent, serr = b.sendBillingAlert(ctx, next.AlertEmails, subj, body)
				if serr != nil {
					log.Printf("lifecycle %s: send alert %s: %v", pen, milestone, serr)
				} else if sent {
					_ = withPenLifecycleFileLock(path, func() error {
						cur, cerr := loadPenLifecycle(path)
						if cerr != nil {
							cur = &next
						}
						if cur.AlertsSent == nil {
							cur.AlertsSent = map[string]int64{}
						}
						cur.AlertsSent[milestone] = now.UTC().Unix()
						next = *cur
						return savePenLifecycle(path, cur)
					})
				}
			} else {
				sent = true
			}
			if sent {
				if !changed {
					out = append(out, lifecycleTransition{Pen: pen, From: rec.State, To: next.State, DryRun: dryRun, AlertSent: milestone})
				} else {
					out[len(out)-1].AlertSent = milestone
				}
			}
		}
	}
	return out, nil
}

func (b *broker) lifecycleSweepHandler(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "1" || r.URL.Query().Get("dry_run") == "true"
	transitions, err := b.sweepLifecycles(r.Context(), time.Now().UTC(), dryRun)
	if err != nil {
		log.Printf("lifecycle sweep: %v", err)
		jsonOut(w, 500, map[string]string{"error": "lifecycle sweep failed"})
		return
	}
	if transitions == nil {
		transitions = []lifecycleTransition{}
	}
	jsonOut(w, 200, map[string]any{"dry_run": dryRun, "transitions": transitions})
}

type verifiedRenewToken struct {
	Pen    string
	Handle string
	Role   string
	Exp    int64
	Nonce  string
}

func (b *broker) verifyRenewToken(raw string, now time.Time) (*verifiedRenewToken, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 20 || len(raw) > 512 {
		return nil, errors.New("invalid renewal token")
	}
	payloadB64, sigB64, ok := strings.Cut(raw, ".")
	if !ok || payloadB64 == "" || sigB64 == "" || strings.Contains(sigB64, ".") {
		return nil, errors.New("invalid renewal token")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, errors.New("invalid renewal token")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sigBytes) != sha256.Size {
		return nil, errors.New("invalid renewal token")
	}
	parts := strings.Split(string(payloadBytes), "|")
	if len(parts) != 6 || parts[0] != "v1" {
		return nil, errors.New("invalid renewal token")
	}
	pen := strings.ToLower(strings.TrimSpace(parts[1]))
	handle := strings.ToLower(strings.TrimSpace(parts[2]))
	role := strings.ToLower(strings.TrimSpace(parts[3]))
	exp, err := strconv.ParseInt(parts[4], 10, 64)
	nonce := strings.ToLower(strings.TrimSpace(parts[5]))
	if _, ok := validPen(pen); !ok {
		return nil, errors.New("invalid renewal token")
	}
	if _, ok := validHandle(handle); !ok {
		return nil, errors.New("invalid renewal token")
	}
	if role != "owner" && role != "admin" {
		return nil, errors.New("invalid renewal token")
	}
	if len(nonce) < 16 || len(nonce) > 64 {
		return nil, errors.New("invalid renewal token")
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return nil, errors.New("invalid renewal token")
	}
	nowUnix := now.UTC().Unix()
	if err != nil || exp < nowUnix || exp > now.UTC().Add(renewTokenMaxTTL).Unix() {
		return nil, errors.New("renewal link expired; open your pen's home page and click Renew now again")
	}

	// Verify HMAC against this pen's own 0600 key with fixed purpose prefix.
	rawKey, err := os.ReadFile(b.renewKeyPath(pen))
	if err != nil {
		return nil, errors.New("invalid renewal token")
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(rawKey)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid renewal token")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(renewTokenPurpose))
	mac.Write([]byte(payloadB64))
	if !hmac.Equal(mac.Sum(nil), sigBytes) {
		return nil, errors.New("invalid renewal token")
	}
	return &verifiedRenewToken{Pen: pen, Handle: handle, Role: role, Exp: exp, Nonce: nonce}, nil
}

// renewVerify authenticates a short-lived, single-use signed renewal token
// minted inside the pen by an active owner or admin (D-35), marks its nonce
// consumed BEFORE Stripe Checkout creation, and returns the authoritative
// {pen, plan, payer_handle} so signup-web never trusts browser-supplied fields.
func (b *broker) renewVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	now := time.Now().UTC()
	tok, err := b.verifyRenewToken(in.Token, now)
	if err != nil {
		jsonOut(w, 403, map[string]string{"error": err.Error()})
		return
	}

	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

	path := b.lifecyclePath(tok.Pen)
	rec, err := loadPenLifecycle(path)
	if err != nil || rec.State == stateDeleted || (rec.Plan != planPersonal && rec.Plan != planWork) {
		jsonOut(w, 403, map[string]string{"error": "invalid renewal token"})
		return
	}
	if rec.State != stateGrace && rec.State != stateSleeping && rec.State != stateRenewOnly {
		jsonOut(w, 409, map[string]string{"error": "this pen is already paid and active"})
		return
	}
	// Prune expired nonces (keep-less-data) and reject replay.
	nowUnix := now.Unix()
	pruneRenewNonces(rec, nowUnix)
	if rec.RenewNonces == nil {
		rec.RenewNonces = map[string]renewNonceRecord{}
	}
	if _, used := rec.RenewNonces[tok.Nonce]; used {
		jsonOut(w, 403, map[string]string{"error": "this renewal link was already used; click Renew now inside your pen for a fresh link"})
		return
	}
	// Verify caller is still an active owner or admin of this pen.
	if !b.isPenAdminOrOwner(r.Context(), tok.Pen, tok.Handle) {
		jsonOut(w, 403, map[string]string{"error": "only active owners or admins can renew this pen"})
		return
	}
	// Mark nonce used and bind the broker-verified handle BEFORE Checkout creation
	// so neither replay nor a compromised signup-web can forge payer identity.
	var replayErr bool
	if err := withPenLifecycleFileLock(path, func() error {
		cur, lerr := loadPenLifecycle(path)
		if lerr != nil {
			return lerr
		}
		pruneRenewNonces(cur, nowUnix)
		if cur.RenewNonces == nil {
			cur.RenewNonces = map[string]renewNonceRecord{}
		}
		if _, used := cur.RenewNonces[tok.Nonce]; used {
			replayErr = true
			return nil
		}
		cur.RenewNonces[tok.Nonce] = renewNonceRecord{
			Handle:    tok.Handle,
			Exp:       tok.Exp,
			RetainExp: now.Add(renewNonceRetainTTL).Unix(),
		}
		cur.UpdatedAt = nowUnix
		rec = cur
		return savePenLifecycle(path, cur)
	}); err != nil {
		log.Printf("lifecycle %s: save used renew nonce: %v", tok.Pen, err)
		jsonOut(w, 500, map[string]string{"error": "could not process renewal right now"})
		return
	}
	if replayErr {
		jsonOut(w, 403, map[string]string{"error": "this renewal link was already used; click Renew now inside your pen for a fresh link"})
		return
	}
	jsonOut(w, 200, map[string]any{
		"ok":          true,
		"pen":         tok.Pen,
		"plan":        rec.Plan,
		"state":       rec.State,
		"renew_nonce": tok.Nonce,
	})
}

// lifecycleAlertsHandler manages opt-in billing alert email addresses for a pen
// (D-35: list, add, remove — keep-less-data, removable anytime).
func (b *broker) lifecycleAlertsHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Pen    string `json:"pen"`
		Action string `json:"action"` // "list" | "add" | "remove"
		Email  string `json:"email,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	pen := strings.ToLower(strings.TrimSpace(in.Pen))
	if _, ok := validPen(pen); !ok {
		jsonOut(w, 400, map[string]string{"error": "invalid pen name"})
		return
	}
	action := strings.ToLower(strings.TrimSpace(in.Action))
	if action == "" {
		action = "list"
	}
	if action != "list" && action != "add" && action != "remove" {
		jsonOut(w, 400, map[string]string{"error": "action must be list, add, or remove"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if (action == "add" || action == "remove") && !validEmail(email) {
		jsonOut(w, 400, map[string]string{"error": "invalid email address"})
		return
	}

	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

	path := b.lifecyclePath(pen)
	var emails []string
	var httpStatus int
	var httpErr string
	_ = withPenLifecycleFileLock(path, func() error {
		rec, err := loadPenLifecycle(path)
		if os.IsNotExist(err) {
			httpStatus, httpErr = 404, "pen has no lifecycle record"
			return nil
		}
		if err != nil {
			httpStatus, httpErr = 500, "could not read lifecycle record"
			return nil
		}
		switch action {
		case "add":
			exists := false
			for _, e := range rec.AlertEmails {
				if strings.EqualFold(e, email) {
					exists = true
					break
				}
			}
			if !exists {
				if len(rec.AlertEmails) >= 10 {
					httpStatus, httpErr = 400, "at most 10 alert emails per pen"
					return nil
				}
				rec.AlertEmails = append(rec.AlertEmails, email)
				rec.UpdatedAt = time.Now().UTC().Unix()
				if err := savePenLifecycle(path, rec); err != nil {
					httpStatus, httpErr = 500, "could not save lifecycle record"
					return nil
				}
			}
		case "remove":
			kept := make([]string, 0, len(rec.AlertEmails))
			for _, e := range rec.AlertEmails {
				if !strings.EqualFold(e, email) {
					kept = append(kept, e)
				}
			}
			rec.AlertEmails = kept
			rec.UpdatedAt = time.Now().UTC().Unix()
			if err := savePenLifecycle(path, rec); err != nil {
				httpStatus, httpErr = 500, "could not save lifecycle record"
				return nil
			}
		}
		emails = rec.AlertEmails
		return nil
	})
	if httpStatus != 0 {
		jsonOut(w, httpStatus, map[string]string{"error": httpErr})
		return
	}
	if emails == nil {
		emails = []string{}
	}
	jsonOut(w, 200, map[string]any{"pen": pen, "alert_emails": emails})
}

func pruneReplacedSubs(rec *penLifecycle, nowUnix int64) {
	if len(rec.ReplacedSubs) == 0 {
		return
	}
	cutoff := nowUnix - int64(replacedSubRetainTTL/time.Second)
	for subID, ts := range rec.ReplacedSubs {
		if ts < cutoff {
			delete(rec.ReplacedSubs, subID)
		}
	}
	if len(rec.ReplacedSubs) == 0 {
		rec.ReplacedSubs = nil
	}
}

// findPenByReplacedSubscription scans pens/*/lifecycle.json for a subscription
// that is currently queued for cancellation or was recently replaced (I-6).
// Caller must hold b.lifecycleMu.
func (b *broker) findPenByReplacedSubscription(subID string) (string, bool) {
	if subID == "" || subID == "-" {
		return "", false
	}
	entries, err := os.ReadDir(filepath.Join(b.home, "pens"))
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rec, err := loadPenLifecycle(b.lifecyclePath(e.Name()))
		if err != nil {
			continue
		}
		for _, q := range rec.PendingCancelSubs {
			if q.SubscriptionID == subID {
				return e.Name(), true
			}
		}
		if _, ok := rec.ReplacedSubs[subID]; ok {
			return e.Name(), true
		}
	}
	return "", false
}

// clearPendingCancelSub removes subID from any pen's PendingCancelSubs when
// Stripe notifies us via customer.subscription.deleted that it already ended.
// Caller must hold b.lifecycleMu.
func (b *broker) clearPendingCancelSub(subID string, now time.Time) {
	if subID == "" || subID == "-" {
		return
	}
	entries, err := os.ReadDir(filepath.Join(b.home, "pens"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := b.lifecyclePath(e.Name())
		rec, err := loadPenLifecycle(path)
		if err != nil || len(rec.PendingCancelSubs) == 0 {
			continue
		}
		removed := false
		for _, q := range rec.PendingCancelSubs {
			if q.SubscriptionID == subID {
				removed = true
				break
			}
		}
		if removed {
			_ = withPenLifecycleFileLock(path, func() error {
				cur, cerr := loadPenLifecycle(path)
				if cerr != nil {
					return cerr
				}
				kept2 := make([]pendingCancelSub, 0, len(cur.PendingCancelSubs))
				removed2 := false
				for _, q := range cur.PendingCancelSubs {
					if q.SubscriptionID == subID {
						removed2 = true
						continue
					}
					kept2 = append(kept2, q)
				}
				if !removed2 {
					return nil
				}
				cur.PendingCancelSubs = kept2
				if cur.ReplacedSubs == nil {
					cur.ReplacedSubs = map[string]int64{}
				}
				cur.ReplacedSubs[subID] = now.UTC().Unix()
				pruneReplacedSubs(cur, now.UTC().Unix())
				cur.UpdatedAt = now.UTC().Unix()
				return savePenLifecycle(path, cur)
			})
		}
	}
}

type pendingCancelItem struct {
	Pen            string `json:"pen"`
	SubscriptionID string `json:"subscription_id"`
}

// lifecyclePendingCancels returns due replaced Stripe subscriptions queued by
// recordRenewal so signup-web (which holds the Stripe key) can cancel them (I-6).
// Items backing off after a previous error (next_attempt_at > now) are skipped.
func (b *broker) lifecyclePendingCancels(w http.ResponseWriter, r *http.Request) {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

	nowUnix := b.now().Unix()
	items := []pendingCancelItem{}
	entries, err := os.ReadDir(filepath.Join(b.home, "pens"))
	if err != nil && !os.IsNotExist(err) {
		jsonOut(w, 500, map[string]string{"error": "could not scan pens"})
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rec, err := loadPenLifecycle(b.lifecyclePath(e.Name()))
		if err != nil {
			continue
		}
		for _, q := range rec.PendingCancelSubs {
			if q.SubscriptionID == "" || q.SubscriptionID == "-" {
				continue
			}
			if q.NextAttemptAt > nowUnix {
				continue
			}
			items = append(items, pendingCancelItem{Pen: e.Name(), SubscriptionID: q.SubscriptionID})
		}
	}
	jsonOut(w, 200, map[string]any{"items": items})
}

func (b *broker) lifecycleCancelDone(w http.ResponseWriter, r *http.Request) {
	var in pendingCancelItem
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	pen := strings.ToLower(strings.TrimSpace(in.Pen))
	subID := strings.TrimSpace(in.SubscriptionID)
	if _, ok := validPen(pen); !ok || !strings.HasPrefix(subID, "sub_") {
		jsonOut(w, 400, map[string]string{"error": "invalid request"})
		return
	}

	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

	path := b.lifecyclePath(pen)
	now := b.now()
	var httpStatus int
	var httpErr string
	var removed bool
	_ = withPenLifecycleFileLock(path, func() error {
		rec, err := loadPenLifecycle(path)
		if err != nil {
			httpStatus, httpErr = 404, "pen not found"
			return nil
		}
		kept := make([]pendingCancelSub, 0, len(rec.PendingCancelSubs))
		for _, q := range rec.PendingCancelSubs {
			if q.SubscriptionID == subID {
				removed = true
				continue
			}
			kept = append(kept, q)
		}
		if removed {
			rec.PendingCancelSubs = kept
			if rec.ReplacedSubs == nil {
				rec.ReplacedSubs = map[string]int64{}
			}
			rec.ReplacedSubs[subID] = now.Unix()
			pruneReplacedSubs(rec, now.Unix())
			rec.UpdatedAt = now.Unix()
			if err := savePenLifecycle(path, rec); err != nil {
				httpStatus, httpErr = 500, "could not save lifecycle"
				return nil
			}
		}
		return nil
	})
	if httpStatus != 0 {
		jsonOut(w, httpStatus, map[string]string{"error": httpErr})
		return
	}
	if removed {
		b.ledger(fmt.Sprintf("%s cancelled replaced Stripe subscription %s for pen %s", now.Format(time.RFC3339), subID, pen))
	}
	jsonOut(w, 200, map[string]any{"ok": true})
}

func (b *broker) lifecycleCancelAlert(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Pen            string `json:"pen"`
		SubscriptionID string `json:"subscription_id"`
		Error          string `json:"error"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	pen := strings.ToLower(strings.TrimSpace(in.Pen))
	subID := strings.TrimSpace(in.SubscriptionID)
	if _, ok := validPen(pen); !ok || !strings.HasPrefix(subID, "sub_") {
		jsonOut(w, 400, map[string]string{"error": "invalid request"})
		return
	}

	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

	path := b.lifecyclePath(pen)
	now := b.now()
	errText := cleanField(in.Error, 200)
	var httpStatus int
	var httpErr string
	var shouldAlert bool
	var attempts int
	var nextAttemptAt int64
	_ = withPenLifecycleFileLock(path, func() error {
		rec, err := loadPenLifecycle(path)
		if err != nil {
			httpStatus, httpErr = 404, "pen not found"
			return nil
		}
		idx := -1
		for i, q := range rec.PendingCancelSubs {
			if q.SubscriptionID == subID {
				idx = i
				break
			}
		}
		if idx < 0 {
			httpStatus, httpErr = 404, "subscription not queued"
			return nil
		}
		item := &rec.PendingCancelSubs[idx]
		item.Attempts++
		item.NextAttemptAt = now.Add(cancelRetryBackoff(item.Attempts)).Unix()
		item.LastError = errText
		shouldAlert = item.LastAlertAt == 0 || now.Unix()-item.LastAlertAt >= int64(cancelAlertCooldown/time.Second)
		if shouldAlert {
			item.LastAlertAt = now.Unix()
		}
		attempts = item.Attempts
		nextAttemptAt = item.NextAttemptAt
		rec.UpdatedAt = now.Unix()
		if err := savePenLifecycle(path, rec); err != nil {
			httpStatus, httpErr = 500, "could not save lifecycle"
			return nil
		}
		return nil
	})
	if httpStatus != 0 {
		jsonOut(w, httpStatus, map[string]string{"error": httpErr})
		return
	}

	msg := fmt.Sprintf("Could not cancel replaced Stripe subscription %s for pen %s (attempt %d; cancel manually or grant Subscriptions: Write): %s",
		subID, pen, attempts, errText)
	log.Print(msg)
	if shouldAlert {
		b.notifyKind("health", msg)
	}
	jsonOut(w, 200, map[string]any{
		"ok":              true,
		"alerted":         shouldAlert,
		"attempts":        attempts,
		"next_attempt_at": nextAttemptAt,
	})
}

func pruneWakeHistory(history []int64, now time.Time) []int64 {
	if len(history) == 0 {
		return nil
	}
	cutoff := now.UTC().Add(-renewWakeHistoryTTL).Unix()
	out := make([]int64, 0, len(history))
	for _, ts := range history {
		if ts >= cutoff {
			out = append(out, ts)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// countRenewOnlyPens counts pens currently in stateRenewOnly. Caller must hold b.lifecycleMu.
func (b *broker) countRenewOnlyPens() int {
	entries, err := os.ReadDir(filepath.Join(b.home, "pens"))
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rec, err := loadPenLifecycle(b.lifecyclePath(e.Name()))
		if err == nil && rec.State == stateRenewOnly {
			count++
		}
	}
	return count
}

// checkGlobalWakeCapHealth alerts the operator if the global concurrent
// renew-only wake cap stays saturated for >5 minutes (I-7 Part 2).
// Caller must hold b.lifecycleMu.
func (b *broker) checkGlobalWakeCapHealth(now time.Time, concurrent int) {
	maxConc := b.effectiveRenewWakeMaxConcurrent()
	if concurrent < maxConc {
		b.globalCapFullSince = time.Time{}
		return
	}
	if b.globalCapFullSince.IsZero() {
		b.globalCapFullSince = now
		return
	}
	if now.Sub(b.globalCapFullSince) >= renewWakeGlobalCapAlertAfter &&
		(b.globalCapAlertedAt.IsZero() || now.Sub(b.globalCapAlertedAt) >= time.Hour) {
		b.globalCapAlertedAt = now
		msg := fmt.Sprintf("Renewal wake global cap (%d/%d concurrent) has remained full for >%s", concurrent, maxConc, renewWakeGlobalCapAlertAfter)
		log.Print(msg)
		b.notifyKind("health", msg)
	}
}

// requestRenewWake validates per-pen caps (3/24h, 10/30d), global concurrent
// cap (2), and host reserve capacity, and atomically records state=renew_only +
// billing-status.json before spawning the background wake. Always fast (<5ms)
// so POST /api/wake has no timing oracle across sleeping/active/capped/full.
func (b *broker) requestRenewWake(ctx context.Context, pen string, now time.Time) (shouldStart bool, startedAt, ceiling int64, reason string) {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

	now = now.UTC()
	nowUnix := now.Unix()
	path := b.lifecyclePath(pen)
	rec, err := loadPenLifecycle(path)
	if err != nil {
		return false, 0, 0, "missing"
	}
	if rec.State != stateSleeping {
		return false, 0, 0, "not-sleeping"
	}
	if rec.Plan != planPersonal && rec.Plan != planWork {
		return false, 0, 0, "not-paid"
	}
	if _, err := os.Stat(filepath.Join(b.home, "pens", pen, ".removed")); err == nil {
		return false, 0, 0, "removed"
	}
	if _, err := os.Stat(filepath.Join(b.home, "pens", pen, ".retired")); err == nil {
		return false, 0, 0, "retired"
	}

	rec.WakeHistory = pruneWakeHistory(rec.WakeHistory, now)
	dayCutoff := now.Add(-24 * time.Hour).Unix()
	dayCount := 0
	for _, ts := range rec.WakeHistory {
		if ts >= dayCutoff {
			dayCount++
		}
	}
	if dayCount >= renewWakeMaxPerDay {
		msg := fmt.Sprintf("Pen %s hit its daily renewal-wake cap (%d/%d in 24h)", pen, dayCount, renewWakeMaxPerDay)
		log.Print(msg)
		b.notifyKind("health", msg)
		return false, 0, 0, "daily-cap"
	}
	if len(rec.WakeHistory) >= renewWakeMaxPerMonth {
		msg := fmt.Sprintf("Pen %s hit its 30-day renewal-wake cap (%d/%d in 30d)", pen, len(rec.WakeHistory), renewWakeMaxPerMonth)
		log.Print(msg)
		b.notifyKind("health", msg)
		return false, 0, 0, "monthly-cap"
	}

	concurrent := b.countRenewOnlyPens()
	maxConc := b.effectiveRenewWakeMaxConcurrent()
	if concurrent >= maxConc {
		b.checkGlobalWakeCapHealth(now, concurrent)
		return false, 0, 0, "global-cap"
	}
	b.globalCapFullSince = time.Time{}

	// Never evict or block a paying pen: renewal wakes only use available
	// slots within MAX_PENS + reserve (default reserve=2, configurable to 0).
	capInfo, cerr := b.readCapacity(ctx)
	if cerr != nil {
		log.Printf("lifecycle wake %s: capacity check failed: %v", pen, cerr)
		return false, 0, 0, "capacity-error"
	}
	reserve := b.effectiveRenewWakeReserve()
	if capInfo.Pens+concurrent >= capInfo.Max+reserve {
		log.Printf("lifecycle wake %s: host full (%d live + %d wakes >= %d max + %d reserve)", pen, capInfo.Pens, concurrent, capInfo.Max, reserve)
		return false, 0, 0, "host-full"
	}

	ceilUnix := now.Add(renewWakeCeiling).Unix()
	var failReason string
	var savedHistLen int
	if err := withPenLifecycleFileLock(path, func() error {
		cur, lerr := loadPenLifecycle(path)
		if lerr != nil || cur.State != stateSleeping || (cur.Plan != planPersonal && cur.Plan != planWork) {
			failReason = "not-sleeping"
			return nil
		}
		prevRec := *cur
		cur.WakeHistory = pruneWakeHistory(cur.WakeHistory, now)
		cur.State = stateRenewOnly
		cur.WakeStartedAt = nowUnix
		cur.WakeReadyAt = 0
		cur.WakeCeiling = ceilUnix
		cur.WakeUntil = ceilUnix
		cur.WakeHistory = append(cur.WakeHistory, nowUnix)
		if cur.RenewURL == "" {
			cur.RenewURL = b.renewOriginForPen(cur.Plan)
		}
		cur.UpdatedAt = nowUnix
		// B1 & B2: Write BOTH .renew-only marker and billing-status.json BEFORE
		// committing state=renew_only or starting containers. If writing fails,
		// abort and roll back cleanly so a pen can never boot in normal mode.
		if berr := syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), cur, b.renewOriginForPen(cur.Plan)); berr != nil {
			log.Printf("lifecycle wake %s: write renew_only status/marker failed (aborting wake): %v", pen, berr)
			_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), &prevRec, "")
			failReason = "banner-error"
			return nil
		}
		if serr := savePenLifecycle(path, cur); serr != nil {
			log.Printf("lifecycle wake %s: save renew_only: %v", pen, serr)
			_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), &prevRec, "")
			failReason = "save-error"
			return nil
		}
		savedHistLen = len(cur.WakeHistory)
		return nil
	}); err != nil {
		log.Printf("lifecycle wake %s: lock renew_only: %v", pen, err)
		return false, 0, 0, "save-error"
	}
	if failReason != "" {
		return false, 0, 0, failReason
	}
	b.ledger(fmt.Sprintf("%s renew-only wake requested for %s (ceiling %s, wakes_24h=%d, wakes_30d=%d)",
		now.Format(time.RFC3339), pen, time.Unix(ceilUnix, 0).UTC().Format(time.RFC3339), dayCount+1, savedHistLen))
	return true, nowUnix, ceilUnix, "started"
}

func (b *broker) checkPenHealth(ctx context.Context, pen string) error {
	if b.wakeHealthFn != nil {
		return b.wakeHealthFn(ctx, pen)
	}
	_, code, stderr := b.run(ctx, "pen", pen, "health")
	if code != 0 {
		return fmt.Errorf("pen health exit %d: %s", code, strings.TrimSpace(stderr))
	}
	return nil
}

// runRenewWakeAsync executes the slow Docker wake and waits for the registrar
// to confirm home.<zone> TLS readiness before starting the 10-minute renewal
// window (bounded by the 20-minute hard ceiling from button press).
func (b *broker) runRenewWakeAsync(pen string, wakeStartedAt, ceilingUnix int64) {
	ctx, cancel := context.WithTimeout(context.Background(), renewWakeCeiling)
	defer cancel()

	if !b.tryBeginWake(pen) {
		log.Printf("lifecycle wake %s: wake already in flight; rolling back renew-only request", pen)
		b.rollbackFailedRenewWake(pen, wakeStartedAt)
		return
	}
	started := func() bool {
		defer b.endWake(pen)
		_, code, stderr := b.runUnbounded(ctx, "wake", "--renew-only", "--no-lifecycle", pen)
		b.invalidateCapacityCache()
		if code != 0 {
			log.Printf("lifecycle wake %s: wake --renew-only failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
			b.rollbackFailedRenewWake(pen, wakeStartedAt)
			return false
		}
		return true
	}()
	if !started {
		return
	}
	b.pollRenewWakeReady(ctx, pen, wakeStartedAt, ceilingUnix)
}

func (b *broker) pollRenewWakeReady(ctx context.Context, pen string, wakeStartedAt, ceilingUnix int64) {
	ceilTime := time.Unix(ceilingUnix, 0).UTC()
	pollInterval := b.wakeHealthInterval
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	for {
		if b.now().After(ceilTime) || ctx.Err() != nil {
			return
		}
		// Stop polling if pen was already renewed or put back to sleep.
		b.lifecycleMu.Lock()
		rec, err := loadPenLifecycle(b.lifecyclePath(pen))
		stillThisWake := err == nil && rec.State == stateRenewOnly && rec.WakeStartedAt == wakeStartedAt
		b.lifecycleMu.Unlock()
		if !stillThisWake {
			return
		}

		hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
		herr := b.checkPenHealth(hctx, pen)
		hcancel()
		if herr == nil {
			b.markRenewWakeReady(pen, wakeStartedAt, b.now())
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

func (b *broker) markRenewWakeReady(pen string, wakeStartedAt int64, readyAt time.Time) {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

	path := b.lifecyclePath(pen)
	var updated *penLifecycle
	var until int64
	if err := withPenLifecycleFileLock(path, func() error {
		rec, err := loadPenLifecycle(path)
		if err != nil || rec.State != stateRenewOnly || rec.WakeStartedAt != wakeStartedAt {
			return nil
		}
		readyUnix := readyAt.UTC().Unix()
		until = readyAt.UTC().Add(renewWakeWindow).Unix()
		if rec.WakeCeiling > 0 && until > rec.WakeCeiling {
			until = rec.WakeCeiling
		}
		rec.WakeReadyAt = readyUnix
		rec.WakeUntil = until
		rec.UpdatedAt = readyUnix
		if err := savePenLifecycle(path, rec); err != nil {
			return err
		}
		updated = rec
		return nil
	}); err != nil {
		log.Printf("lifecycle wake %s: save ready deadline: %v", pen, err)
		return
	}
	if updated == nil {
		return
	}
	if err := syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), updated, b.renewOriginForPen(updated.Plan)); err != nil {
		log.Printf("lifecycle wake %s: update billing-status.json: %v", pen, err)
	}
	b.ledger(fmt.Sprintf("%s renew-only wake ready for %s (window until %s)",
		readyAt.UTC().Format(time.RFC3339), pen, time.Unix(until, 0).UTC().Format(time.RFC3339)))
}

func (b *broker) rollbackFailedRenewWake(pen string, wakeStartedAt int64) {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

	path := b.lifecyclePath(pen)
	var rolled *penLifecycle
	_ = withPenLifecycleFileLock(path, func() error {
		rec, err := loadPenLifecycle(path)
		if err != nil || rec.State != stateRenewOnly || rec.WakeStartedAt != wakeStartedAt {
			return nil
		}
		rec.State = stateSleeping
		rec.WakeStartedAt = 0
		rec.WakeReadyAt = 0
		rec.WakeUntil = 0
		rec.WakeCeiling = 0
		rec.UpdatedAt = b.now().Unix()
		if err := savePenLifecycle(path, rec); err != nil {
			return err
		}
		rolled = rec
		return nil
	})
	if rolled == nil {
		return
	}
	_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), rolled, "")
	_ = os.Remove(filepath.Join(b.home, "pens", pen, ".renew-wake"))
}

// lifecycleTransitionHandler executes operator-initiated `hogman-host sleep`,
// `hogman-host wake`, and `hogman-host wake --renew-only` transitions through
// the broker so the broker stays the single owner of lifecycle.json (I-12).
func (b *broker) lifecycleTransitionHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Pen    string `json:"pen"`
		Action string `json:"action"` // "sleep" | "wake" | "renew_only"
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	pen := strings.ToLower(strings.TrimSpace(in.Pen))
	if _, ok := validPen(pen); !ok {
		jsonOut(w, 400, map[string]string{"error": "invalid pen name"})
		return
	}
	action := strings.ToLower(strings.TrimSpace(in.Action))
	if action != "sleep" && action != "wake" && action != "renew_only" {
		jsonOut(w, 400, map[string]string{"error": "action must be sleep, wake, or renew_only"})
		return
	}
	penDir := filepath.Join(b.home, "pens", pen)
	if fi, err := os.Stat(penDir); err != nil || !fi.IsDir() {
		jsonOut(w, 404, map[string]string{"error": "no pen " + pen})
		return
	}
	if _, err := os.Stat(filepath.Join(penDir, ".retired")); err == nil {
		jsonOut(w, 409, map[string]string{"error": "pen " + pen + " has already been deleted"})
		return
	}
	if !b.tryBeginWake(pen) {
		jsonOut(w, 409, map[string]string{"error": "a wake or sleep is already in flight for " + pen})
		return
	}
	defer b.endWake(pen)

	now := b.now().UTC()
	nowUnix := now.Unix()
	path := b.lifecyclePath(pen)

	switch action {
	case "sleep":
		b.lifecycleMu.Lock()
		defer b.lifecycleMu.Unlock()

		_, code, stderr := b.runUnbounded(r.Context(), "sleep", "--no-lifecycle", pen)
		b.invalidateCapacityCache()
		if code != 0 {
			jsonOut(w, 500, map[string]string{"error": fmt.Sprintf("sleep %s failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))})
			return
		}
		var saved *penLifecycle
		var firstDeleteDate bool
		if err := withPenLifecycleFileLock(path, func() error {
			rec, lerr := loadPenLifecycle(path)
			if os.IsNotExist(lerr) {
				rec = &penLifecycle{Plan: planFree, State: stateActive}
			} else if lerr != nil {
				return lerr
			}
			sleepSince := nowUnix
			deleteAfter := now.Add(lifecycleSleepDuration).Unix()
			if rec.SleepSince > 0 && rec.DeleteAfter > 0 {
				sleepSince = rec.SleepSince
				deleteAfter = rec.DeleteAfter
			} else {
				firstDeleteDate = true
			}
			rec.State = stateSleeping
			rec.SleepSince = sleepSince
			rec.DeleteAfter = deleteAfter
			rec.WakeStartedAt = 0
			rec.WakeReadyAt = 0
			rec.WakeUntil = 0
			rec.WakeCeiling = 0
			rec.UpdatedAt = nowUnix
			if serr := savePenLifecycle(path, rec); serr != nil {
				return serr
			}
			saved = rec
			return nil
		}); err != nil {
			jsonOut(w, 500, map[string]string{"error": "could not save lifecycle: " + err.Error()})
			return
		}
		_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), saved, "")
		deleteDate := time.Unix(saved.DeleteAfter, 0).UTC().Format("2006-01-02")
		b.ledger(fmt.Sprintf("%s lifecycle %s: operator sleep -> sleeping (delete after %s)",
			now.Format(time.RFC3339), pen, deleteDate))
		jsonOut(w, 200, map[string]any{
			"ok":                true,
			"pen":               pen,
			"state":             saved.State,
			"delete_after":      deleteDate,
			"first_delete_date": firstDeleteDate,
		})

	case "wake":
		if _, err := os.Stat(filepath.Join(penDir, ".removed")); err == nil {
			jsonOut(w, 409, map[string]string{"error": "pen " + pen + " was removed (use upgrade/restore, not wake)"})
			return
		}
		_, code, stderr := b.runUnbounded(r.Context(), "wake", "--no-lifecycle", pen)
		b.invalidateCapacityCache()
		if code != 0 {
			jsonOut(w, 500, map[string]string{"error": fmt.Sprintf("wake %s failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))})
			return
		}
		b.lifecycleMu.Lock()
		var saved *penLifecycle
		err := withPenLifecycleFileLock(path, func() error {
			rec, lerr := loadPenLifecycle(path)
			if os.IsNotExist(lerr) {
				return nil
			}
			if lerr != nil {
				return lerr
			}
			rec.State = stateActive
			rec.SleepSince = 0
			rec.DeleteAfter = 0
			rec.PendingWake = false
			rec.PendingWakeAttempts = 0
			rec.PendingWakeNextAt = 0
			rec.WakeStartedAt = 0
			rec.WakeReadyAt = 0
			rec.WakeUntil = 0
			rec.WakeCeiling = 0
			rec.UpdatedAt = nowUnix
			if serr := savePenLifecycle(path, rec); serr != nil {
				return serr
			}
			saved = rec
			return nil
		})
		if saved != nil {
			_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), saved, b.renewOriginForPen(saved.Plan))
		}
		b.lifecycleMu.Unlock()
		if err != nil {
			jsonOut(w, 500, map[string]string{"error": "could not save lifecycle: " + err.Error()})
			return
		}
		b.ledger(fmt.Sprintf("%s lifecycle %s: operator wake -> active", now.Format(time.RFC3339), pen))
		jsonOut(w, 200, map[string]any{"ok": true, "pen": pen, "state": stateActive})

	case "renew_only":
		if _, err := os.Stat(filepath.Join(penDir, ".sleeping")); err != nil {
			jsonOut(w, 409, map[string]string{"error": "pen " + pen + " is not asleep"})
			return
		}
		b.lifecycleMu.Lock()
		var prevRec penLifecycle
		var ceilUnix int64
		var startErrStatus int
		var startErrMsg string
		if err := withPenLifecycleFileLock(path, func() error {
			rec, lerr := loadPenLifecycle(path)
			if os.IsNotExist(lerr) {
				rec = &penLifecycle{Plan: planPersonal, State: stateSleeping, SleepSince: nowUnix, DeleteAfter: now.Add(lifecycleSleepDuration).Unix()}
			} else if lerr != nil {
				startErrStatus, startErrMsg = 500, "could not read lifecycle: "+lerr.Error()
				return nil
			}
			if rec.Plan != planPersonal && rec.Plan != planWork {
				startErrStatus, startErrMsg = 400, fmt.Sprintf("pen %s plan is %q; renew-only wake is only for paid pens", pen, rec.Plan)
				return nil
			}
			if rec.State != stateSleeping && rec.State != stateRenewOnly {
				startErrStatus, startErrMsg = 409, fmt.Sprintf("pen %s state is %q, not sleeping", pen, rec.State)
				return nil
			}
			concurrent := b.countRenewOnlyPens()
			maxConc := b.effectiveRenewWakeMaxConcurrent()
			if rec.State != stateRenewOnly && concurrent >= maxConc {
				startErrStatus, startErrMsg = 429, fmt.Sprintf("global renewal-wake cap reached (%d/%d)", concurrent, maxConc)
				return nil
			}
			capInfo, cerr := b.readCapacity(r.Context())
			if cerr != nil {
				startErrStatus, startErrMsg = 503, "capacity check failed: "+cerr.Error()
				return nil
			}
			reserve := b.effectiveRenewWakeReserve()
			if rec.State != stateRenewOnly && capInfo.Pens+concurrent >= capInfo.Max+reserve {
				startErrStatus, startErrMsg = 503, fmt.Sprintf("host is at capacity (%d live + %d wake / %d total)", capInfo.Pens, concurrent, capInfo.Max+reserve)
				return nil
			}
			prevRec = *rec
			if rec.SleepSince == 0 {
				rec.SleepSince = nowUnix
			}
			if rec.DeleteAfter == 0 {
				rec.DeleteAfter = now.Add(lifecycleSleepDuration).Unix()
			}
			ceilUnix = now.Add(renewWakeCeiling).Unix()
			rec.State = stateRenewOnly
			rec.WakeStartedAt = nowUnix
			rec.WakeReadyAt = 0
			rec.WakeUntil = ceilUnix
			rec.WakeCeiling = ceilUnix
			if rec.RenewURL == "" {
				rec.RenewURL = b.renewOriginForPen(rec.Plan)
			}
			rec.UpdatedAt = nowUnix
			if berr := syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), rec, b.renewOriginForPen(rec.Plan)); berr != nil {
				_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), &prevRec, "")
				startErrStatus, startErrMsg = 500, "failed writing renew-only status/marker: "+berr.Error()
				return nil
			}
			if serr := savePenLifecycle(path, rec); serr != nil {
				_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), &prevRec, "")
				startErrStatus, startErrMsg = 500, "failed saving lifecycle: "+serr.Error()
				return nil
			}
			return nil
		}); err != nil {
			b.lifecycleMu.Unlock()
			jsonOut(w, 500, map[string]string{"error": "lock error: " + err.Error()})
			return
		}
		b.lifecycleMu.Unlock()
		if startErrStatus != 0 {
			jsonOut(w, startErrStatus, map[string]string{"error": startErrMsg})
			return
		}

		_, code, stderr := b.runUnbounded(r.Context(), "wake", "--renew-only", "--no-lifecycle", pen)
		b.invalidateCapacityCache()
		if code != 0 {
			b.rollbackFailedRenewWake(pen, nowUnix)
			jsonOut(w, 500, map[string]string{"error": fmt.Sprintf("wake --renew-only %s failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))})
			return
		}
		go func(p string, started, ceil int64) {
			ctx, cancel := context.WithTimeout(context.Background(), renewWakeCeiling)
			defer cancel()
			b.pollRenewWakeReady(ctx, p, started, ceil)
		}(pen, nowUnix, ceilUnix)
		b.ledger(fmt.Sprintf("%s lifecycle %s: operator renew-only wake (ceiling %s)",
			now.Format(time.RFC3339), pen, time.Unix(ceilUnix, 0).UTC().Format(time.RFC3339)))
		jsonOut(w, 200, map[string]any{"ok": true, "pen": pen, "state": stateRenewOnly})
	}
}

// lifecycleWakeHandler accepts a public renewal-wake request forwarded by
// signup-web and ALWAYS returns 202 immediately (doing slow container/cert work
// asynchronously) so callers cannot probe pen state or caps by response or timing.
func (b *broker) lifecycleWakeHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Pen string `json:"pen"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad request"})
		return
	}
	pen := strings.ToLower(strings.TrimSpace(in.Pen))
	if _, ok := validPen(pen); !ok {
		jsonOut(w, 400, map[string]string{"error": "invalid pen name"})
		return
	}
	shouldStart, startedAt, ceiling, _ := b.requestRenewWake(r.Context(), pen, b.now())
	if shouldStart {
		go b.runRenewWakeAsync(pen, startedAt, ceiling)
	}
	jsonOut(w, 202, map[string]any{"ok": true})
}

// sweepExpiredRenewWakes handles ONLY expired renew_only deadlines and
// pending_wake retries from paid renewals (never running active->grace,
// billing alerts, or purges for unrelated pens) so the 1-minute watcher stays
// narrowly scoped to ephemeral wakes and paid-renewal recovery.
//
// Pending-wake retries execute outside lifecycleMu and are serialized per pen
// via tryBeginWake/endWake so they never overlap finishRenewalWork. Expired
// renew_only sleeps hold lifecycleMu across `hogman-host sleep` and the final
// save so a concurrent renewal payment cannot land in the gap and get
// overwritten back to sleeping by `hogman-host sleep`.
func (b *broker) sweepExpiredRenewWakes(ctx context.Context, now time.Time) ([]lifecycleTransition, error) {
	nowUTC := now.UTC()
	nowUnix := nowUTC.Unix()

	b.lifecycleMu.Lock()
	pensDir := filepath.Join(b.home, "pens")
	entries, err := os.ReadDir(pensDir)
	if os.IsNotExist(err) {
		b.lifecycleMu.Unlock()
		return nil, nil
	}
	if err != nil {
		b.lifecycleMu.Unlock()
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	concurrent := 0
	var pendingWakePens []string
	var expiredRenewPens []string
	for _, pen := range names {
		rec, lerr := loadPenLifecycle(b.lifecyclePath(pen))
		if lerr != nil {
			continue
		}
		if rec.State == stateActive && rec.PendingWake {
			if rec.PendingWakeNextAt == 0 || nowUnix >= rec.PendingWakeNextAt {
				pendingWakePens = append(pendingWakePens, pen)
			}
			continue
		}
		if rec.State == stateRenewOnly {
			concurrent++
			if next, changed := evaluateLifecycle(*rec, nowUTC); changed && next.State == stateSleeping {
				expiredRenewPens = append(expiredRenewPens, pen)
			}
		}
	}
	b.lifecycleMu.Unlock()

	var out []lifecycleTransition
	for _, pen := range pendingWakePens {
		if !b.tryBeginWake(pen) {
			continue
		}
		var pendingOwner string
		func() {
			defer b.endWake(pen)
			path := b.lifecyclePath(pen)
			b.lifecycleMu.Lock()
			rec, lerr := loadPenLifecycle(path)
			stillDue := lerr == nil && rec.State == stateActive && rec.PendingWake &&
				(rec.PendingWakeNextAt == 0 || nowUnix >= rec.PendingWakeNextAt)
			b.lifecycleMu.Unlock()
			if !stillDue {
				return
			}

			tr := lifecycleTransition{Pen: pen, From: stateSleeping, To: stateActive, Woken: true}
			_, code, stderr := b.runUnbounded(ctx, "wake", "--no-lifecycle", pen)
			b.invalidateCapacityCache()
			if code != 0 {
				log.Printf("renew-wake watcher %s: pending_wake retry failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
				b.notifyKind("health", fmt.Sprintf("Pen %s paid renewal wake retry failed (exit %d): %s", pen, code, strings.TrimSpace(stderr)))
				b.lifecycleMu.Lock()
				_ = withPenLifecycleFileLock(path, func() error {
					if cur, cerr := loadPenLifecycle(path); cerr == nil && cur.PendingWake {
						cur.PendingWakeAttempts++
						cur.PendingWakeNextAt = nowUTC.Add(pendingWakeBackoff(cur.PendingWakeAttempts)).Unix()
						cur.UpdatedAt = nowUnix
						return savePenLifecycle(path, cur)
					}
					return nil
				})
				b.lifecycleMu.Unlock()
				tr.Woken = false
				tr.ActionNote = "wake retry failed"
				out = append(out, tr)
				return
			}

			b.lifecycleMu.Lock()
			var syncedRec *penLifecycle
			saveErr := withPenLifecycleFileLock(path, func() error {
				cur, cerr := loadPenLifecycle(path)
				if cerr != nil || cur.State != stateActive {
					return nil
				}
				cur.PendingWake = false
				cur.PendingWakeAttempts = 0
				cur.PendingWakeNextAt = 0
				cur.UpdatedAt = nowUnix
				if serr := savePenLifecycle(path, cur); serr != nil {
					return serr
				}
				syncedRec = cur
				pendingOwner = cur.PendingOwner
				return nil
			})
			if saveErr != nil {
				log.Printf("renew-wake watcher %s: save active after pending_wake: %v", pen, saveErr)
				b.lifecycleMu.Unlock()
				return
			}
			if syncedRec != nil {
				_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), syncedRec, b.renewOriginForPen(syncedRec.Plan))
			}
			b.lifecycleMu.Unlock()
			out = append(out, tr)
		}()

		if pendingOwner != "" {
			if done, perr := b.applyPendingOwner(ctx, pen, pendingOwner); perr != nil {
				log.Printf("renew-wake watcher %s: retry pending_owner %s: %v", pen, pendingOwner, perr)
			} else if done {
				p := b.lifecyclePath(pen)
				b.lifecycleMu.Lock()
				_ = withPenLifecycleFileLock(p, func() error {
					if cur, cerr := loadPenLifecycle(p); cerr == nil && cur.PendingOwner == pendingOwner {
						cur.PendingOwner = ""
						cur.UpdatedAt = nowUnix
						return savePenLifecycle(p, cur)
					}
					return nil
				})
				b.lifecycleMu.Unlock()
			}
		}
	}

	for _, pen := range expiredRenewPens {
		if !b.tryBeginWake(pen) {
			continue
		}
		func() {
			defer b.endWake(pen)
			path := b.lifecyclePath(pen)
			b.lifecycleMu.Lock()
			defer b.lifecycleMu.Unlock()
			rec, lerr := loadPenLifecycle(path)
			if lerr != nil || rec.State != stateRenewOnly {
				return
			}
			next, changed := evaluateLifecycle(*rec, nowUTC)
			if !changed || next.State != stateSleeping {
				return
			}

			_, code, stderr := b.runUnbounded(ctx, "sleep", "--no-lifecycle", pen)
			b.invalidateCapacityCache()
			if code != 0 {
				log.Printf("renew-wake watcher %s: sleep failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
				return
			}
			if serr := withPenLifecycleFileLock(path, func() error { return savePenLifecycle(path, &next) }); serr != nil {
				log.Printf("renew-wake watcher %s: save sleeping: %v", pen, serr)
				return
			}
			_ = syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), &next, "")
			b.ledger(fmt.Sprintf("%s lifecycle %s: renew_only -> sleeping (delete after %s)",
				nowUTC.Format(time.RFC3339), pen, time.Unix(next.DeleteAfter, 0).UTC().Format("2006-01-02")))
			concurrent--
			out = append(out, lifecycleTransition{Pen: pen, From: stateRenewOnly, To: stateSleeping})
		}()
	}

	b.lifecycleMu.Lock()
	b.checkGlobalWakeCapHealth(nowUTC, concurrent)
	b.lifecycleMu.Unlock()
	return out, nil
}

// runRenewWakeWatcher periodically enforces persisted renew_only deadlines,
// retries failed paid-renewal wakes (pending_wake), and alerts if the global
// wake cap stays full.
func (b *broker) runRenewWakeWatcher() {
	time.Sleep(15 * time.Second)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		now := b.now()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		if _, err := b.sweepExpiredRenewWakes(ctx, now); err != nil {
			log.Printf("renew-wake watcher: %v", err)
		}
		cancel()
		<-t.C
	}
}
