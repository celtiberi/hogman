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

	stateActive   = "active"
	stateGrace    = "grace"
	stateSleeping = "sleeping"
	stateDeleted  = "deleted"

	lifecycleGraceDuration   = 30 * 24 * time.Hour
	lifecycleSleepDuration   = 365 * 24 * time.Hour
	lifecycleYearDuration    = 365 * 24 * time.Hour
	lifecycleAutoRenewBuffer = 3 * 24 * time.Hour // leap year + Stripe invoice finalisation grace
	lifecyclePreAlertLead    = 30 * 24 * time.Hour
	lifecycleFinalLead       = 7 * 24 * time.Hour
	maxAppliedEvents         = 50
)

var errNoLifecycle = errors.New("pen has no lifecycle.json")

const (
	renewTokenPurpose   = "hogman-renew-v1:"
	renewTokenMaxTTL    = 20 * time.Minute
	renewNonceRetainTTL = 24 * time.Hour // matches Stripe Checkout session max lifetime
)

type renewNonceRecord struct {
	Handle    string `json:"handle"`
	Exp       int64  `json:"exp"`
	RetainExp int64  `json:"retain_exp"`
	Consumed  bool   `json:"consumed,omitempty"`
}

type penLifecycle struct {
	Plan              string                      `json:"plan"` // "free" | "personal" | "work"
	State             string                      `json:"state"`
	PaidUntil         int64                       `json:"paid_until,omitempty"`
	GraceUntil        int64                       `json:"grace_until,omitempty"`
	SleepSince        int64                       `json:"sleep_since,omitempty"`
	DeleteAfter       int64                       `json:"delete_after,omitempty"`
	SubscriptionID    string                      `json:"subscription_id,omitempty"`
	CustomerID        string                      `json:"customer_id,omitempty"`
	CancelledAt       int64                       `json:"cancelled_at,omitempty"`
	BackdateRenewal   bool                        `json:"backdate_renewal"` // D-35 default: false
	PendingWake       bool                        `json:"pending_wake,omitempty"`
	PendingOwner      string                      `json:"pending_owner,omitempty"`
	PendingCancelSubs []string                    `json:"pending_cancel_subs,omitempty"` // I-6: replaced Stripe sub IDs awaiting cancel by web
	AppliedEvents     []string                    `json:"applied_events,omitempty"`
	RenewNonces       map[string]renewNonceRecord `json:"renew_nonces,omitempty"` // broker-verified nonces; pruned by RetainExp
	AlertEmails       []string                    `json:"alert_emails,omitempty"`
	AlertsSent        map[string]int64            `json:"alerts_sent,omitempty"`
	RenewURL          string                      `json:"renew_url,omitempty"`
	UpdatedAt         int64                       `json:"updated_at,omitempty"`
}

type portalBillingStatus struct {
	Pen        string `json:"pen,omitempty"`
	State      string `json:"state"`
	PaidUntil  string `json:"paid_until,omitempty"`
	GraceUntil string `json:"grace_until,omitempty"`
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

func syncRegistrarBillingBanner(pen, billingPath string, rec *penLifecycle, fallbackRenewOrigin string) error {
	if rec.State != stateGrace {
		err := os.Remove(billingPath)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi, err := os.Stat(filepath.Dir(billingPath)); err != nil || !fi.IsDir() {
		return nil
	}
	renewOrigin := sanitizeHTTPSOrigin(rec.RenewURL)
	if renewOrigin == "" {
		renewOrigin = sanitizeHTTPSOrigin(fallbackRenewOrigin)
	}
	st := portalBillingStatus{
		Pen:      pen,
		State:    stateGrace,
		RenewURL: renewOrigin,
	}
	if rec.PaidUntil > 0 {
		st.PaidUntil = time.Unix(rec.PaidUntil, 0).UTC().Format(time.RFC3339)
	}
	if rec.GraceUntil > 0 {
		st.GraceUntil = time.Unix(rec.GraceUntil, 0).UTC().Format(time.RFC3339)
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
	wasSleeping = rec.State == stateSleeping
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
	next.CancelledAt = 0
	next.PendingWake = wasSleeping
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
	return savePenLifecycle(b.lifecyclePath(pen), rec)
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
	rec, err := loadPenLifecycle(path)
	if os.IsNotExist(err) {
		return nil, false, false, errNoLifecycle
	}
	if err != nil {
		return nil, false, false, err
	}
	if hasAppliedEvent(*rec, eventID) {
		return rec, true, false, nil
	}
	if rec.State == stateDeleted {
		return nil, false, false, fmt.Errorf("pen %s has already been deleted", pen)
	}
	backdate := b.backdateRenewal || rec.BackdateRenewal
	updated, sleeping := applyRenewal(*rec, now, backdate)
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
		// previous subscription_id existed, queue the old one for cancellation
		// by signup-web (which holds the Stripe key) so it cannot double-charge.
		if rec.SubscriptionID != "" && rec.SubscriptionID != "-" && rec.SubscriptionID != subID {
			alreadyQueued := false
			for _, q := range updated.PendingCancelSubs {
				if q == rec.SubscriptionID {
					alreadyQueued = true
					break
				}
			}
			if !alreadyQueued {
				updated.PendingCancelSubs = append(updated.PendingCancelSubs, rec.SubscriptionID)
			}
		}
		updated.SubscriptionID = subID
	}
	if custID != "" && custID != "-" {
		updated.CustomerID = custID
	}
	if updated.RenewURL == "" {
		updated.RenewURL = b.renewOriginForPen(updated.Plan)
	}
	if err := savePenLifecycle(path, &updated); err != nil {
		return nil, false, false, err
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

// finishRenewalWork executes post-webhook wake and persisted PendingOwner
// promotion (D-35, B9) outside the webhook's synchronous response path.
func (b *broker) finishRenewalWork(ctx context.Context, pen string, wake bool) error {
	if wake {
		_, code, stderr := b.runUnbounded(ctx, "wake", pen)
		b.invalidateCapacityCache()
		if code != 0 {
			err := fmt.Errorf("wake %s failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
			b.notifyKind("health", fmt.Sprintf("Pen %s was renewed and paid, but wake failed: %v", pen, err))
			return err
		}
		b.lifecycleMu.Lock()
		if rec, err := loadPenLifecycle(b.lifecyclePath(pen)); err == nil && rec.PendingWake {
			rec.PendingWake = false
			rec.UpdatedAt = time.Now().UTC().Unix()
			_ = savePenLifecycle(b.lifecyclePath(pen), rec)
		}
		b.lifecycleMu.Unlock()
	}

	b.lifecycleMu.Lock()
	var pendingOwner string
	if rec, err := loadPenLifecycle(b.lifecyclePath(pen)); err == nil && !rec.PendingWake {
		pendingOwner = rec.PendingOwner
	}
	b.lifecycleMu.Unlock()
	if pendingOwner == "" {
		return nil
	}
	done, err := b.applyPendingOwner(ctx, pen, pendingOwner)
	if done {
		b.lifecycleMu.Lock()
		if rec, lerr := loadPenLifecycle(b.lifecyclePath(pen)); lerr == nil && rec.PendingOwner == pendingOwner {
			rec.PendingOwner = ""
			rec.UpdatedAt = time.Now().UTC().Unix()
			_ = savePenLifecycle(b.lifecyclePath(pen), rec)
		}
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
				_, code, stderr := b.runUnbounded(ctx, "wake", pen)
				b.invalidateCapacityCache()
				if code != 0 {
					log.Printf("lifecycle %s: retry wake failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
					b.notifyKind("health", fmt.Sprintf("Pen %s paid renewal wake retry failed (exit %d): %s", pen, code, strings.TrimSpace(stderr)))
					tr.Woken = false
					tr.ActionNote = "wake retry failed"
				} else {
					rec.PendingWake = false
					rec.UpdatedAt = now.UTC().Unix()
					_ = savePenLifecycle(path, rec)
				}
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
					rec.PendingOwner = ""
					rec.UpdatedAt = now.UTC().Unix()
					_ = savePenLifecycle(path, rec)
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
					if err := savePenLifecycle(path, &next); err != nil {
						log.Printf("lifecycle %s: save grace: %v", pen, err)
						continue
					}
					if err := syncRegistrarBillingBanner(pen, b.registrarBillingPath(pen), &next, b.renewOriginForPen(next.Plan)); err != nil {
						log.Printf("lifecycle %s: write grace banner: %v", pen, err)
					}
					b.ledger(fmt.Sprintf("%s lifecycle %s: active -> grace (until %s)",
						now.UTC().Format(time.RFC3339), pen, time.Unix(next.GraceUntil, 0).UTC().Format("2006-01-02")))
				case stateSleeping:
					_, code, stderr := b.runUnbounded(ctx, "sleep", pen)
					b.invalidateCapacityCache()
					if code != 0 {
						log.Printf("lifecycle %s: sleep failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
						continue
					}
					if err := savePenLifecycle(path, &next); err != nil {
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
					if err := savePenLifecycle(path, &next); err != nil {
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
					if next.AlertsSent == nil {
						next.AlertsSent = map[string]int64{}
					}
					next.AlertsSent[milestone] = now.UTC().Unix()
					_ = savePenLifecycle(path, &next)
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
	if rec.State != stateGrace && rec.State != stateSleeping {
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
	rec.RenewNonces[tok.Nonce] = renewNonceRecord{
		Handle:    tok.Handle,
		Exp:       tok.Exp,
		RetainExp: now.Add(renewNonceRetainTTL).Unix(),
	}
	rec.UpdatedAt = nowUnix
	if err := savePenLifecycle(path, rec); err != nil {
		log.Printf("lifecycle %s: save used renew nonce: %v", tok.Pen, err)
		jsonOut(w, 500, map[string]string{"error": "could not process renewal right now"})
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
	rec, err := loadPenLifecycle(path)
	if os.IsNotExist(err) {
		jsonOut(w, 404, map[string]string{"error": "pen has no lifecycle record"})
		return
	}
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": "could not read lifecycle record"})
		return
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
				jsonOut(w, 400, map[string]string{"error": "at most 10 alert emails per pen"})
				return
			}
			rec.AlertEmails = append(rec.AlertEmails, email)
			rec.UpdatedAt = time.Now().UTC().Unix()
			if err := savePenLifecycle(path, rec); err != nil {
				jsonOut(w, 500, map[string]string{"error": "could not save lifecycle record"})
				return
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
			jsonOut(w, 500, map[string]string{"error": "could not save lifecycle record"})
			return
		}
	}
	emails := rec.AlertEmails
	if emails == nil {
		emails = []string{}
	}
	jsonOut(w, 200, map[string]any{"pen": pen, "alert_emails": emails})
}

type pendingCancelItem struct {
	Pen            string `json:"pen"`
	SubscriptionID string `json:"subscription_id"`
}

// lifecyclePendingCancels returns replaced Stripe subscriptions queued by
// recordRenewal so signup-web (which holds the Stripe key) can cancel them (I-6).
func (b *broker) lifecyclePendingCancels(w http.ResponseWriter, r *http.Request) {
	b.lifecycleMu.Lock()
	defer b.lifecycleMu.Unlock()

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
		for _, subID := range rec.PendingCancelSubs {
			if subID != "" && subID != "-" {
				items = append(items, pendingCancelItem{Pen: e.Name(), SubscriptionID: subID})
			}
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
	rec, err := loadPenLifecycle(path)
	if err != nil {
		jsonOut(w, 404, map[string]string{"error": "pen not found"})
		return
	}
	kept := make([]string, 0, len(rec.PendingCancelSubs))
	removed := false
	for _, q := range rec.PendingCancelSubs {
		if q == subID {
			removed = true
			continue
		}
		kept = append(kept, q)
	}
	if removed {
		rec.PendingCancelSubs = kept
		rec.UpdatedAt = time.Now().UTC().Unix()
		if err := savePenLifecycle(path, rec); err != nil {
			jsonOut(w, 500, map[string]string{"error": "could not save lifecycle"})
			return
		}
		b.ledger(fmt.Sprintf("%s cancelled replaced Stripe subscription %s for pen %s", time.Now().UTC().Format(time.RFC3339), subID, pen))
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
	msg := fmt.Sprintf("Could not cancel replaced Stripe subscription %s for pen %s (cancel manually or grant Subscriptions: Write): %s",
		subID, pen, cleanField(in.Error, 200))
	log.Print(msg)
	b.notifyKind("health", msg)
	jsonOut(w, 200, map[string]any{"ok": true})
}
