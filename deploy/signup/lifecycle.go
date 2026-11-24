package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Pen lifecycle state machine (D-35):
//
//   Paid pen (personal $50/yr, work $120/yr):
//     active  --(now >= paid_until)-->  grace (30 days, all-member banner, owner/admin can pay)
//     grace   --(now >= grace_until)--> sleeping (stopped, no slot used, state kept for 1 year)
//     sleeping --(now >= delete_after)-> deleted (state removed, name stays retired per D-21)
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

	lifecycleGraceDuration = 30 * 24 * time.Hour
	lifecycleSleepDuration = 365 * 24 * time.Hour
	lifecycleYearDuration  = 365 * 24 * time.Hour
	lifecyclePreAlertLead  = 30 * 24 * time.Hour
	lifecycleFinalLead     = 7 * 24 * time.Hour
)

type penLifecycle struct {
	Plan            string           `json:"plan"` // "free" | "personal" | "work"
	State           string           `json:"state"`
	PaidUntil       int64            `json:"paid_until,omitempty"`
	GraceUntil      int64            `json:"grace_until,omitempty"`
	SleepSince      int64            `json:"sleep_since,omitempty"`
	DeleteAfter     int64            `json:"delete_after,omitempty"`
	SubscriptionID  string           `json:"subscription_id,omitempty"`
	CustomerID      string           `json:"customer_id,omitempty"`
	CancelledAt     int64            `json:"cancelled_at,omitempty"`
	BackdateRenewal bool             `json:"backdate_renewal"` // D-35 default: false
	AlertEmails     []string         `json:"alert_emails,omitempty"`
	AlertsSent      map[string]int64 `json:"alerts_sent,omitempty"`
	RenewURL        string           `json:"renew_url,omitempty"`
	UpdatedAt       int64            `json:"updated_at,omitempty"`
}

type portalBillingStatus struct {
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
	ActionNote string `json:"note,omitempty"`
}

func (b *broker) lifecyclePath(pen string) string {
	return filepath.Join(b.home, "pens", pen, "lifecycle.json")
}

func (b *broker) portalBillingPath(pen string) string {
	return filepath.Join(b.home, "pens", pen, "data", "portal", "billing-status.json")
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

func syncPortalBillingBanner(portalPath string, rec *penLifecycle) error {
	if rec.State != stateGrace {
		err := os.Remove(portalPath)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// Only write when the pen's portal directory already exists.
	if fi, err := os.Stat(filepath.Dir(portalPath)); err != nil || !fi.IsDir() {
		return nil
	}
	st := portalBillingStatus{
		State:    stateGrace,
		RenewURL: sanitizeHTTPSURL(rec.RenewURL),
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
	tmp, err := os.CreateTemp(filepath.Dir(portalPath), ".billing-*")
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
	if err := os.Rename(tmpPath, portalPath); err != nil {
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

// evaluateLifecycle computes the next D-35 lifecycle state for rec at now
// without mutating external systems. Returns a copy of the updated record and
// whether a state transition occurred.
func evaluateLifecycle(rec penLifecycle, now time.Time) (next penLifecycle, transitioned bool) {
	next = rec
	nowUnix := now.UTC().Unix()
	if next.State == "" {
		next.State = stateActive
	}
	if next.State == stateDeleted {
		return next, false
	}

	// Paid pens move active -> grace -> sleeping -> deleted on fixed D-35 timers.
	if next.Plan == planPersonal || next.Plan == planWork {
		if next.State == stateActive && next.PaidUntil > 0 && nowUnix >= next.PaidUntil {
			next.State = stateGrace
			next.GraceUntil = time.Unix(next.PaidUntil, 0).UTC().Add(lifecycleGraceDuration).Unix()
			next.UpdatedAt = nowUnix
			transitioned = true
		}
		if next.State == stateGrace && next.GraceUntil > 0 && nowUnix >= next.GraceUntil {
			next.State = stateSleeping
			next.SleepSince = nowUnix
			next.DeleteAfter = now.UTC().Add(lifecycleSleepDuration).Unix()
			next.UpdatedAt = nowUnix
			transitioned = true
		}
	}

	// Any sleeping pen (paid or best-effort free put to sleep by operator) is
	// deleted after 1 year asleep, keeping its name retired per D-21.
	if next.State == stateSleeping && next.DeleteAfter > 0 && nowUnix >= next.DeleteAfter {
		next.State = stateDeleted
		next.UpdatedAt = nowUnix
		transitioned = true
	}
	return next, transitioned
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
	next.AlertsSent = nil // reset per-cycle alert deduplication for the new paid year
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
				fmt.Sprintf("Your Hogman pen (%s) is paid through %s.\nIf auto-renewal is off, any owner or admin can renew for another year before %s to avoid the 30-day grace period.\n", pen, dueDate, dueDate),
				true
		}
	case stateGrace:
		if rec.GraceUntil > 0 && nowUnix >= rec.GraceUntil-int64(lifecycleFinalLead.Seconds()) && !sent("grace-day-23") {
			sleepDate := time.Unix(rec.GraceUntil, 0).UTC().Format("2006-01-02")
			return "grace-day-23",
				fmt.Sprintf("Hogman pen %s goes to sleep on %s", pen, sleepDate),
				fmt.Sprintf("Your Hogman pen (%s) is in its 30-day grace period and will go to sleep on %s.\nAny owner or admin can pay for a fresh year to keep it awake (an admin who pays becomes an owner).\n", pen, sleepDate),
				true
		}
		if !sent("grace-start") {
			sleepDate := time.Unix(rec.GraceUntil, 0).UTC().Format("2006-01-02")
			return "grace-start",
				fmt.Sprintf("Hogman pen %s entered its 30-day grace period", pen),
				fmt.Sprintf("Your Hogman pen (%s) passed its paid-until date and is now in its 30-day grace period (stays awake until %s).\nAny owner or admin can pay for a fresh year starting from the day of payment.\n", pen, sleepDate),
				true
		}
	case stateSleeping:
		if !sent("sleeping") {
			delDate := time.Unix(rec.DeleteAfter, 0).UTC().Format("2006-01-02")
			return "sleeping",
				fmt.Sprintf("Hogman pen %s is now asleep", pen),
				fmt.Sprintf("Your Hogman pen (%s) has been put to sleep after 30 days unpaid. Its state is kept until %s; any owner or admin can pay for a fresh year before then to wake it up.\n", pen, delDate),
				true
		}
	}
	return "", "", "", false
}

func (b *broker) sendBillingAlert(ctx context.Context, to []string, subject, text string) error {
	if b.alertSendFn != nil {
		return b.alertSendFn(ctx, to, subject, text)
	}
	if b.resendAPIKey == "" || b.billingFrom == "" {
		return nil // email alerts not configured on this host
	}
	var valid []string
	for _, addr := range to {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if validEmail(addr) {
			valid = append(valid, addr)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	payload, err := json.Marshal(map[string]any{
		"from":    b.billingFrom,
		"to":      valid,
		"subject": subject,
		"text":    text,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.resend.com/emails", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.resendAPIKey)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("resend returned HTTP %d", resp.StatusCode)
	}
	return nil
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

// renewPen applies a D-35 payment renewal to pen (waking it if asleep and
// promoting an existing admin payer to owner when payerHandle is provided).
func (b *broker) renewPen(ctx context.Context, pen, payerHandle, subID, custID string, now time.Time) (*penLifecycle, error) {
	path := b.lifecyclePath(pen)
	rec, err := loadPenLifecycle(path)
	if err != nil {
		return nil, err
	}
	if rec.State == stateDeleted {
		return nil, fmt.Errorf("pen %s has already been deleted", pen)
	}
	backdate := b.backdateRenewal || rec.BackdateRenewal
	next, wasSleeping := applyRenewal(*rec, now, backdate)
	if subID != "" && subID != "-" {
		next.SubscriptionID = subID
	}
	if custID != "" && custID != "-" {
		next.CustomerID = custID
	}
	if err := savePenLifecycle(path, &next); err != nil {
		return nil, err
	}
	if err := syncPortalBillingBanner(b.portalBillingPath(pen), &next); err != nil {
		log.Printf("lifecycle %s: clear grace banner: %v", pen, err)
	}
	if wasSleeping {
		_, code, stderr := b.runUnbounded(ctx, "wake", pen)
		b.invalidateCapacityCache()
		if code != 0 {
			return &next, fmt.Errorf("pen %s renewed in ledger, but wake failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
		}
	}
	if h := strings.ToLower(strings.TrimSpace(payerHandle)); h != "" {
		if _, ok := validHandle(h); ok {
			// D-35: an existing admin who pays becomes an owner (best-effort if already owner).
			_, code, stderr := b.runUnbounded(ctx, "pen", pen, "member", "role", h, "owner")
			if code != 0 {
				log.Printf("lifecycle %s: promote payer %s to owner (exit %d): %s", pen, h, code, strings.TrimSpace(stderr))
			}
		}
	}
	b.ledger(fmt.Sprintf("%s renewed %s until %s (backdate=%v, woke=%v)",
		now.UTC().Format(time.RFC3339), pen, time.Unix(next.PaidUntil, 0).UTC().Format("2006-01-02"), backdate, wasSleeping))
	return &next, nil
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

// sweepLifecycles evaluates every pen's lifecycle.json at now, applies D-35
// transitions (grace banner -> sleep -> purge) and sends due opt-in alerts.
func (b *broker) sweepLifecycles(ctx context.Context, now time.Time, dryRun bool) ([]lifecycleTransition, error) {
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
		next, changed := evaluateLifecycle(*rec, now)
		tr := lifecycleTransition{Pen: pen, From: rec.State, To: next.State, DryRun: dryRun}

		if changed {
			if !dryRun {
				switch next.State {
				case stateGrace:
					if err := savePenLifecycle(path, &next); err != nil {
						log.Printf("lifecycle %s: save grace: %v", pen, err)
						continue
					}
					if err := syncPortalBillingBanner(b.portalBillingPath(pen), &next); err != nil {
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
					_ = syncPortalBillingBanner(b.portalBillingPath(pen), &next)
					b.ledger(fmt.Sprintf("%s lifecycle %s: %s -> sleeping (delete after %s)",
						now.UTC().Format(time.RFC3339), pen, rec.State, time.Unix(next.DeleteAfter, 0).UTC().Format("2006-01-02")))
				case stateDeleted:
					_, code, stderr := b.runUnbounded(ctx, "purge", pen)
					b.invalidateCapacityCache()
					if code != 0 {
						log.Printf("lifecycle %s: purge failed (exit %d): %s", pen, code, strings.TrimSpace(stderr))
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

		// Check opt-in Owner/Admin billing alert email for the resulting state.
		if milestone, subj, body, due := dueBillingAlert(pen, next, now); due {
			if !dryRun {
				if err := b.sendBillingAlert(ctx, next.AlertEmails, subj, body); err != nil {
					log.Printf("lifecycle %s: send alert %s: %v", pen, milestone, err)
				} else {
					if next.AlertsSent == nil {
						next.AlertsSent = map[string]int64{}
					}
					next.AlertsSent[milestone] = now.UTC().Unix()
					_ = savePenLifecycle(path, &next)
				}
			}
			if !changed {
				out = append(out, lifecycleTransition{Pen: pen, From: rec.State, To: next.State, DryRun: dryRun, AlertSent: milestone})
			} else {
				out[len(out)-1].AlertSent = milestone
			}
		}
	}
	return out, nil
}

func (b *broker) lifecycleSweepHandler(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "1" || r.URL.Query().Get("dry_run") == "true"
	b.mu.Lock()
	defer b.mu.Unlock()
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
