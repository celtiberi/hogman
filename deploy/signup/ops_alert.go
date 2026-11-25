package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	setPolicyAlertThresholdMs = 5000
	setPolicyAlertCooldown    = 6 * time.Hour
	opsSnapshotMaxAge         = 10 * time.Minute
	opsSnapshotMaxFutureSkew  = 2 * time.Minute
	maxOpsSnapshotBytes       = 2 << 20
)

type opsSnapshotSummary struct {
	GeneratedAt string              `json:"generated_at"`
	Pens        []opsSnapshotPenRow `json:"pens"`
}

type opsSnapshotPenRow struct {
	Name             string `json:"name"`
	State            string `json:"state"`
	SetPolicySamples int    `json:"setpolicy_samples"`
	SetPolicyLastMs  int64  `json:"setpolicy_last_ms"`
	SetPolicyP95Ms   int64  `json:"setpolicy_p95_ms"`
}

// checkSetPolicyLatencyAlerts reads the host's read-only Fleet Ops snapshot (if
// present and fresh) and pushes one aggregated, rate-limited "ops" ntfy alert
// whenever live pens have p95 Headscale SetPolicy latency > 5 seconds (I-30).
// Per-pen cooldowns are only armed if the notification actually passed the
// limiter/semaphore so transient rate-limit drops never cause a 6-hour blackout.
func (b *broker) checkSetPolicyLatencyAlerts(now time.Time) []string {
	path := b.opsSnapshotPath
	if path == "" {
		return nil
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil
	}
	defer root.Close()
	f, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxOpsSnapshotBytes+1))
	if err != nil || len(raw) > maxOpsSnapshotBytes {
		return nil
	}
	var snap opsSnapshotSummary
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil
	}
	genAt, err := time.Parse(time.RFC3339, snap.GeneratedAt)
	if err != nil {
		return nil
	}
	nowUTC := now.UTC()
	age := nowUTC.Sub(genAt.UTC())
	if age > opsSnapshotMaxAge || age < -opsSnapshotMaxFutureSkew {
		return nil
	}

	b.setPolicyAlertMu.Lock()
	if b.setPolicyAlerted == nil {
		b.setPolicyAlerted = map[string]time.Time{}
	}
	seenLive := map[string]bool{}
	var candidates []opsSnapshotPenRow
	for _, p := range snap.Pens {
		if p.Name == "" || (p.State != "running" && p.State != "renew_only") {
			continue
		}
		seenLive[p.Name] = true
		if p.SetPolicySamples <= 0 {
			continue
		}
		if p.SetPolicyP95Ms <= setPolicyAlertThresholdMs {
			delete(b.setPolicyAlerted, p.Name)
			continue
		}
		if prev, ok := b.setPolicyAlerted[p.Name]; ok && nowUTC.Sub(prev) < setPolicyAlertCooldown {
			continue
		}
		candidates = append(candidates, p)
	}
	for name := range b.setPolicyAlerted {
		if !seenLive[name] {
			delete(b.setPolicyAlerted, name)
		}
	}
	b.setPolicyAlertMu.Unlock()

	if len(candidates) == 0 {
		return nil
	}

	var msg string
	if len(candidates) == 1 {
		p := candidates[0]
		msg = fmt.Sprintf(
			"Slow SetPolicy on pen %s: p95 %dms (last %dms across %d pushes) exceeds %dms threshold",
			p.Name, p.SetPolicyP95Ms, p.SetPolicyLastMs, p.SetPolicySamples, setPolicyAlertThresholdMs,
		)
	} else {
		parts := make([]string, 0, len(candidates))
		for _, p := range candidates {
			parts = append(parts, fmt.Sprintf("%s (p95 %dms, last %dms)", p.Name, p.SetPolicyP95Ms, p.SetPolicyLastMs))
		}
		msg = fmt.Sprintf(
			"Slow SetPolicy on %d pens (>%dms p95): %s",
			len(candidates), setPolicyAlertThresholdMs, strings.Join(parts, ", "),
		)
	}

	if !b.notifyKind("ops", msg) {
		return nil
	}

	alerted := make([]string, 0, len(candidates))
	b.setPolicyAlertMu.Lock()
	for _, p := range candidates {
		b.setPolicyAlerted[p.Name] = nowUTC
		alerted = append(alerted, p.Name)
	}
	b.setPolicyAlertMu.Unlock()

	b.ledger(fmt.Sprintf("%s ops-alert: %s", nowUTC.Format(time.RFC3339), msg))
	return alerted
}
