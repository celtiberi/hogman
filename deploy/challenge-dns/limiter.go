package main

import (
	"sync"
	"time"
)

const (
	defaultGlobalEABPerMin  = 20
	defaultGlobalEABPerHour = 90
	defaultCredFailPerMin   = 5
	defaultCredFailPerHour  = 15
)

// windowLimiter allows at most perMin events a minute and perHour an hour.
type windowLimiter struct {
	mu              sync.Mutex
	perMin, perHour int
	events          []time.Time
}

func (l *windowLimiter) pruneLocked(now time.Time) (min int) {
	kept := l.events[:0]
	for _, t := range l.events {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
			if now.Sub(t) < time.Minute {
				min++
			}
		}
	}
	l.events = kept
	return min
}

func (l *windowLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	min := l.pruneLocked(now)
	if min >= l.perMin || len(l.events) >= l.perHour {
		return false
	}
	l.events = append(l.events, now)
	return true
}

func (l *windowLimiter) exceeded(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	min := l.pruneLocked(now)
	return min >= l.perMin || len(l.events) >= l.perHour
}

func (l *windowLimiter) empty(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	return len(l.events) == 0
}

func (l *windowLimiter) record(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	l.events = append(l.events, now)
}

// eabLimiter coordinates upstream EAB throttling in one place:
//   - host credentials (gate wildcard) are always exempt so front-door failover
//     is never starved by pen traffic;
//   - per-credential failure cooldown is checked BEFORE consuming a global slot
//     so one failing pen cannot burn fleet-wide upstream headroom;
//   - global burst brake remains consumed even if upstream Mint later fails so
//     fleet-wide upstream calls stay bounded during a CA outage;
//   - expired per-credential failure entries are pruned on every write/check.
type eabLimiter struct {
	mu          sync.Mutex
	now         func() time.Time
	global      *windowLimiter
	failPerMin  int
	failPerHour int
	credFails   map[string]*windowLimiter
}

func newEABLimiter(globalPerMin, globalPerHour, failPerMin, failPerHour int, now func() time.Time) *eabLimiter {
	if now == nil {
		now = time.Now
	}
	return &eabLimiter{
		now:         now,
		global:      &windowLimiter{perMin: globalPerMin, perHour: globalPerHour},
		failPerMin:  failPerMin,
		failPerHour: failPerHour,
		credFails:   map[string]*windowLimiter{},
	}
}

func defaultEABLimiter(now func() time.Time) *eabLimiter {
	return newEABLimiter(
		defaultGlobalEABPerMin,
		defaultGlobalEABPerHour,
		defaultCredFailPerMin,
		defaultCredFailPerHour,
		now,
	)
}

// Allow checks whether an upstream EAB mint attempt for (kind, credID) may
// proceed and, if so, consumes one slot from the shared global burst limiter.
// On rejection, reason carries a client-safe rate-limit message.
func (l *eabLimiter) Allow(kind, credID string) (ok bool, reason string) {
	if kind == "host" {
		return true, ""
	}
	now := l.now()
	if l.inCooldown(credID, now) {
		return false, "fallback account key requests are cooling down after upstream errors; try later"
	}
	if !l.global.allow(now) {
		return false, "fallback account keys are rate-limited; try later"
	}
	return true, ""
}

func (l *eabLimiter) inCooldown(credID string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim := l.credFails[credID]
	if lim == nil {
		return false
	}
	if lim.exceeded(now) {
		return true
	}
	if lim.empty(now) {
		delete(l.credFails, credID)
	}
	return false
}

// RecordFailure records an upstream EAB mint error for a pen credential and
// sweeps expired failure buckets for other credentials so memory stays bounded.
func (l *eabLimiter) RecordFailure(kind, credID string) {
	if kind == "host" {
		return
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.credFails == nil {
		l.credFails = map[string]*windowLimiter{}
	}
	for id, existing := range l.credFails {
		if id != credID && existing.empty(now) {
			delete(l.credFails, id)
		}
	}
	lim := l.credFails[credID]
	if lim == nil {
		lim = &windowLimiter{perMin: l.failPerMin, perHour: l.failPerHour}
		l.credFails[credID] = lim
	}
	lim.record(now)
}

func (l *eabLimiter) trackedFailureCreds() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.credFails)
}

func (l *eabLimiter) hasFailureRecord(credID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.credFails[credID]
	return ok
}
