package main

import (
	"testing"
	"time"
)

func TestWindowLimiterSlidingWindows(t *testing.T) {
	t.Parallel()
	l := &windowLimiter{perMin: 2, perHour: 3}
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	first, second, third := l.allow(now), l.allow(now), l.allow(now)
	if !first || !second || third {
		t.Fatal("per-minute limit not enforced")
	}
	now = now.Add(2 * time.Minute)
	fourth, fifth := l.allow(now), l.allow(now)
	if !fourth || fifth {
		t.Fatal("per-hour limit not enforced")
	}
	now = now.Add(time.Hour)
	if !l.empty(now) {
		t.Fatal("expected limiter empty after full hour")
	}
}

func TestEABLimiterHostExemptAndCooldownIsolation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	lim := newEABLimiter(4, 4, 2, 5, func() time.Time { return now })

	// Failing penA hits its 2/min cooldown without exhausting global headroom (4/min) for penB.
	for i := 0; i < 2; i++ {
		if ok, reason := lim.Allow("pen", "pen-a"); !ok {
			t.Fatalf("pen-a attempt %d unexpectedly denied: %s", i, reason)
		}
		lim.RecordFailure("pen", "pen-a")
	}
	if ok, _ := lim.Allow("pen", "pen-a"); ok {
		t.Fatal("pen-a should be in failure cooldown")
	}
	// Rejected cooldown attempts must not burn global slots: pen-b still gets the remaining 2 global slots.
	for i := 0; i < 5; i++ {
		if ok, _ := lim.Allow("pen", "pen-a"); ok {
			t.Fatalf("pen-a cooldown retry %d unexpectedly allowed", i)
		}
	}
	for i := 0; i < 2; i++ {
		if ok, reason := lim.Allow("pen", "pen-b"); !ok {
			t.Fatalf("pen-b slot %d denied: %s", i, reason)
		}
	}
	// Global 4/min cap is now full: pen-c is denied, but host credential stays exempt.
	if ok, _ := lim.Allow("pen", "pen-c"); ok {
		t.Fatal("pen-c should hit global burst cap")
	}
	for i := 0; i < 3; i++ {
		if ok, reason := lim.Allow("host", "host-1"); !ok {
			t.Fatalf("host attempt %d denied: %s", i, reason)
		}
		lim.RecordFailure("host", "host-1")
	}
	if lim.hasFailureRecord("host-1") {
		t.Fatal("host failure should not be tracked in credFails")
	}

	// After an hour, recording a failure for another cred prunes pen-a's expired bucket.
	now = now.Add(time.Hour + time.Minute)
	lim.RecordFailure("pen", "pen-d")
	if lim.hasFailureRecord("pen-a") || !lim.hasFailureRecord("pen-d") || lim.trackedFailureCreds() != 1 {
		t.Fatalf("expired credFails not pruned: hasA=%v hasD=%v total=%d",
			lim.hasFailureRecord("pen-a"), lim.hasFailureRecord("pen-d"), lim.trackedFailureCreds())
	}
}
