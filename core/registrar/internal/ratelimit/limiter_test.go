package ratelimit

import (
	"testing"
	"time"
)

func TestSlidingWindowCheckRecordAndExpiryEviction(t *testing.T) {
	lim := NewWindow[int64](2, time.Minute, 16)
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	if ok, retry := lim.Check(1, t0); !ok || retry != 0 {
		t.Fatalf("first Check = (%v, %d), want (true, 0)", ok, retry)
	}
	if lim.Len() != 0 {
		t.Fatalf("Check on unseen key should not allocate entry, len=%d", lim.Len())
	}

	lim.Record(1, t0)
	lim.Record(1, t0.Add(15*time.Second))

	ok, retry := lim.Check(1, t0.Add(20*time.Second))
	if ok || retry != 40 {
		t.Fatalf("at +20s Check = (%v, %d), want (false, 40)", ok, retry)
	}

	ok, retry = lim.Check(1, t0.Add(59*time.Second+500*time.Millisecond))
	if ok || retry != 1 {
		t.Fatalf("at +59.5s Check = (%v, %d), want (false, 1)", ok, retry)
	}

	if ok, retry := lim.Check(1, t0.Add(time.Minute)); !ok || retry != 0 {
		t.Fatalf("at +60s Check = (%v, %d), want (true, 0)", ok, retry)
	}

	if ok, retry := lim.Check(1, t0.Add(76*time.Second)); !ok || retry != 0 {
		t.Fatalf("at +76s Check = (%v, %d), want (true, 0)", ok, retry)
	}
	if lim.Len() != 0 {
		t.Fatalf("expired key should be evicted on Check, len=%d", lim.Len())
	}
}

func TestSlidingWindowCapSweepsExpiredBeforeLRU(t *testing.T) {
	lim := NewWindow[string](2, time.Minute, 3)
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	if ok, _ := lim.Allow("stale", t0); !ok {
		t.Fatal("stale should be allowed")
	}
	if ok, _ := lim.Allow("active-1", t0.Add(30*time.Second)); !ok {
		t.Fatal("active-1 should be allowed")
	}
	if ok, _ := lim.Allow("active-2", t0.Add(40*time.Second)); !ok {
		t.Fatal("active-2 should be allowed")
	}
	if ok, _ := lim.Allow("active-1", t0.Add(45*time.Second)); !ok {
		t.Fatal("active-1 second hit should be allowed")
	}

	if ok, _ := lim.Allow("fresh", t0.Add(65*time.Second)); !ok {
		t.Fatal("fresh should be allowed")
	}
	if lim.Len() != 3 {
		t.Fatalf("len = %d, want 3", lim.Len())
	}
	if ok, _ := lim.Allow("active-1", t0.Add(66*time.Second)); ok {
		t.Fatal("active-1 should still be rate-limited after stale sweep")
	}
}

func TestSlidingWindowZeroLimitDisabled(t *testing.T) {
	lim := NewWindow[int64](0, time.Minute, 4)
	t0 := time.Now()
	if ok, retry := lim.Allow(7, t0); !ok || retry != 0 {
		t.Fatalf("zero-limit Allow = (%v, %d), want (true, 0)", ok, retry)
	}
	lim.Record(7, t0)
	if lim.Len() != 0 {
		t.Fatalf("zero-limit limiter should not track keys, len=%d", lim.Len())
	}
}

func TestStrictSlidingWindowFailsClosedInsteadOfEvictingActiveKeys(t *testing.T) {
	lim := NewStrictWindow[int64](1, time.Minute, 2)
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	if ok, _ := lim.Allow(10, t0); !ok {
		t.Fatal("key 10 should pass")
	}
	if ok, _ := lim.Allow(20, t0.Add(10*time.Second)); !ok {
		t.Fatal("key 20 should pass")
	}
	if ok, retry := lim.Check(30, t0.Add(20*time.Second)); ok || retry != 40 {
		t.Fatalf("full strict limiter Check(30) = (%v, %d), want (false, 40)", ok, retry)
	}
	if ok, _ := lim.Check(10, t0.Add(25*time.Second)); ok {
		t.Fatal("active key 10 must remain throttled")
	}
	if ok, _ := lim.Allow(30, t0.Add(61*time.Second)); !ok {
		t.Fatal("key 30 should pass after expired key 10 is swept")
	}
}
