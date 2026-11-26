package main

import (
	"testing"
	"time"
)

func TestSlidingWindowCheckRecordAndExpiryEviction(t *testing.T) {
	lim := newSlidingWindow[int64](2, time.Minute, 16)
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	// Two-phase Check does not consume budget until Record is called.
	if ok, retry := lim.Check(1, t0); !ok || retry != 0 {
		t.Fatalf("first Check = (%v, %d), want (true, 0)", ok, retry)
	}
	if lim.Len() != 0 {
		t.Fatalf("Check on unseen key should not allocate entry, len=%d", lim.Len())
	}

	lim.Record(1, t0)
	lim.Record(1, t0.Add(15*time.Second))

	// At t0+20s the oldest hit expires in 40s.
	ok, retry := lim.Check(1, t0.Add(20*time.Second))
	if ok || retry != 40 {
		t.Fatalf("at +20s Check = (%v, %d), want (false, 40)", ok, retry)
	}

	// Fractional seconds round up to >= 1.
	ok, retry = lim.Check(1, t0.Add(59*time.Second+500*time.Millisecond))
	if ok || retry != 1 {
		t.Fatalf("at +59.5s Check = (%v, %d), want (false, 1)", ok, retry)
	}

	// Once oldest hit expires (+60s), one slot re-opens while the +15s hit remains.
	if ok, retry := lim.Check(1, t0.Add(time.Minute)); !ok || retry != 0 {
		t.Fatalf("at +60s Check = (%v, %d), want (true, 0)", ok, retry)
	}

	// Once all hits expire (+76s), Check deletes the empty key from the map.
	if ok, retry := lim.Check(1, t0.Add(76*time.Second)); !ok || retry != 0 {
		t.Fatalf("at +76s Check = (%v, %d), want (true, 0)", ok, retry)
	}
	if lim.Len() != 0 {
		t.Fatalf("expired key should be evicted on Check, len=%d", lim.Len())
	}
}

func TestSlidingWindowCapSweepsExpiredBeforeLRU(t *testing.T) {
	lim := newSlidingWindow[string](2, time.Minute, 3)
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	// Fill cap with an expired key ("stale") and two active keys.
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

	// At t0+65s, "stale" is expired. Inserting "fresh" sweeps "stale" and keeps both active keys.
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
	lim := newSlidingWindow[int64](0, time.Minute, 4)
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
	lim := newStrictSlidingWindow[int64](1, time.Minute, 2)
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	if ok, _ := lim.Allow(10, t0); !ok {
		t.Fatal("key 10 should pass")
	}
	if ok, _ := lim.Allow(20, t0.Add(10*time.Second)); !ok {
		t.Fatal("key 20 should pass")
	}
	// Cap reached with active buckets: key 30 must fail closed (never evict active key 10).
	if ok, retry := lim.Check(30, t0.Add(20*time.Second)); ok || retry != 40 {
		t.Fatalf("full strict limiter Check(30) = (%v, %d), want (false, 40)", ok, retry)
	}
	if ok, _ := lim.Check(10, t0.Add(25*time.Second)); ok {
		t.Fatal("active key 10 must remain throttled")
	}
	// Once key 10 expires (+61s), sweep frees its slot and key 30 is admitted.
	if ok, _ := lim.Allow(30, t0.Add(61*time.Second)); !ok {
		t.Fatal("key 30 should pass after expired key 10 is swept")
	}
}
