package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPresenceCacheTTLCoalescingAndErrorBackoff(t *testing.T) {
	var clockMu sync.Mutex
	cur := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return cur
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		cur = cur.Add(d)
		clockMu.Unlock()
	}

	var calls atomic.Int32
	gate := make(chan struct{})
	var failFetch atomic.Bool
	cache := newPresenceCache(
		clock,
		5*time.Second,
		time.Second,
		context.Background,
		func(fn func()) bool { go fn(); return true },
		func(ctx context.Context) ([]HSNode, error) {
			calls.Add(1)
			<-gate
			if failFetch.Load() {
				return nil, errors.New("upstream down")
			}
			return []HSNode{{ID: "n1", Online: true}}, nil
		},
	)

	// Overlapping calls coalesce into a single fetch.
	var wg sync.WaitGroup
	results := make([]map[string]HSNode, 2)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = cache.Snapshot(context.Background())
		}(i)
	}
	time.Sleep(10 * time.Millisecond)
	close(gate)
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("coalesced fetch count = %d, want 1", calls.Load())
	}
	for i, snap := range results {
		if !snap["n1"].Online {
			t.Fatalf("caller %d got %+v, want n1 online", i, snap)
		}
	}

	// Within TTL, cached snapshot is served without re-fetching.
	advance(2 * time.Second)
	snap := cache.Snapshot(context.Background())
	if !snap["n1"].Online || calls.Load() != 1 {
		t.Fatalf("within TTL: calls=%d snap=%+v", calls.Load(), snap)
	}

	// Past TTL with failing upstream returns stale snapshot and backs off for TTL.
	advance(4 * time.Second)
	failFetch.Store(true)
	snap = cache.Snapshot(context.Background())
	if !snap["n1"].Online || calls.Load() != 2 {
		t.Fatalf("stale on failure: calls=%d snap=%+v", calls.Load(), snap)
	}
	if snap = cache.Snapshot(context.Background()); !snap["n1"].Online || calls.Load() != 2 {
		t.Fatalf("error backoff should prevent immediate retry and keep stale snapshot, calls=%d snap=%+v", calls.Load(), snap)
	}
}

func TestKeyRotatorCoalescingCooldownAndConcurrencyCap(t *testing.T) {
	var clockMu sync.Mutex
	cur := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return cur
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		cur = cur.Add(d)
		clockMu.Unlock()
	}

	rot := newKeyRotator(clock, 10*time.Second, 1, func(fn func()) bool { go fn(); return true }, nil)

	// 1. Overlapping requests for the same node coalesce; a second distinct node hits concurrency cap=1.
	started := make(chan struct{})
	release := make(chan struct{})
	var runs atomic.Int32

	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			errCh <- rot.Do(context.Background(), "node-1", func() error {
				if runs.Add(1) == 1 {
					close(started)
				}
				<-release
				return nil
			})
		}()
	}
	<-started
	if err := rot.Do(context.Background(), "node-2", func() error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("concurrency-capped node-2 = %v, want ErrNotFound", err)
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("coalesced node-1 caller %d = %v, want nil", i, err)
		}
	}
	if runs.Load() != 1 {
		t.Fatalf("node-1 fn runs = %d, want 1", runs.Load())
	}

	// 2. Immediate repeat for node-1 hits per-node cooldown; advancing past cooldown succeeds.
	if err := rot.Do(context.Background(), "node-1", func() error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cooldown node-1 = %v, want ErrNotFound", err)
	}
	advance(11 * time.Second)
	if err := rot.Do(context.Background(), "node-1", func() error { return nil }); err != nil {
		t.Fatalf("post-cooldown node-1 = %v, want nil", err)
	}
}
