package registrar

import (
	"context"
	"errors"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hogman/registrar/internal/headscale"
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
		func(ctx context.Context) ([]headscale.Node, error) {
			calls.Add(1)
			<-gate
			if failFetch.Load() {
				return nil, errors.New("upstream down")
			}
			return []headscale.Node{{ID: "n1", Online: true}}, nil
		},
	)

	// Overlapping calls coalesce into a single fetch.
	var wg sync.WaitGroup
	results := make([]map[string]headscale.Node, 2)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = cache.Snapshot(context.Background())
		}(i)
	}
	// Wait deterministically until the second caller has coalesced onto the in-flight call.
	for {
		cache.mu.RLock()
		joined := cache.flight != nil && cache.flight.waiters == 1
		cache.mu.RUnlock()
		if joined {
			break
		}
		runtime.Gosched()
	}
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
	// Wait deterministically until the second node-1 caller has joined the in-flight call.
	for {
		rot.mu.Lock()
		joined := rot.flight["node-1"] != nil && rot.flight["node-1"].waiters == 1
		rot.mu.Unlock()
		if joined {
			break
		}
		runtime.Gosched()
	}
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

func TestCanonicalKeysAndAddDeviceReserveOverflow(t *testing.T) {
	wantNK := "nodekey:1ee6564c897e325f8631ee28e929237ee135e0cbbad1e5038e4c40791ee4ec73"
	bareUpperNK := strings.ToUpper(strings.TrimPrefix(wantNK, "nodekey:"))
	if got, ok := canonicalNodeKey(bareUpperNK); !ok || got != wantNK {
		t.Fatalf("canonicalNodeKey(bare upper) = (%q, %v), want (%q, true)", got, ok, wantNK)
	}
	wantMK := "mkey:1ee6564c897e325f8631ee28e929237ee135e0cbbad1e5038e4c40791ee4ec73"
	bareUpperMK := strings.ToUpper(strings.TrimPrefix(wantMK, "mkey:"))
	if got, ok := canonicalMachineKey(bareUpperMK); !ok || got != wantMK {
		t.Fatalf("canonicalMachineKey(bare upper) = (%q, %v), want (%q, true)", got, ok, wantMK)
	}
	if _, ok := canonicalNodeKey("nodekey:0000000000000000000000000000000000000000000000000000000000000000"); ok {
		t.Fatal("canonicalNodeKey accepted all-zero key")
	}
	if _, ok := canonicalMachineKey("mkey:not-valid-hex"); ok {
		t.Fatal("canonicalMachineKey accepted invalid hex")
	}
	if addDeviceReserve(math.MaxInt) != math.MaxInt {
		t.Fatalf("addDeviceReserve(MaxInt) overflowed: %d", addDeviceReserve(math.MaxInt))
	}
}
