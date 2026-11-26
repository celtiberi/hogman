package main

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

const defaultLimiterMaxKeys = 1024

type windowBucket struct {
	hits []time.Time
	last time.Time
}

// slidingWindow is a concurrency-safe, bounded-memory sliding-window rate
// limiter. It supports both one-step Allow (for public HTTP endpoints) and
// two-phase Check+Record (so failed upstream calls do not consume budget).
//
// Empty keys are pruned on lookup and expired keys are swept before LRU
// eviction whenever the key cap is reached.
type slidingWindow[K comparable] struct {
	mu          sync.Mutex
	limit       int
	window      time.Duration
	maxKeys     int
	evictOnFull bool
	entries     map[K]*windowBucket
}

func newSlidingWindow[K comparable](limit int, window time.Duration, maxKeys int) *slidingWindow[K] {
	if maxKeys <= 0 {
		maxKeys = defaultLimiterMaxKeys
	}
	return &slidingWindow[K]{
		limit:       limit,
		window:      window,
		maxKeys:     maxKeys,
		evictOnFull: true,
		entries:     map[K]*windowBucket{},
	}
}

// newStrictSlidingWindow returns a bounded sliding-window limiter that sweeps
// expired entries when full and fails closed (instead of evicting an active
// throttled key) if maxKeys active buckets are already present.
func newStrictSlidingWindow[K comparable](limit int, window time.Duration, maxKeys int) *slidingWindow[K] {
	w := newSlidingWindow[K](limit, window, maxKeys)
	w.evictOnFull = false
	return w
}

// Check prunes expired hits for key and reports whether another hit is
// permitted against the limiter's configured limit without recording one.
func (w *slidingWindow[K]) Check(key K, now time.Time) (ok bool, retryAfter int) {
	return w.CheckLimit(key, w.limit, now)
}

// CheckLimit is like Check with a caller-supplied limit (useful when limits
// are configured dynamically on the caller). When denied, retryAfter is the
// number of seconds (at least 1) until the oldest in-window hit expires.
func (w *slidingWindow[K]) CheckLimit(key K, limit int, now time.Time) (ok bool, retryAfter int) {
	if limit <= 0 || w.window <= 0 {
		return true, 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.checkLocked(key, limit, now)
}

// Record records a hit for key at now, sweeping expired entries and evicting
// the least-recently-touched key if the map is at maxKeys.
func (w *slidingWindow[K]) Record(key K, now time.Time) {
	if w.limit <= 0 || w.window <= 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.recordLocked(key, now)
}

// Allow atomically checks the window for key and records a hit if allowed.
func (w *slidingWindow[K]) Allow(key K, now time.Time) (ok bool, retryAfter int) {
	if w.limit <= 0 || w.window <= 0 {
		return true, 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if ok, retryAfter = w.checkLocked(key, w.limit, now); !ok {
		return false, retryAfter
	}
	w.recordLocked(key, now)
	return true, 0
}

// Len returns the number of keys currently tracked in the limiter.
func (w *slidingWindow[K]) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries)
}

func (w *slidingWindow[K]) pruneBucket(b *windowBucket, now time.Time) {
	kept := b.hits[:0]
	for _, t := range b.hits {
		if now.Sub(t) < w.window {
			kept = append(kept, t)
		}
	}
	b.hits = kept
}

func (w *slidingWindow[K]) sweepExpiredLocked(now time.Time) {
	for k, b := range w.entries {
		w.pruneBucket(b, now)
		if len(b.hits) == 0 {
			delete(w.entries, k)
		}
	}
}

func (w *slidingWindow[K]) checkLocked(key K, limit int, now time.Time) (bool, int) {
	b, ok := w.entries[key]
	if !ok {
		if !w.evictOnFull && len(w.entries) >= w.maxKeys {
			w.sweepExpiredLocked(now)
			if len(w.entries) >= w.maxKeys {
				// Fail closed when all slots hold active buckets rather than
				// evicting an active throttled key (e.g. server-churn bypass).
				var earliest time.Time
				for _, existing := range w.entries {
					if len(existing.hits) > 0 && (earliest.IsZero() || existing.hits[0].Before(earliest)) {
						earliest = existing.hits[0]
					}
				}
				secs := 1
				if !earliest.IsZero() {
					rem := earliest.Add(w.window).Sub(now)
					if s := int((rem + time.Second - 1) / time.Second); s > 1 {
						secs = s
					}
				}
				return false, secs
			}
		}
		return true, 0
	}
	w.pruneBucket(b, now)
	if len(b.hits) == 0 {
		delete(w.entries, key)
		return true, 0
	}
	// Refresh last-seen timestamp even when throttled so an active abuser is
	// not evicted before idle keys under a flood.
	b.last = now
	if len(b.hits) >= limit {
		rem := b.hits[0].Add(w.window).Sub(now)
		secs := int((rem + time.Second - 1) / time.Second)
		if secs < 1 {
			secs = 1
		}
		return false, secs
	}
	return true, 0
}

func (w *slidingWindow[K]) recordLocked(key K, now time.Time) {
	if b, ok := w.entries[key]; ok {
		w.pruneBucket(b, now)
		b.hits = append(b.hits, now)
		b.last = now
		return
	}
	maxKeys := w.maxKeys
	if maxKeys <= 0 {
		maxKeys = defaultLimiterMaxKeys
	}
	if len(w.entries) >= maxKeys {
		w.sweepExpiredLocked(now)
	}
	if len(w.entries) >= maxKeys {
		if !w.evictOnFull {
			return
		}
		var oldestKey K
		var oldestAt time.Time
		first := true
		for k, b := range w.entries {
			if first || b.last.Before(oldestAt) {
				first = false
				oldestKey = k
				oldestAt = b.last
			}
		}
		if !first {
			delete(w.entries, oldestKey)
		}
	}
	w.entries[key] = &windowBucket{
		hits: []time.Time{now},
		last: now,
	}
}

func rateLimitKey(raw string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	a = a.Unmap()
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
}
