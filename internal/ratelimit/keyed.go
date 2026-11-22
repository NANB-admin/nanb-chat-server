// Package ratelimit holds the server's keyed token-bucket limiter: one bucket
// per caller-chosen key (a client IP, a requester/target pair, ...), so one
// party exhausting ITS budget never spends anyone else's.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// sweepInterval bounds how often a full map is scanned for idle buckets, so a
// flood of new keys at the cap can't turn every request into an O(n) sweep.
const sweepInterval = time.Second

// Keyed is a set of token buckets, one per key, created lazily.
//
// Memory is bounded by MaxKeys. When the map is full and a new key arrives,
// buckets that are back at full capacity are dropped first (a full bucket holds
// no throttle state, so forgetting it changes nothing). If the map is STILL
// full — many keys actively throttled at once, i.e. a distributed flood — the
// new key shares a single overflow bucket instead of growing the map. Only
// unknown keys ever land there; keys already tracked keep their own budget.
type Keyed struct {
	cfg KeyedConfig
	now func() time.Time

	mu        sync.Mutex
	buckets   map[string]*rate.Limiter
	overflow  *rate.Limiter
	lastSweep time.Time
}

// NewKeyed builds a Keyed limiter. now is injectable for tests; nil means
// time.Now.
func NewKeyed(cfg KeyedConfig, now func() time.Time) *Keyed {
	if now == nil {
		now = time.Now
	}
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = 1
	}
	return &Keyed{
		cfg:      cfg,
		now:      now,
		buckets:  map[string]*rate.Limiter{},
		overflow: rate.NewLimiter(cfg.Rate, cfg.Burst),
	}
}

// Allow spends one token from key's bucket, reporting whether one was there.
func (k *Keyed) Allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	return k.bucket(key, now).AllowN(now, 1)
}

// HasTokens reports whether key's bucket holds at least n tokens, WITHOUT
// spending any. An untracked key is not added to the map: it has a fresh, full
// bucket by definition (unless the map is saturated, in which case it would be
// served by the overflow bucket, so that is what is consulted).
func (k *Keyed) HasTokens(key string, n int) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if b, ok := k.buckets[key]; ok {
		return b.TokensAt(now) >= float64(n)
	}
	if len(k.buckets) >= k.cfg.MaxKeys {
		k.sweep(now)
		if len(k.buckets) >= k.cfg.MaxKeys {
			return k.overflow.TokensAt(now) >= float64(n)
		}
	}
	return n <= k.cfg.Burst
}

// Charge spends n tokens from key's bucket unconditionally. The bucket may go
// into debt, in which case the key is refused until it has refilled. Used when
// the cost of an operation is only known after it ran (how many key packages a
// claim returned; whether an access key turned out to be wrong).
func (k *Keyed) Charge(key string, n int) {
	if n <= 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	if n > k.cfg.Burst {
		n = k.cfg.Burst // ReserveN refuses n > burst outright
	}
	k.bucket(key, now).ReserveN(now, n)
}

// bucket returns key's limiter, creating it (or falling back to the overflow
// bucket at the cap). Caller holds mu.
func (k *Keyed) bucket(key string, now time.Time) *rate.Limiter {
	if b, ok := k.buckets[key]; ok {
		return b
	}
	if len(k.buckets) >= k.cfg.MaxKeys {
		k.sweep(now)
		if len(k.buckets) >= k.cfg.MaxKeys {
			return k.overflow
		}
	}
	b := rate.NewLimiter(k.cfg.Rate, k.cfg.Burst)
	k.buckets[key] = b
	return b
}

// sweep drops buckets that have refilled completely, at most once per
// sweepInterval. Caller holds mu.
func (k *Keyed) sweep(now time.Time) {
	if !k.lastSweep.IsZero() && now.Sub(k.lastSweep) < sweepInterval {
		return
	}
	k.lastSweep = now
	full := float64(k.cfg.Burst)
	for key, b := range k.buckets {
		if b.TokensAt(now) >= full {
			delete(k.buckets, key)
		}
	}
}
