package delivery

import (
	"context"
	"sync"
	"time"
)

// cachedResolver wraps a RecipientResolver with a short-TTL in-memory cache, so
// repeat sends to the same device (sender + recipient liveness checks run on
// every SubmitMessage) don't each hit the DB.
//
// "Live" here means the device exists and its account isn't deleted — state that
// changes only on a device revoke / account delete, so a brief staleness window
// is fine: a just-revoked device may be treated as live for up to the TTL (its
// envelopes queue but are never picked up — it can't reconnect — and expire via
// retention), and the rare negative is re-checked once its entry ages out.
//
// Device EXPIRY (web devices, identity_db.devices.expires_at) is stricter than
// the TTL: when the inner resolver implements ExpiringRecipientResolver the
// cache entry's lifetime is min(TTL, time until the device's expires_at), so a
// device is never reported live after its expiry (bound: 0 s; a plain revoke
// still has the up-to-TTL = 30 s staleness above). A resolver that does not
// report expiry falls back to the TTL bound, i.e. an expired device could stay
// live for up to one TTL.
//
// (v1: the map isn't garbage-collected beyond TTL-on-read; bounded by the
// active-device count, same posture as the per-account WS limiter map.)
type cachedResolver struct {
	inner RecipientResolver
	ttl   time.Duration
	now   func() time.Time

	mu    sync.Mutex
	cache map[string]livenessEntry
}

type livenessEntry struct {
	accountID string
	live      bool
	expiresAt time.Time
}

// NewCachedResolver wraps inner with a TTL liveness cache.
func NewCachedResolver(inner RecipientResolver, ttl time.Duration) RecipientResolver {
	return &cachedResolver{
		inner: inner,
		ttl:   ttl,
		now:   time.Now,
		cache: map[string]livenessEntry{},
	}
}

// Forget drops [deviceID]'s cached liveness, so the next lookup reads the
// store. Called when the device is revoked, which otherwise stayed "live" for
// up to one TTL.
func (c *cachedResolver) Forget(deviceID string) {
	c.mu.Lock()
	delete(c.cache, deviceID)
	c.mu.Unlock()
}

func (c *cachedResolver) RecipientLive(ctx context.Context, deviceID string) (bool, error) {
	_, live, err := c.AccountForDevice(ctx, deviceID)
	return live, err
}

// AccountForDevice resolves (and caches) the device's owning account id +
// liveness. RecipientLive is a thin wrapper over it, so both share one cache
// entry and one upstream lookup per device per TTL.
func (c *cachedResolver) AccountForDevice(ctx context.Context, deviceID string) (string, bool, error) {
	now := c.now()
	c.mu.Lock()
	if e, ok := c.cache[deviceID]; ok && now.Before(e.expiresAt) {
		c.mu.Unlock()
		return e.accountID, e.live, nil
	}
	c.mu.Unlock()

	var (
		accountID string
		live      bool
		deviceExp *time.Time
		err       error
	)
	if ex, ok := c.inner.(ExpiringRecipientResolver); ok {
		accountID, live, deviceExp, err = ex.AccountForDeviceExpiry(ctx, deviceID)
	} else {
		accountID, live, err = c.inner.AccountForDevice(ctx, deviceID)
	}
	if err != nil {
		return "", false, err // never cache errors
	}
	entryExp := now.Add(c.ttl)
	if live && deviceExp != nil && deviceExp.Before(entryExp) {
		entryExp = *deviceExp
	}
	c.mu.Lock()
	c.cache[deviceID] = livenessEntry{accountID: accountID, live: live, expiresAt: entryExp}
	c.mu.Unlock()
	return accountID, live, nil
}
