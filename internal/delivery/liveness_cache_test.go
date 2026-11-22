package delivery

import (
	"context"
	"errors"
	"testing"
	"time"
)

type countingResolver struct {
	calls     int
	accountID string
	live      bool
	err       error
}

func (c *countingResolver) RecipientLive(ctx context.Context, deviceID string) (bool, error) {
	_, live, err := c.AccountForDevice(ctx, deviceID)
	return live, err
}

// AccountForDevice is the single upstream lookup the cache fronts; RecipientLive
// delegates to it, so `calls` counts one increment per genuine cache miss.
func (c *countingResolver) AccountForDevice(_ context.Context, _ string) (string, bool, error) {
	c.calls++
	return c.accountID, c.live, c.err
}

func newTestCache(inner RecipientResolver, now *time.Time) *cachedResolver {
	return &cachedResolver{
		inner: inner,
		ttl:   30 * time.Second,
		now:   func() time.Time { return *now },
		cache: map[string]livenessEntry{},
	}
}

func TestCachedResolver_CachesWithinTTL(t *testing.T) {
	inner := &countingResolver{live: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, &now)

	for i := 0; i < 3; i++ {
		live, err := c.RecipientLive(context.Background(), "dev-1")
		if err != nil || !live {
			t.Fatalf("want live,nil; got %v,%v", live, err)
		}
	}
	if inner.calls != 1 {
		t.Fatalf("want 1 DB call (rest cached), got %d", inner.calls)
	}
}

func TestCachedResolver_RefetchesAfterTTL(t *testing.T) {
	inner := &countingResolver{live: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, &now)

	_, _ = c.RecipientLive(context.Background(), "dev-1")
	now = now.Add(31 * time.Second) // past TTL
	_, _ = c.RecipientLive(context.Background(), "dev-1")
	if inner.calls != 2 {
		t.Fatalf("want 2 calls after TTL expiry, got %d", inner.calls)
	}
}

func TestCachedResolver_DistinctDevicesEachQueryOnce(t *testing.T) {
	inner := &countingResolver{live: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, &now)

	_, _ = c.RecipientLive(context.Background(), "dev-1")
	_, _ = c.RecipientLive(context.Background(), "dev-2")
	_, _ = c.RecipientLive(context.Background(), "dev-1")
	if inner.calls != 2 {
		t.Fatalf("want 2 calls (one per distinct device), got %d", inner.calls)
	}
}

func TestCachedResolver_DoesNotCacheErrors(t *testing.T) {
	inner := &countingResolver{err: errors.New("db down")}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, &now)

	_, _ = c.RecipientLive(context.Background(), "dev-1")
	_, _ = c.RecipientLive(context.Background(), "dev-1")
	if inner.calls != 2 {
		t.Fatalf("errors must not be cached; want 2 calls, got %d", inner.calls)
	}
}

func TestCachedResolver_ForgetMakesTheNextLookupReadTheStore(t *testing.T) {
	inner := &countingResolver{live: true}
	now := time.Unix(1000, 0)
	c := newTestCache(inner, &now)
	_, _ = c.RecipientLive(context.Background(), "dev-1")

	c.Forget("dev-1")
	_, _ = c.RecipientLive(context.Background(), "dev-1")

	if inner.calls != 2 {
		t.Fatalf("want a fresh store read after Forget, got %d calls", inner.calls)
	}
}
