package delivery

import (
	"context"
	"testing"
	"time"
)

// expiringResolver is a RecipientResolver that also reports the device's own
// expires_at, via the optional ExpiringRecipientResolver interface.
type expiringResolver struct {
	calls     int
	expiresAt *time.Time
	now       *time.Time
}

func (e *expiringResolver) RecipientLive(ctx context.Context, id string) (bool, error) {
	_, live, err := e.AccountForDevice(ctx, id)
	return live, err
}

func (e *expiringResolver) AccountForDevice(ctx context.Context, id string) (string, bool, error) {
	a, live, _, err := e.AccountForDeviceExpiry(ctx, id)
	return a, live, err
}

func (e *expiringResolver) AccountForDeviceExpiry(_ context.Context, _ string) (string, bool, *time.Time, error) {
	e.calls++
	live := e.expiresAt == nil || e.now.Before(*e.expiresAt)
	return "acc-1", live, e.expiresAt, nil
}

func TestCachedResolver_DoesNotKeepDeviceLivePastItsExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(10 * time.Second) // sooner than the 30s TTL
	inner := &expiringResolver{expiresAt: &exp, now: &now}
	c := newTestCache(inner, &now)

	if live, _ := c.RecipientLive(context.Background(), "web-1"); !live {
		t.Fatal("device must be live before expiry")
	}
	now = now.Add(11 * time.Second) // past expiry, still inside the 30s TTL
	if live, _ := c.RecipientLive(context.Background(), "web-1"); live {
		t.Fatal("cache kept an expired device live")
	}
}

func TestCachedResolver_StillCachesWhileDeviceUnexpired(t *testing.T) {
	now := time.Unix(1000, 0)
	exp := now.Add(time.Hour)
	inner := &expiringResolver{expiresAt: &exp, now: &now}
	c := newTestCache(inner, &now)

	_, _ = c.RecipientLive(context.Background(), "web-1")
	_, _ = c.RecipientLive(context.Background(), "web-1")
	if inner.calls != 1 {
		t.Fatalf("want 1 upstream call, got %d", inner.calls)
	}
}

func TestCachedResolver_DeviceWithoutExpiryCachedForFullTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	inner := &expiringResolver{now: &now}
	c := newTestCache(inner, &now)

	_, _ = c.RecipientLive(context.Background(), "phone-1")
	now = now.Add(29 * time.Second)
	_, _ = c.RecipientLive(context.Background(), "phone-1")
	if inner.calls != 1 {
		t.Fatalf("want 1 upstream call, got %d", inner.calls)
	}
}
