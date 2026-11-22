package keypackages_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/keypackages"
	"github.com/nanb/nanb-server/internal/proto"
)

func newCappedSvc(maxStored int) (*keypackages.Service, *keypackages.StoreInMemory) {
	store := keypackages.NewStoreInMemory()
	svc := keypackages.NewService(keypackages.ServiceDeps{
		Store:              store,
		AccountLookup:      &fakeAccountLookup{byUsername: map[string]string{}},
		LowWaterMark:       lowWaterMark,
		MaxPerBatch:        maxPerBatch,
		MaxBlobSize:        maxBlobSize,
		MaxStoredPerDevice: maxStored,
	})
	return svc, store
}

func kpBatch(n int) proto.PublishKeyPackagesRequest {
	kps := make([][]byte, n)
	for i := range kps {
		kps[i] = []byte("kp")
	}
	return proto.PublishKeyPackagesRequest{KeyPackages: kps}
}

func TestPublishCap_BatchBeyondTheCapIsTrimmedToFit(t *testing.T) {
	svc, _ := newCappedSvc(3)

	resp, err := svc.Publish(context.Background(), "acct-alice", "dev-1", kpBatch(5))

	require.NoError(t, err)
	assert.Equal(t, 3, resp.StoredCount)
}

func TestPublishCap_DeviceNeverHoldsMoreThanTheCap(t *testing.T) {
	svc, store := newCappedSvc(3)
	ctx := context.Background()
	_, _ = svc.Publish(ctx, "acct-alice", "dev-1", kpBatch(2))
	_, _ = svc.Publish(ctx, "acct-alice", "dev-1", kpBatch(2))

	n, err := store.CountUnconsumedByDevice(ctx, "acct-alice", "dev-1")

	require.NoError(t, err)
	assert.Equal(t, 3, n)
}

func TestPublishCap_PublishIntoAFullPoolIsNotAnError(t *testing.T) {
	svc, _ := newCappedSvc(2)
	ctx := context.Background()
	_, _ = svc.Publish(ctx, "acct-alice", "dev-1", kpBatch(2))

	resp, err := svc.Publish(ctx, "acct-alice", "dev-1", kpBatch(2))

	require.NoError(t, err)
	assert.Equal(t, 0, resp.StoredCount)
}

// publishKeyPackages(reset: true) REPLACES the pool, so a full pool must not
// stop a reset from landing its fresh packages.
func TestPublishCap_ResetReplacesAFullPool(t *testing.T) {
	svc, store := newCappedSvc(2)
	ctx := context.Background()
	_, _ = svc.Publish(ctx, "acct-alice", "dev-1", kpBatch(2))
	reset := kpBatch(2)
	reset.Reset = true

	resp, err := svc.Publish(ctx, "acct-alice", "dev-1", reset)

	require.NoError(t, err)
	assert.Equal(t, 2, resp.StoredCount)
	n, _ := store.CountUnconsumedByDevice(ctx, "acct-alice", "dev-1")
	assert.Equal(t, 2, n)
}

func TestPublishCap_IsPerDevice(t *testing.T) {
	svc, _ := newCappedSvc(2)
	ctx := context.Background()
	_, _ = svc.Publish(ctx, "acct-alice", "dev-1", kpBatch(2))

	resp, err := svc.Publish(ctx, "acct-alice", "dev-2", kpBatch(2))

	require.NoError(t, err)
	assert.Equal(t, 2, resp.StoredCount)
}

func TestPublishCap_DefaultsWhenUnset(t *testing.T) {
	svc, _ := newCappedSvc(0)
	ctx := context.Background()
	_, _ = svc.Publish(ctx, "acct-alice", "dev-1", kpBatch(keypackages.DefaultMaxStoredPerDevice))

	resp, err := svc.Publish(ctx, "acct-alice", "dev-1", kpBatch(1))

	require.NoError(t, err)
	assert.Equal(t, 0, resp.StoredCount)
}

func TestPublishCap_ClientSizedBatchesAreUnaffected(t *testing.T) {
	// Sign-up / link / restore publish 100; the replenisher tops up 50 when the
	// pool drops under 10. Both must be stored in full under the default cap.
	svc, _ := newCappedSvc(0)
	ctx := context.Background()
	_, _ = svc.Publish(ctx, "acct-alice", "dev-1", kpBatch(100))

	resp, err := svc.Publish(ctx, "acct-alice", "dev-1", kpBatch(50))

	require.NoError(t, err)
	assert.Equal(t, 50, resp.StoredCount)
}
