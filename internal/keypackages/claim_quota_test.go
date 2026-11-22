package keypackages_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/keypackages"
)

// quotaClock is a test clock that only moves when told to.
type quotaClock struct{ t time.Time }

func (c *quotaClock) now() time.Time { return c.t }

// newQuotaSvc: per-(requester, target) budget of `burst` packages refilling
// one per minute; @alice → acct-alice, @bob → acct-bob, @carol → acct-carol.
func newQuotaSvc(burst int) (*keypackages.Service, *keypackages.StoreInMemory, *quotaClock) {
	clock := &quotaClock{t: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	store := keypackages.NewStoreInMemory()
	svc := keypackages.NewService(keypackages.ServiceDeps{
		Store: store,
		AccountLookup: &fakeAccountLookup{byUsername: map[string]string{
			"@alice": "acct-alice", "@bob": "acct-bob", "@carol": "acct-carol",
		}},
		LowWaterMark: lowWaterMark,
		MaxPerBatch:  maxPerBatch,
		MaxBlobSize:  maxBlobSize,
		ClaimQuota:   keypackages.NewPairClaimQuota(burst, time.Minute, clock.now),
	})
	return svc, store, clock
}

func stock(store *keypackages.StoreInMemory, account, device string, n int) {
	kps := make([][]byte, n)
	for i := range kps {
		kps[i] = []byte("kp")
	}
	_ = store.PublishBatch(context.Background(), account, device, kps)
}

func TestClaimQuota_RequesterIsCutOffPastItsBudget(t *testing.T) {
	svc, store, _ := newQuotaSvc(2)
	stock(store, "acct-bob", "dev-b1", 10)
	ctx := context.Background()
	_, _ = svc.FetchForUsername(ctx, "acct-mallory", "@bob")
	_, _ = svc.FetchForUsername(ctx, "acct-mallory", "@bob")

	_, err := svc.FetchForUsername(ctx, "acct-mallory", "@bob")

	assert.True(t, errors.Is(err, keypackages.ErrClaimQuotaExceeded))
}

func TestClaimQuota_RefusedClaimConsumesNothing(t *testing.T) {
	svc, store, _ := newQuotaSvc(1)
	stock(store, "acct-bob", "dev-b1", 10)
	ctx := context.Background()
	_, _ = svc.FetchForUsername(ctx, "acct-mallory", "@bob")
	for i := 0; i < 5; i++ {
		_, _ = svc.FetchForUsername(ctx, "acct-mallory", "@bob")
	}

	n, err := store.CountUnconsumed(ctx, "acct-bob")

	require.NoError(t, err)
	assert.Equal(t, 9, n)
}

func TestClaimQuota_OneRequesterExhaustedDoesNotLimitAnother(t *testing.T) {
	svc, store, _ := newQuotaSvc(1)
	stock(store, "acct-bob", "dev-b1", 10)
	ctx := context.Background()
	_, _ = svc.FetchForUsername(ctx, "acct-mallory", "@bob")

	_, err := svc.FetchForUsername(ctx, "acct-alice", "@bob")

	require.NoError(t, err)
}

func TestClaimQuota_IsPerTarget(t *testing.T) {
	svc, store, _ := newQuotaSvc(1)
	stock(store, "acct-bob", "dev-b1", 10)
	stock(store, "acct-carol", "dev-c1", 10)
	ctx := context.Background()
	_, _ = svc.FetchForUsername(ctx, "acct-alice", "@bob")

	_, err := svc.FetchForUsername(ctx, "acct-alice", "@carol")

	require.NoError(t, err)
}

func TestClaimQuota_OwnAccountIsNeverLimited(t *testing.T) {
	svc, store, _ := newQuotaSvc(1)
	stock(store, "acct-alice", "dev-a2", 10)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _ = svc.FetchAllDevicesForUsername(ctx, "acct-alice", "@alice")
	}

	_, err := svc.FetchForUsername(ctx, "acct-alice", "@alice")

	require.NoError(t, err)
}

func TestClaimQuota_AllDevicesFetchIsChargedPerPackage(t *testing.T) {
	svc, store, _ := newQuotaSvc(2)
	stock(store, "acct-bob", "dev-b1", 10)
	stock(store, "acct-bob", "dev-b2", 10)
	ctx := context.Background()
	_, _ = svc.FetchAllDevicesForUsername(ctx, "acct-alice", "@bob") // two packages

	_, err := svc.FetchForUsername(ctx, "acct-alice", "@bob")

	assert.True(t, errors.Is(err, keypackages.ErrClaimQuotaExceeded))
}

func TestClaimQuota_AllDevicesFetchIsRefusedPastTheBudget(t *testing.T) {
	svc, store, _ := newQuotaSvc(1)
	stock(store, "acct-bob", "dev-b1", 10)
	ctx := context.Background()
	_, _ = svc.FetchAllDevicesForUsername(ctx, "acct-mallory", "@bob")

	_, err := svc.FetchAllDevicesForUsername(ctx, "acct-mallory", "@bob")

	assert.True(t, errors.Is(err, keypackages.ErrClaimQuotaExceeded))
}

func TestClaimQuota_BudgetRefillsOverTime(t *testing.T) {
	svc, store, clock := newQuotaSvc(1)
	stock(store, "acct-bob", "dev-b1", 10)
	ctx := context.Background()
	_, _ = svc.FetchForUsername(ctx, "acct-alice", "@bob")

	clock.t = clock.t.Add(time.Minute)

	_, err := svc.FetchForUsername(ctx, "acct-alice", "@bob")
	require.NoError(t, err)
}

// The own-device hand-off route claims many packages of one sibling device at
// once; it must not be touched by the peer quota.
func TestClaimQuota_OwnDeviceClaimIsUnaffected(t *testing.T) {
	svc, store, _ := newQuotaSvc(1)
	stock(store, "acct-alice", "dev-a2", 10)

	resp, err := svc.ClaimForOwnDevice(context.Background(), "acct-alice", "dev-a1", "dev-a2", 5)

	require.NoError(t, err)
	assert.Len(t, resp.Devices, 5)
}

func TestClaimQuota_HandlerAnswers429(t *testing.T) {
	svc, store, _ := newQuotaSvc(1)
	stock(store, "acct-bob", "dev-b1", 10)
	h := keypackages.NewHandlers(svc)
	r := chi.NewRouter()
	r.Get("/accounts/{username}/key-package", h.GetKeyPackageByUsername)
	r.ServeHTTP(httptest.NewRecorder(), authedRequest(t, "GET", "/accounts/@bob/key-package", nil, "acct-mallory", "dev-m"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest(t, "GET", "/accounts/@bob/key-package", nil, "acct-mallory", "dev-m"))

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}
