package keypackages_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nanb/nanb-server/internal/keypackages"
	"github.com/nanb/nanb-server/internal/proto"
)

const lowWaterMark = 10
const maxPerBatch = 200
const maxBlobSize = 8 * 1024

type fakeAccountLookup struct {
	byUsername map[string]string // username -> accountID
}

func (f *fakeAccountLookup) AccountIDByUsername(_ context.Context, username string) (string, error) {
	id, ok := f.byUsername[username]
	if !ok {
		return "", keypackages.ErrAccountNotFound
	}
	return id, nil
}

func newSvc(t *testing.T) (*keypackages.Service, *keypackages.StoreInMemory) {
	t.Helper()
	store := keypackages.NewStoreInMemory()
	lookup := &fakeAccountLookup{byUsername: map[string]string{
		"@alice": "acct-alice",
		"@bob":   "acct-bob",
	}}
	svc := keypackages.NewService(keypackages.ServiceDeps{
		Store:         store,
		AccountLookup: lookup,
		LowWaterMark:  lowWaterMark,
		MaxPerBatch:   maxPerBatch,
		MaxBlobSize:   maxBlobSize,
	})
	return svc, store
}

func TestService_Publish_StoresCount(t *testing.T) {
	svc, _ := newSvc(t)
	resp, err := svc.Publish(context.Background(), "acct-alice", "dev-1",
		proto.PublishKeyPackagesRequest{KeyPackages: [][]byte{[]byte("a"), []byte("b")}})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if resp.StoredCount != 2 {
		t.Fatalf("stored = %d, want 2", resp.StoredCount)
	}
}

type recordingPublishListener struct{ heard []string }

func (r *recordingPublishListener) KeyPackagesPublished(accountID, deviceID string) {
	r.heard = append(r.heard, accountID+"/"+deviceID)
}

func newSvcWithListener(t *testing.T, l keypackages.PublishListener) *keypackages.Service {
	t.Helper()
	return keypackages.NewService(keypackages.ServiceDeps{
		Store:         keypackages.NewStoreInMemory(),
		AccountLookup: &fakeAccountLookup{},
		LowWaterMark:  lowWaterMark,
		MaxPerBatch:   maxPerBatch,
		MaxBlobSize:   maxBlobSize,
		Published:     l,
	})
}

func TestService_Publish_TellsTheListenerWhoPublished(t *testing.T) {
	l := &recordingPublishListener{}
	svc := newSvcWithListener(t, l)
	_, err := svc.Publish(context.Background(), "acct-alice", "dev-1",
		proto.PublishKeyPackagesRequest{KeyPackages: [][]byte{[]byte("a")}})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(l.heard) != 1 || l.heard[0] != "acct-alice/dev-1" {
		t.Fatalf("heard = %v, want [acct-alice/dev-1]", l.heard)
	}
}

func TestService_Publish_RejectedBatchTellsNobody(t *testing.T) {
	l := &recordingPublishListener{}
	svc := newSvcWithListener(t, l)
	_, _ = svc.Publish(context.Background(), "acct-alice", "dev-1",
		proto.PublishKeyPackagesRequest{KeyPackages: [][]byte{}})
	if len(l.heard) != 0 {
		t.Fatalf("heard = %v, want nothing", l.heard)
	}
}

func TestService_Publish_ResetDropsThisDevicesStalePackages(t *testing.T) {
	svc, store := newSvc(t)
	ctx := context.Background()
	_ = store.PublishBatch(ctx, "acct-alice", "dev-1", [][]byte{[]byte("dead1"), []byte("dead2")})

	if _, err := svc.Publish(ctx, "acct-alice", "dev-1", proto.PublishKeyPackagesRequest{
		KeyPackages: [][]byte{[]byte("fresh")},
		Reset:       true,
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Only the fresh package survives; popping must never yield a dead one,
	// which is the whole point — a Welcome built from it is undecryptable.
	got, err := store.PopOne(ctx, "acct-alice")
	if err != nil {
		t.Fatalf("PopOne: %v", err)
	}
	if string(got) != "fresh" {
		t.Fatalf("popped %q, want \"fresh\"", got)
	}
	if _, err := store.PopOne(ctx, "acct-alice"); !errors.Is(err, keypackages.ErrEmpty) {
		t.Fatalf("second PopOne err = %v, want ErrEmpty (stale packages survived)", err)
	}
}

func TestService_Publish_ResetLeavesOtherDevicesAlone(t *testing.T) {
	svc, store := newSvc(t)
	ctx := context.Background()
	_ = store.PublishBatch(ctx, "acct-bob", "dev-A", [][]byte{[]byte("a1")})
	_ = store.PublishBatch(ctx, "acct-bob", "dev-B", [][]byte{[]byte("b1")})

	// dev-A resetting must not disarm dev-B, whose store is perfectly healthy.
	if _, err := svc.Publish(ctx, "acct-bob", "dev-A", proto.PublishKeyPackagesRequest{
		KeyPackages: [][]byte{[]byte("a2")},
		Reset:       true,
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	resp, err := svc.FetchAllDevicesForUsername(ctx, "acct-requester", "@bob")
	if err != nil {
		t.Fatalf("FetchAllDevices: %v", err)
	}
	if len(resp.Devices) != 2 {
		t.Fatalf("got %d devices, want 2 (dev-B lost its pool)", len(resp.Devices))
	}
}

func TestService_Publish_WithoutResetKeepsExisting(t *testing.T) {
	svc, store := newSvc(t)
	ctx := context.Background()
	_ = store.PublishBatch(ctx, "acct-alice", "dev-1", [][]byte{[]byte("old")})

	if _, err := svc.Publish(ctx, "acct-alice", "dev-1", proto.PublishKeyPackagesRequest{
		KeyPackages: [][]byte{[]byte("new")},
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Default publish APPENDS — the ordinary replenisher top-up must not
	// destroy a pool that is still perfectly usable.
	if _, err := store.PopOne(ctx, "acct-alice"); err != nil {
		t.Fatalf("first PopOne: %v", err)
	}
	if _, err := store.PopOne(ctx, "acct-alice"); err != nil {
		t.Fatalf("second PopOne: %v — append lost a package", err)
	}
}

func TestService_FetchAllDevices_OnePerDevice(t *testing.T) {
	svc, store := newSvc(t)
	ctx := context.Background()
	// Two devices for @bob, each with two packages.
	_ = store.PublishBatch(ctx, "acct-bob", "dev-A", [][]byte{[]byte("a1"), []byte("a2")})
	_ = store.PublishBatch(ctx, "acct-bob", "dev-B", [][]byte{[]byte("b1"), []byte("b2")})

	resp, err := svc.FetchAllDevicesForUsername(ctx, "acct-requester", "@bob")
	if err != nil {
		t.Fatalf("FetchAllDevices: %v", err)
	}
	if len(resp.Devices) != 2 {
		t.Fatalf("got %d devices, want 2", len(resp.Devices))
	}
	gotDevs := map[string]bool{}
	for _, d := range resp.Devices {
		gotDevs[d.DeviceID] = true
		if len(d.KeyPackage) == 0 {
			t.Fatalf("device %s returned empty key package", d.DeviceID)
		}
	}
	if !gotDevs["dev-A"] || !gotDevs["dev-B"] {
		t.Fatalf("missing a device: %v", gotDevs)
	}
	// One consumed per device → two packages remain (a2, b2).
	if n, _ := store.CountUnconsumed(ctx, "acct-bob"); n != 2 {
		t.Fatalf("remaining = %d, want 2", n)
	}
}

func TestService_FetchAllDevices_EmptyAccountNoError(t *testing.T) {
	svc, _ := newSvc(t)
	resp, err := svc.FetchAllDevicesForUsername(context.Background(), "acct-requester", "@alice")
	if err != nil {
		t.Fatalf("want nil error for empty account, got %v", err)
	}
	if len(resp.Devices) != 0 {
		t.Fatalf("want 0 devices, got %d", len(resp.Devices))
	}
}

func TestService_FetchAllDevices_UnknownAccount(t *testing.T) {
	svc, _ := newSvc(t)
	_, err := svc.FetchAllDevicesForUsername(context.Background(), "acct-requester", "@nobody")
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeAccountNotFound {
		t.Fatalf("err = %v, want ErrCodeAccountNotFound", err)
	}
}

func TestService_Publish_RejectsEmptyBatch(t *testing.T) {
	svc, _ := newSvc(t)
	_, err := svc.Publish(context.Background(), "acct-alice", "dev-1",
		proto.PublishKeyPackagesRequest{KeyPackages: nil})
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeKeyPackageInvalid {
		t.Fatalf("err = %v, want APIError ErrCodeKeyPackageInvalid", err)
	}
}

func TestService_Publish_RejectsOversizeBatch(t *testing.T) {
	svc, _ := newSvc(t)
	big := make([][]byte, maxPerBatch+1)
	for i := range big {
		big[i] = []byte("x")
	}
	_, err := svc.Publish(context.Background(), "acct-alice", "dev-1",
		proto.PublishKeyPackagesRequest{KeyPackages: big})
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeKeyPackageInvalid {
		t.Fatalf("err = %v, want APIError ErrCodeKeyPackageInvalid", err)
	}
}

func TestService_Publish_RejectsOversizeBlob(t *testing.T) {
	svc, _ := newSvc(t)
	big := make([]byte, maxBlobSize+1)
	_, err := svc.Publish(context.Background(), "acct-alice", "dev-1",
		proto.PublishKeyPackagesRequest{KeyPackages: [][]byte{big}})
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeKeyPackageInvalid {
		t.Fatalf("err = %v, want APIError ErrCodeKeyPackageInvalid", err)
	}
}

func TestService_Publish_RejectsEmptyBlobInBatch(t *testing.T) {
	svc, _ := newSvc(t)
	_, err := svc.Publish(context.Background(), "acct-alice", "dev-1",
		proto.PublishKeyPackagesRequest{KeyPackages: [][]byte{[]byte("ok"), []byte{}}})
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeKeyPackageInvalid {
		t.Fatalf("err = %v, want APIError ErrCodeKeyPackageInvalid", err)
	}
}

func TestService_Fetch_ReturnsBytesAndRemainingCount(t *testing.T) {
	svc, store := newSvc(t)
	_ = store.PublishBatch(context.Background(), "acct-bob", "dev-1",
		[][]byte{[]byte("kp-a"), []byte("kp-b")})
	resp, err := svc.FetchForUsername(context.Background(), "acct-requester", "@bob")
	if err != nil {
		t.Fatalf("FetchForUsername: %v", err)
	}
	if string(resp.KeyPackage) != "kp-a" {
		t.Fatalf("got %q, want kp-a", resp.KeyPackage)
	}
	if resp.RemainingForUser != 1 {
		t.Fatalf("remaining = %d, want 1", resp.RemainingForUser)
	}
}

func TestService_Fetch_ReplenishFlagTrueWhenBelowLowWater(t *testing.T) {
	svc, store := newSvc(t)
	// publish 2 KPs; after one fetch, remaining=1 which is < lowWaterMark=10
	_ = store.PublishBatch(context.Background(), "acct-bob", "dev-1",
		[][]byte{[]byte("a"), []byte("b")})
	resp, err := svc.FetchForUsername(context.Background(), "acct-requester", "@bob")
	if err != nil {
		t.Fatalf("FetchForUsername: %v", err)
	}
	if !resp.ReplenishNeeded {
		t.Fatalf("ReplenishNeeded = false, want true at remaining=%d (low water=%d)",
			resp.RemainingForUser, lowWaterMark)
	}
}

func TestService_Fetch_ReplenishFlagFalseWhenAboveLowWater(t *testing.T) {
	svc, store := newSvc(t)
	pkgs := make([][]byte, 15)
	for i := range pkgs {
		pkgs[i] = []byte{byte(i)}
	}
	_ = store.PublishBatch(context.Background(), "acct-bob", "dev-1", pkgs)
	resp, err := svc.FetchForUsername(context.Background(), "acct-requester", "@bob")
	if err != nil {
		t.Fatalf("FetchForUsername: %v", err)
	}
	if resp.ReplenishNeeded {
		t.Fatalf("ReplenishNeeded = true, want false at remaining=%d (low water=%d)", resp.RemainingForUser, lowWaterMark)
	}
}

func TestService_Fetch_ReturnsGoneWhenEmpty(t *testing.T) {
	svc, _ := newSvc(t)
	_, err := svc.FetchForUsername(context.Background(), "acct-requester", "@bob")
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeKeyPackageExhausted {
		t.Fatalf("err = %v, want APIError ErrCodeKeyPackageExhausted", err)
	}
}

func TestService_Fetch_ReturnsNotFoundForUnknownUsername(t *testing.T) {
	svc, _ := newSvc(t)
	_, err := svc.FetchForUsername(context.Background(), "acct-requester", "@nobody")
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeAccountNotFound {
		t.Fatalf("err = %v, want APIError ErrCodeAccountNotFound", err)
	}
}

func TestService_Count_ReturnsStoreCount(t *testing.T) {
	svc, store := newSvc(t)
	_ = store.PublishBatch(context.Background(), "acct-alice", "dev-1",
		[][]byte{[]byte("a"), []byte("b"), []byte("c")})
	resp, err := svc.Count(context.Background(), "acct-alice", "dev-1")
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if resp.Count != 3 {
		t.Fatalf("count = %d, want 3", resp.Count)
	}
}

// A sibling's spare packages can't stand in for this device's: each device's
// package only opens on that device, so a phone that ran dry must still read low.
func TestService_Count_IgnoresOtherDevicesOfTheAccount(t *testing.T) {
	svc, store := newSvc(t)
	_ = store.PublishBatch(context.Background(), "acct-alice", "dev-phone",
		[][]byte{[]byte("a")})
	_ = store.PublishBatch(context.Background(), "acct-alice", "dev-web",
		[][]byte{[]byte("b"), []byte("c"), []byte("d")})
	resp, err := svc.Count(context.Background(), "acct-alice", "dev-phone")
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if resp.Count != 1 {
		t.Fatalf("count = %d, want 1", resp.Count)
	}
}

type errLookup struct{ err error }

func (e errLookup) AccountIDByUsername(_ context.Context, _ string) (string, error) {
	return "", e.err
}

type errStoreKp struct {
	popErr   error
	countErr error
	// deleteErr fails a Reset publish's purge, so the service must surface it
	// rather than fall through and append onto a pool it failed to clear.
	deleteErr error
}

func (s *errStoreKp) DeleteUnconsumedByDevice(_ context.Context, _ string) error {
	return s.deleteErr
}

func (s *errStoreKp) PublishBatch(_ context.Context, _, _ string, _ [][]byte) error { return nil }
func (s *errStoreKp) PopOne(_ context.Context, _ string) ([]byte, error) {
	if s.popErr != nil {
		return nil, s.popErr
	}
	return []byte("kp"), nil
}
func (s *errStoreKp) PopOnePerDevice(_ context.Context, _ string) ([]keypackages.DevicePackage, error) {
	if s.popErr != nil {
		return nil, s.popErr
	}
	return []keypackages.DevicePackage{{DeviceID: "dev", Payload: []byte("kp")}}, nil
}
func (s *errStoreKp) PopForDevice(_ context.Context, _, _ string, _ int) ([][]byte, error) {
	if s.popErr != nil {
		return nil, s.popErr
	}
	return [][]byte{[]byte("kp")}, nil
}

func (s *errStoreKp) CountUnconsumed(_ context.Context, _ string) (int, error) {
	if s.countErr != nil {
		return 0, s.countErr
	}
	return 0, nil
}
func (s *errStoreKp) CountUnconsumedByDevice(_ context.Context, _, _ string) (int, error) {
	if s.countErr != nil {
		return 0, s.countErr
	}
	return 0, nil
}

func TestService_Count_StoreErrorReturnsInternal(t *testing.T) {
	store := &errStoreKp{countErr: errors.New("disk fire")}
	svc := keypackages.NewService(keypackages.ServiceDeps{
		Store:         store,
		AccountLookup: &fakeAccountLookup{},
		LowWaterMark:  lowWaterMark,
		MaxPerBatch:   maxPerBatch,
		MaxBlobSize:   maxBlobSize,
	})
	_, err := svc.Count(context.Background(), "acct-x", "dev-x")
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeInternal {
		t.Fatalf("err = %v, want ErrCodeInternal", err)
	}
}

func TestService_Fetch_LookupErrorReturnsInternal(t *testing.T) {
	store := keypackages.NewStoreInMemory()
	svc := keypackages.NewService(keypackages.ServiceDeps{
		Store:         store,
		AccountLookup: errLookup{err: errors.New("dns down")},
		LowWaterMark:  lowWaterMark,
		MaxPerBatch:   maxPerBatch,
		MaxBlobSize:   maxBlobSize,
	})
	_, err := svc.FetchForUsername(context.Background(), "acct-requester", "@anyone")
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeInternal {
		t.Fatalf("err = %v, want ErrCodeInternal", err)
	}
}

func TestService_Fetch_PopErrorReturnsInternal(t *testing.T) {
	store := &errStoreKp{popErr: errors.New("pg down")}
	svc := keypackages.NewService(keypackages.ServiceDeps{
		Store: store,
		AccountLookup: &fakeAccountLookup{byUsername: map[string]string{
			"@bob": "acct-bob",
		}},
		LowWaterMark: lowWaterMark,
		MaxPerBatch:  maxPerBatch,
		MaxBlobSize:  maxBlobSize,
	})
	_, err := svc.FetchForUsername(context.Background(), "acct-requester", "@bob")
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeInternal {
		t.Fatalf("err = %v, want ErrCodeInternal", err)
	}
}

func TestService_Fetch_CountErrorAfterPopReturnsKeyPackage(t *testing.T) {
	// Pop succeeds but CountUnconsumed fails: caller still gets the KeyPackage
	// (remaining=-1, ReplenishNeeded=false).
	store := &errStoreKp{countErr: errors.New("count gone")}
	svc := keypackages.NewService(keypackages.ServiceDeps{
		Store: store,
		AccountLookup: &fakeAccountLookup{byUsername: map[string]string{
			"@bob": "acct-bob",
		}},
		LowWaterMark: lowWaterMark,
		MaxPerBatch:  maxPerBatch,
		MaxBlobSize:  maxBlobSize,
	})
	resp, err := svc.FetchForUsername(context.Background(), "acct-requester", "@bob")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if string(resp.KeyPackage) != "kp" {
		t.Fatalf("KeyPackage = %q, want kp", resp.KeyPackage)
	}
	if resp.RemainingForUser != -1 {
		t.Fatalf("RemainingForUser = %d, want -1", resp.RemainingForUser)
	}
	if resp.ReplenishNeeded {
		t.Fatalf("ReplenishNeeded = true, want false when remaining=-1")
	}
}
