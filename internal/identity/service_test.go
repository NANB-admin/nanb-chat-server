package identity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/identity"
	"github.com/nanb/nanb-server/internal/proto"
)

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

type mutableClock struct{ t time.Time }

func (m *mutableClock) Now() time.Time { return m.t }

type seqIDs struct {
	values []string
	i      int
}

func (s *seqIDs) Next() string {
	v := s.values[s.i]
	s.i++
	return v
}

func makeRequest(t *testing.T, username string) proto.CreateAccountRequest {
	t.Helper()
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	devPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	claim := identity.UsernameClaimPayload(username, idPub)
	sig := ed25519.Sign(idPriv, claim)

	return proto.CreateAccountRequest{
		Username:          username,
		IdentityPubKey:    idPub,
		DevicePubKey:      devPub,
		DeviceDisplayName: "test-device",
		SignedClaim:       sig,
		KeyPackages:       [][]byte{[]byte("kp-1"), []byte("kp-2")},
	}
}

// makeRequestWithDeviceKey is like makeRequest but lets the caller supply
// a fixed device public key (so a session test can sign challenges with
// the matching private key).
func makeRequestWithDeviceKey(t *testing.T, username string, devPub ed25519.PublicKey) proto.CreateAccountRequest {
	t.Helper()
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	claim := identity.UsernameClaimPayload(username, idPub)
	sig := ed25519.Sign(idPriv, claim)

	return proto.CreateAccountRequest{
		Username:          username,
		IdentityPubKey:    idPub,
		DevicePubKey:      devPub,
		DeviceDisplayName: "test-device",
		SignedClaim:       sig,
		KeyPackages:       [][]byte{[]byte("kp-1")},
	}
}

func newServiceForTest() (*identity.Service, *identity.StoreInMemory, *seqIDs) {
	store := identity.NewStoreInMemory()
	ids := &seqIDs{values: []string{"acc-1", "dev-1", "acc-2", "dev-2"}}
	clock := fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	_, jwtPriv, _ := ed25519.GenerateKey(rand.Reader)

	svc := identity.NewService(identity.ServiceDeps{
		Store:       store,
		Clock:       clock,
		IDGen:       ids,
		JWTSignKey:  jwtPriv,
		JWTLifetime: 24 * time.Hour,
	})
	return svc, store, ids
}

func TestService_CreateAccount_HappyPath(t *testing.T) {
	svc, store, _ := newServiceForTest()
	req := makeRequest(t, "nass")

	resp, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "acc-1", resp.AccountID)
	assert.Equal(t, "dev-1", resp.DeviceID)
	assert.NotEmpty(t, resp.JWT)

	got, err := store.GetAccountByUsername(context.Background(), "nass")
	require.NoError(t, err)
	assert.Equal(t, "nass", got.Username)
	assert.Equal(t, "acc-1", got.AccountID)
	assert.Len(t, store.KeyPackagesFor("acc-1"), 2)
}

func TestService_CreateAccount_RejectsInvalidUsername(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := makeRequest(t, "Nass")

	_, err := svc.CreateAccount(context.Background(), req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeUsernameInvalid, apiErr.Code)
}

func TestService_CreateAccount_RejectsBadSignature(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := makeRequest(t, "nass")
	req.SignedClaim = []byte("garbage")

	_, err := svc.CreateAccount(context.Background(), req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}

func TestService_CreateAccount_RejectsBadDevicePubKey(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := makeRequest(t, "nass")
	req.DevicePubKey = []byte{1, 2, 3}

	_, err := svc.CreateAccount(context.Background(), req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}

func TestService_CreateAccount_AcceptsX25519PubKey(t *testing.T) {
	svc, store, _ := newServiceForTest()
	req := makeRequest(t, "nass")
	x := make([]byte, 32)
	x[0] = 0xAA
	req.X25519PubKey = x

	_, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	stored, err := store.GetAccountByUsername(context.Background(), "nass")
	require.NoError(t, err)
	assert.Equal(t, x, stored.X25519PubKey)
}

// makeAccountWithIdentity creates a CreateAccountRequest and returns the
// account identity private key so a test can sign a device-link authorization.
func makeAccountWithIdentity(t *testing.T, username string) (proto.CreateAccountRequest, ed25519.PrivateKey) {
	t.Helper()
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	devPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	x := make([]byte, 32)
	x[0] = 0x11
	return proto.CreateAccountRequest{
		Username:       username,
		IdentityPubKey: idPub,
		X25519PubKey:   x,
		DevicePubKey:   devPub,
		SignedClaim:    ed25519.Sign(idPriv, identity.UsernameClaimPayload(username, idPub)),
		KeyPackages:    [][]byte{[]byte("kp-1")},
	}, idPriv
}

func TestService_LinkDevice_HappyPath(t *testing.T) {
	svc, store, _ := newServiceForTest()
	ctx := context.Background()
	acctReq, idPriv := makeAccountWithIdentity(t, "nass")
	created, err := svc.CreateAccount(ctx, acctReq)
	require.NoError(t, err)

	// The new device generates its OWN keys (not phrase-derived).
	newDevPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	newX := make([]byte, 32)
	newX[0] = 0xCD
	// The primary authorizes by signing the new device's pub key with the
	// account identity key.
	signedLink := ed25519.Sign(idPriv, newDevPub)

	resp, err := svc.LinkDevice(ctx, created.DeviceID, proto.LinkDeviceRequest{
		DevicePubKey:      newDevPub,
		X25519PubKey:      newX,
		DeviceDisplayName: "ipad",
		SignedLink:        signedLink,
		KeyPackages:       [][]byte{[]byte("kp-a"), []byte("kp-b")},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.DeviceID)
	assert.NotEqual(t, created.DeviceID, resp.DeviceID)

	// Two active devices now, the new one carrying its own X25519 key.
	devs, err := store.ListActiveDevicesByAccountID(ctx, created.AccountID)
	require.NoError(t, err)
	require.Len(t, devs, 2)
	var linked proto.Device
	for _, d := range devs {
		if d.DeviceID == resp.DeviceID {
			linked = d
		}
	}
	assert.Equal(t, newX, linked.X25519PubKey)
	assert.Len(t, store.KeyPackagesFor(created.AccountID), 3) // 1 primary + 2 linked

	// The freshly-keyed device can discover its server identity by pub key.
	pend, err := svc.PendingDevice(ctx, newDevPub)
	require.NoError(t, err)
	assert.True(t, pend.Linked)
	assert.Equal(t, resp.DeviceID, pend.DeviceID)
	assert.Equal(t, created.AccountID, pend.AccountID)
	assert.Equal(t, "nass", pend.Username)
}

type chanDevicesNotifier struct{ ch chan []string }

func (n chanDevicesNotifier) NotifyDevicesChanged(ids []string) { n.ch <- ids }

func newServiceWithNotifier(n identity.DevicesChangedNotifier) (*identity.Service, *seqIDs) {
	ids := &seqIDs{values: []string{"acc-1", "dev-1", "dev-2", "dev-3"}}
	_, jwtPriv, _ := ed25519.GenerateKey(rand.Reader)
	svc := identity.NewService(identity.ServiceDeps{
		Store:          identity.NewStoreInMemory(),
		Clock:          fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)},
		IDGen:          ids,
		JWTSignKey:     jwtPriv,
		JWTLifetime:    24 * time.Hour,
		DevicesChanged: n,
	})
	return svc, ids
}

func TestService_LinkDevice_NotifiesExistingDevicesButNotTheNewOne(t *testing.T) {
	notifier := chanDevicesNotifier{ch: make(chan []string, 1)}
	svc, _ := newServiceWithNotifier(notifier)
	ctx := context.Background()
	acctReq, idPriv := makeAccountWithIdentity(t, "nass")
	created, err := svc.CreateAccount(ctx, acctReq)
	require.NoError(t, err)
	newDevPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	resp, err := svc.LinkDevice(ctx, created.DeviceID, proto.LinkDeviceRequest{
		DevicePubKey: newDevPub,
		X25519PubKey: make([]byte, 32),
		SignedLink:   ed25519.Sign(idPriv, newDevPub),
		KeyPackages:  [][]byte{[]byte("kp")},
	})
	require.NoError(t, err)

	select {
	case got := <-notifier.ch:
		assert.Equal(t, []string{created.DeviceID}, got)
		assert.NotContains(t, got, resp.DeviceID)
	case <-time.After(2 * time.Second):
		t.Fatal("existing devices were never notified of the link")
	}
}

func TestService_LinkDevice_RetryOfAlreadyLinkedDeviceDoesNotNotify(t *testing.T) {
	notifier := chanDevicesNotifier{ch: make(chan []string, 2)}
	svc, _ := newServiceWithNotifier(notifier)
	ctx := context.Background()
	acctReq, idPriv := makeAccountWithIdentity(t, "nass")
	created, err := svc.CreateAccount(ctx, acctReq)
	require.NoError(t, err)
	newDevPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	req := proto.LinkDeviceRequest{
		DevicePubKey: newDevPub,
		X25519PubKey: make([]byte, 32),
		SignedLink:   ed25519.Sign(idPriv, newDevPub),
		KeyPackages:  [][]byte{[]byte("kp")},
	}
	_, err = svc.LinkDevice(ctx, created.DeviceID, req)
	require.NoError(t, err)
	<-notifier.ch // the first link's notification

	_, err = svc.LinkDevice(ctx, created.DeviceID, req)
	require.NoError(t, err)

	select {
	case <-notifier.ch:
		t.Fatal("an idempotent re-link must not notify again")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestService_LinkDevice_RejectsForgedAuthorization(t *testing.T) {
	svc, _, _ := newServiceForTest()
	ctx := context.Background()
	acctReq, _ := makeAccountWithIdentity(t, "nass")
	created, err := svc.CreateAccount(ctx, acctReq)
	require.NoError(t, err)

	newDevPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	// Sign the link with a key that is NOT the account identity key.
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, err = svc.LinkDevice(ctx, created.DeviceID, proto.LinkDeviceRequest{
		DevicePubKey: newDevPub,
		X25519PubKey: make([]byte, 32),
		SignedLink:   ed25519.Sign(wrongPriv, newDevPub),
		KeyPackages:  [][]byte{[]byte("kp")},
	})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}

func TestService_LinkDevice_IsIdempotentOnRetry(t *testing.T) {
	svc, store, _ := newServiceForTest()
	ctx := context.Background()
	acctReq, idPriv := makeAccountWithIdentity(t, "nass")
	created, err := svc.CreateAccount(ctx, acctReq)
	require.NoError(t, err)

	newDevPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	req := proto.LinkDeviceRequest{
		DevicePubKey: newDevPub,
		X25519PubKey: make([]byte, 32),
		SignedLink:   ed25519.Sign(idPriv, newDevPub),
		KeyPackages:  [][]byte{[]byte("kp")},
	}
	first, err := svc.LinkDevice(ctx, created.DeviceID, req)
	require.NoError(t, err)
	second, err := svc.LinkDevice(ctx, created.DeviceID, req)
	require.NoError(t, err)

	// A re-link of the same pub key returns the same device and doesn't create
	// a duplicate row.
	assert.Equal(t, first.DeviceID, second.DeviceID)
	devs, _ := store.ListActiveDevicesByAccountID(ctx, created.AccountID)
	assert.Len(t, devs, 2)
}

func TestService_UpdateProfile_SetsAndTrimsDisplayName(t *testing.T) {
	svc, store, _ := newServiceForTest()
	ctx := context.Background()
	created, err := svc.CreateAccount(ctx, makeRequest(t, "nass"))
	require.NoError(t, err)

	padded := "  Alex J  "
	require.NoError(t, svc.UpdateProfile(
		ctx, created.AccountID, proto.UpdateProfileRequest{DisplayName: &padded}))

	acc, err := store.GetAccountByUsername(ctx, "nass")
	require.NoError(t, err)
	assert.Equal(t, "Alex J", acc.DisplayName) // trimmed
}

func TestService_UpdateProfile_RejectsTooLong(t *testing.T) {
	svc, _, _ := newServiceForTest()
	ctx := context.Background()
	created, err := svc.CreateAccount(ctx, makeRequest(t, "nass"))
	require.NoError(t, err)

	long := strings.Repeat("x", identity.MaxDisplayNameLen+1)
	err = svc.UpdateProfile(
		ctx, created.AccountID, proto.UpdateProfileRequest{DisplayName: &long})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestService_UpdateProfile_RejectsEmptyUpdate(t *testing.T) {
	svc, _, _ := newServiceForTest()
	ctx := context.Background()
	created, err := svc.CreateAccount(ctx, makeRequest(t, "nass"))
	require.NoError(t, err)

	err = svc.UpdateProfile(ctx, created.AccountID, proto.UpdateProfileRequest{})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestService_PendingDevice_NotLinkedYet(t *testing.T) {
	svc, _, _ := newServiceForTest()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	resp, err := svc.PendingDevice(context.Background(), pub)
	require.NoError(t, err)
	assert.False(t, resp.Linked)
	assert.Empty(t, resp.DeviceID)
}

func TestService_CreateAccount_OmitsX25519PubKeyWhenAbsent(t *testing.T) {
	// Backwards-compat: clients pre-X25519 simply omit the field; account creation must still succeed.
	svc, store, _ := newServiceForTest()
	req := makeRequest(t, "nass")
	req.X25519PubKey = nil

	_, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	stored, err := store.GetAccountByUsername(context.Background(), "nass")
	require.NoError(t, err)
	assert.Empty(t, stored.X25519PubKey)
}

func TestService_CreateAccount_RejectsShortX25519PubKey(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := makeRequest(t, "nass")
	req.X25519PubKey = []byte{1, 2, 3} // not 32 bytes

	_, err := svc.CreateAccount(context.Background(), req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}

func TestService_CreateAccount_RejectsEmptyKeyPackage(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := makeRequest(t, "nass")
	req.KeyPackages = [][]byte{[]byte("ok"), {}}

	_, err := svc.CreateAccount(context.Background(), req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeKeyPackageInvalid, apiErr.Code)
}

func TestService_CreateAccount_RejectsOversizedKeyPackageBatch(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := makeRequest(t, "nass")
	batch := make([][]byte, identity.MaxKeyPackagesPerRequest+1)
	for i := range batch {
		batch[i] = []byte("kp")
	}
	req.KeyPackages = batch

	_, err := svc.CreateAccount(context.Background(), req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeKeyPackageInvalid, apiErr.Code)
}

func TestService_CreateAccount_RejectsOversizedKeyPackageBlob(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := makeRequest(t, "nass")
	req.KeyPackages = [][]byte{make([]byte, identity.MaxKeyPackageBlobSize+1)}

	_, err := svc.CreateAccount(context.Background(), req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeKeyPackageInvalid, apiErr.Code)
}

func TestService_LinkDevice_RejectsOversizedKeyPackageBatch(t *testing.T) {
	svc, _, _ := newServiceForTest()
	ctx := context.Background()
	acctReq, idPriv := makeAccountWithIdentity(t, "nass")
	created, err := svc.CreateAccount(ctx, acctReq)
	require.NoError(t, err)

	newDevPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	batch := make([][]byte, identity.MaxKeyPackagesPerRequest+1)
	for i := range batch {
		batch[i] = []byte("kp")
	}

	_, err = svc.LinkDevice(ctx, created.DeviceID, proto.LinkDeviceRequest{
		DevicePubKey: newDevPub,
		X25519PubKey: make([]byte, 32),
		SignedLink:   ed25519.Sign(idPriv, newDevPub),
		KeyPackages:  batch,
	})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeKeyPackageInvalid, apiErr.Code)
}

func TestService_CreateAccount_RejectsTakenUsername(t *testing.T) {
	svc, _, _ := newServiceForTest()

	req := makeRequest(t, "nass")
	_, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	req2 := makeRequest(t, "nass")
	_, err = svc.CreateAccount(context.Background(), req2)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeUsernameTaken, apiErr.Code)
}

func TestService_CreateAccount_RejectsHeldUsername(t *testing.T) {
	svc, store, _ := newServiceForTest()
	store.AddUsernameHold("nass", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	req := makeRequest(t, "nass")
	_, err := svc.CreateAccount(context.Background(), req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeUsernameOnHold, apiErr.Code)
}

func TestService_CreateAccount_RejectsDuplicateIdentityKey(t *testing.T) {
	// Same identity key under two usernames = same recovery phrase twice.
	// Restore is keyed by (username, identity key) but the phrase alone must
	// map to one identity — reject the second signup.
	svc, _, _ := newServiceForTest()

	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	mkReq := func(username string) proto.CreateAccountRequest {
		devPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		return proto.CreateAccountRequest{
			Username:       username,
			IdentityPubKey: idPub,
			DevicePubKey:   devPub,
			SignedClaim:    ed25519.Sign(idPriv, identity.UsernameClaimPayload(username, idPub)),
			KeyPackages:    [][]byte{[]byte("kp-1")},
		}
	}

	_, err = svc.CreateAccount(context.Background(), mkReq("nass"))
	require.NoError(t, err)

	_, err = svc.CreateAccount(context.Background(), mkReq("other"))
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeIdentityKeyTaken, apiErr.Code)
}

func TestService_CheckUsername_Available(t *testing.T) {
	svc, _, _ := newServiceForTest()

	avail, err := svc.CheckUsername(context.Background(), "nass")
	require.NoError(t, err)
	assert.True(t, avail.Available)
	assert.Empty(t, avail.Reason)
}

func TestService_CheckUsername_Taken(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)

	avail, err := svc.CheckUsername(context.Background(), "nass")
	require.NoError(t, err)
	assert.False(t, avail.Available)
	assert.Equal(t, "taken", avail.Reason)
}

func TestService_CheckUsername_OnHold_ReportedAsTakenForPrivacy(t *testing.T) {
	svc, store, _ := newServiceForTest()
	store.AddUsernameHold("nass", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))

	avail, err := svc.CheckUsername(context.Background(), "nass")
	require.NoError(t, err)
	assert.False(t, avail.Available)
	// A held (recently-deleted) name must be indistinguishable from a live
	// "taken" one on this unauthenticated endpoint — no deletion-history oracle.
	assert.Equal(t, "taken", avail.Reason)
}

func TestService_CheckUsername_Invalid(t *testing.T) {
	svc, _, _ := newServiceForTest()

	avail, err := svc.CheckUsername(context.Background(), "Not Valid!")
	require.NoError(t, err)
	assert.False(t, avail.Available)
	assert.Equal(t, "invalid", avail.Reason)
}

func TestService_IssueChallenge_KnownUserAndDevice(t *testing.T) {
	svc, _, _ := newServiceForTest()

	req := makeRequest(t, "nass")
	_, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	chal, exp, err := svc.IssueChallenge(context.Background(), "nass", "dev-1")
	require.NoError(t, err)
	assert.Len(t, chal, 32)
	// Fixed clock is 2026-05-07 12:00:00 UTC; expiry should be +2 min.
	expectedExp := time.Date(2026, 5, 7, 12, 2, 0, 0, time.UTC).Unix()
	assert.Equal(t, expectedExp, exp)
}

func TestService_IssueChallenge_UnknownUser(t *testing.T) {
	svc, _, _ := newServiceForTest()

	_, _, err := svc.IssueChallenge(context.Background(), "ghost", "dev-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

func TestService_IssueChallenge_UnknownDevice(t *testing.T) {
	svc, _, _ := newServiceForTest()

	req := makeRequest(t, "nass")
	_, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	_, _, err = svc.IssueChallenge(context.Background(), "nass", "dev-other")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeDeviceNotFound, apiErr.Code)
}

// IssueChallenge must reject (username, deviceID) where the device belongs
// to a different account. Catches a class of API misuse where a caller
// names someone else's username with their own device id.
func TestService_IssueChallenge_DeviceNotOwnedByAccount(t *testing.T) {
	svc, _, _ := newServiceForTest()

	// Account A — gets device id "dev-1".
	require.NoError(t, func() error {
		_, err := svc.CreateAccount(context.Background(), makeRequest(t, "alice"))
		return err
	}())
	// Account B — also gets a device, but the IDGenerator yields "dev-2".
	require.NoError(t, func() error {
		_, err := svc.CreateAccount(context.Background(), makeRequest(t, "bob"))
		return err
	}())

	// Trying to issue a challenge "for alice" against bob's device id.
	_, _, err := svc.IssueChallenge(context.Background(), "alice", "dev-2")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeDeviceNotFound, apiErr.Code)
}

func TestService_CompleteSession_HappyPath(t *testing.T) {
	svc, _, _ := newServiceForTest()

	devPub, devPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	req := makeRequestWithDeviceKey(t, "nass", devPub)
	_, err = svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	chal, _, err := svc.IssueChallenge(context.Background(), "nass", "dev-1")
	require.NoError(t, err)

	sig := ed25519.Sign(devPriv, chal)
	jwt, err := svc.CompleteSession(context.Background(), "nass", "dev-1", chal, sig)
	require.NoError(t, err)
	assert.NotEmpty(t, jwt)
}

func TestService_CompleteSession_RejectsBadSignature(t *testing.T) {
	svc, _, _ := newServiceForTest()

	req := makeRequest(t, "nass")
	_, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	chal, _, err := svc.IssueChallenge(context.Background(), "nass", "dev-1")
	require.NoError(t, err)

	_, err = svc.CompleteSession(context.Background(), "nass", "dev-1", chal, []byte("bad"))
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}

// A challenge is looked up by its own bytes, so presenting one that was never
// issued finds nothing — even while a genuine one is outstanding.
func TestService_CompleteSession_RejectsAChallengeItDidNotIssue(t *testing.T) {
	svc, _, _ := newServiceForTest()

	devPub, devPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	req := makeRequestWithDeviceKey(t, "nass", devPub)
	_, err = svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	storedChal, _, err := svc.IssueChallenge(context.Background(), "nass", "dev-1")
	require.NoError(t, err)
	_ = storedChal

	// Present a different challenge of the same length, signed with the right key.
	tampered := make([]byte, 32)
	tampered[0] = 0x42
	sig := ed25519.Sign(devPriv, tampered)

	_, err = svc.CompleteSession(context.Background(), "nass", "dev-1", tampered, sig)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeChallengeNotFound, apiErr.Code)
}

func TestService_CompleteSession_RejectsUnknownChallenge(t *testing.T) {
	svc, _, _ := newServiceForTest()

	req := makeRequest(t, "nass")
	_, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	_, err = svc.CompleteSession(context.Background(), "nass", "dev-1", []byte("never-issued"), []byte("sig"))
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeChallengeNotFound, apiErr.Code)
}

func TestService_CompleteSession_RejectsExpiredChallenge(t *testing.T) {
	store := identity.NewStoreInMemory()
	ids := &seqIDs{values: []string{"acc-1", "dev-1"}}
	startTime := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	clock := &mutableClock{t: startTime}
	_, jwtPriv, _ := ed25519.GenerateKey(rand.Reader)

	svc := identity.NewService(identity.ServiceDeps{
		Store:       store,
		Clock:       clock,
		IDGen:       ids,
		JWTSignKey:  jwtPriv,
		JWTLifetime: 24 * time.Hour,
	})

	devPub, devPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	req := makeRequestWithDeviceKey(t, "nass", devPub)
	_, err = svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	chal, _, err := svc.IssueChallenge(context.Background(), "nass", "dev-1")
	require.NoError(t, err)

	clock.t = startTime.Add(10 * time.Minute) // past challenge expiry (2 min)

	sig := ed25519.Sign(devPriv, chal)
	_, err = svc.CompleteSession(context.Background(), "nass", "dev-1", chal, sig)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeChallengeExpired, apiErr.Code)
}

func TestService_CompleteSession_RejectsUnknownDevice(t *testing.T) {
	svc, _, _ := newServiceForTest()

	_, err := svc.CompleteSession(context.Background(), "nass", "dev-ghost", []byte("c"), []byte("s"))
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeDeviceNotFound, apiErr.Code)
}

func TestService_CompleteSession_RejectsMalformedChallenge(t *testing.T) {
	// A challenge of the wrong length can't be one we issued; it is not looked up.
	svc, _, _ := newServiceForTest()

	devPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	req := makeRequestWithDeviceKey(t, "nass", devPub)
	_, err = svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	_, _, err = svc.IssueChallenge(context.Background(), "nass", "dev-1")
	require.NoError(t, err)

	// Present a challenge that is shorter than what was stored (32 vs 5).
	_, err = svc.CompleteSession(context.Background(), "nass", "dev-1", []byte("short"), make([]byte, ed25519.SignatureSize))
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeChallengeNotFound, apiErr.Code)
}

// errStore is a test-only Store that returns the configured error from a chosen method.
type errStore struct {
	identity.Store
	failHasUsernameHold      error
	failCreateAccount        error
	failGetAccountByUser     error
	failGetActiveDevice      error
	failGetDeviceByAccount   error
	failListDevices          error
	failStoreChallenge       error
	failConsumeChallenge     error
	consumeChallengeBytes    []byte
	getDevicePassthroughDev  *proto.Device
	getDeviceByAccountResult *proto.Device
}

func (e *errStore) HasUsernameHold(ctx context.Context, username string, now time.Time) (bool, error) {
	if e.failHasUsernameHold != nil {
		return false, e.failHasUsernameHold
	}
	return e.Store.HasUsernameHold(ctx, username, now)
}

func (e *errStore) CreateAccountWithDevice(ctx context.Context, args identity.CreateAccountArgs) error {
	if e.failCreateAccount != nil {
		return e.failCreateAccount
	}
	return e.Store.CreateAccountWithDevice(ctx, args)
}

func (e *errStore) GetAccountByUsername(ctx context.Context, username string) (proto.Account, error) {
	if e.failGetAccountByUser != nil {
		return proto.Account{}, e.failGetAccountByUser
	}
	return e.Store.GetAccountByUsername(ctx, username)
}

func (e *errStore) GetActiveDeviceByID(ctx context.Context, deviceID string) (proto.Device, error) {
	if e.failGetActiveDevice != nil {
		return proto.Device{}, e.failGetActiveDevice
	}
	if e.getDevicePassthroughDev != nil {
		return *e.getDevicePassthroughDev, nil
	}
	return e.Store.GetActiveDeviceByID(ctx, deviceID)
}

func (e *errStore) GetActiveDeviceByAccountID(ctx context.Context, accountID string) (proto.Device, error) {
	if e.failGetDeviceByAccount != nil {
		return proto.Device{}, e.failGetDeviceByAccount
	}
	if e.getDeviceByAccountResult != nil {
		return *e.getDeviceByAccountResult, nil
	}
	return e.Store.GetActiveDeviceByAccountID(ctx, accountID)
}

func (e *errStore) ListActiveDevicesByAccountID(ctx context.Context, accountID string) ([]proto.Device, error) {
	if e.failListDevices != nil {
		return nil, e.failListDevices
	}
	return e.Store.ListActiveDevicesByAccountID(ctx, accountID)
}

func (e *errStore) StoreChallenge(ctx context.Context, key string, challenge []byte, expiresAt time.Time) error {
	if e.failStoreChallenge != nil {
		return e.failStoreChallenge
	}
	return e.Store.StoreChallenge(ctx, key, challenge, expiresAt)
}

func (e *errStore) ConsumeChallenge(ctx context.Context, key string, now time.Time) ([]byte, error) {
	if e.failConsumeChallenge != nil {
		return nil, e.failConsumeChallenge
	}
	if e.consumeChallengeBytes != nil {
		return e.consumeChallengeBytes, nil
	}
	return e.Store.ConsumeChallenge(ctx, key, now)
}

func newServiceWithStore(store identity.Store) *identity.Service {
	ids := &seqIDs{values: []string{"acc-1", "dev-1", "acc-2", "dev-2"}}
	clock := fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	_, jwtPriv, _ := ed25519.GenerateKey(rand.Reader)
	return identity.NewService(identity.ServiceDeps{
		Store:       store,
		Clock:       clock,
		IDGen:       ids,
		JWTSignKey:  jwtPriv,
		JWTLifetime: 24 * time.Hour,
	})
}

func TestService_RepublishDeviceX25519_RejectsWrongLength(t *testing.T) {
	// The stored key is what every peer seals to, so a short/garbled value would
	// brick inbound delivery for the device just as thoroughly as a stale one.
	svc := newServiceWithStore(identity.NewStoreInMemory())

	err := svc.RepublishDeviceX25519(context.Background(), "dev-1", []byte{1, 2, 3})

	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestService_CreateAccount_PropagatesHasUsernameHoldError(t *testing.T) {
	es := &errStore{Store: identity.NewStoreInMemory(), failHasUsernameHold: errors.New("db down")}
	svc := newServiceWithStore(es)
	req := makeRequest(t, "nass")

	_, err := svc.CreateAccount(context.Background(), req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_CreateAccount_PropagatesCreateAccountError(t *testing.T) {
	es := &errStore{Store: identity.NewStoreInMemory(), failCreateAccount: errors.New("db down")}
	svc := newServiceWithStore(es)
	req := makeRequest(t, "nass")

	_, err := svc.CreateAccount(context.Background(), req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_IssueChallenge_PropagatesAccountLookupError(t *testing.T) {
	es := &errStore{Store: identity.NewStoreInMemory(), failGetAccountByUser: errors.New("db down")}
	svc := newServiceWithStore(es)

	_, _, err := svc.IssueChallenge(context.Background(), "nass", "dev-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_IssueChallenge_PropagatesDeviceLookupError(t *testing.T) {
	store := identity.NewStoreInMemory()
	es := &errStore{Store: store, failGetActiveDevice: errors.New("db down")}
	svc := newServiceWithStore(es)

	// Seed the account so the account-lookup step succeeds.
	req := makeRequest(t, "nass")
	_, err := newServiceWithStore(store).CreateAccount(context.Background(), req)
	require.NoError(t, err)

	_, _, err = svc.IssueChallenge(context.Background(), "nass", "dev-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_IssueChallenge_PropagatesStoreChallengeError(t *testing.T) {
	store := identity.NewStoreInMemory()
	es := &errStore{Store: store, failStoreChallenge: errors.New("db down")}
	svc := newServiceWithStore(es)

	req := makeRequest(t, "nass")
	_, err := newServiceWithStore(store).CreateAccount(context.Background(), req)
	require.NoError(t, err)

	_, _, err = svc.IssueChallenge(context.Background(), "nass", "dev-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_CompleteSession_PropagatesDeviceLookupError(t *testing.T) {
	es := &errStore{Store: identity.NewStoreInMemory(), failGetActiveDevice: errors.New("db down")}
	svc := newServiceWithStore(es)

	_, err := svc.CompleteSession(context.Background(), "nass", "dev-1", []byte("c"), []byte("s"))
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_CompleteSession_PropagatesConsumeChallengeError(t *testing.T) {
	store := identity.NewStoreInMemory()
	es := &errStore{Store: store, failConsumeChallenge: errors.New("db down")}
	svc := newServiceWithStore(es)

	devPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	req := makeRequestWithDeviceKey(t, "nass", devPub)
	_, err = newServiceWithStore(store).CreateAccount(context.Background(), req)
	require.NoError(t, err)

	_, err = svc.CompleteSession(context.Background(), "nass", "dev-1", make([]byte, 32), make([]byte, ed25519.SignatureSize))
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_IssueChallenge_PropagatesChallengeReaderError(t *testing.T) {
	store := identity.NewStoreInMemory()
	svc := newServiceWithStore(store)

	req := makeRequest(t, "nass")
	_, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	orig := crypto.ChallengeReader
	t.Cleanup(func() { crypto.ChallengeReader = orig })
	crypto.ChallengeReader = iotest.ErrReader(errors.New("rng down"))

	_, _, err = svc.IssueChallenge(context.Background(), "nass", "dev-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestStoreInMemory_KeyPackagesFor_FiltersByAccount(t *testing.T) {
	// Cover the "skip non-matching account" branch in KeyPackagesFor.
	store := identity.NewStoreInMemory()
	now := time.Now()
	require.NoError(t, store.CreateAccountWithDevice(context.Background(), identity.CreateAccountArgs{
		Account: proto.Account{AccountID: "acc-A", Username: "alpha"},
		Device:  proto.Device{DeviceID: "dev-A", AccountID: "acc-A"},
		KeyPackages: [][]byte{[]byte("a-kp1")},
		KPExpiresAt: now,
	}))
	require.NoError(t, store.CreateAccountWithDevice(context.Background(), identity.CreateAccountArgs{
		Account: proto.Account{AccountID: "acc-B", Username: "bravo"},
		Device:  proto.Device{DeviceID: "dev-B", AccountID: "acc-B"},
		KeyPackages: [][]byte{[]byte("b-kp1"), []byte("b-kp2")},
		KPExpiresAt: now,
	}))

	a := store.KeyPackagesFor("acc-A")
	b := store.KeyPackagesFor("acc-B")

	assert.Len(t, a, 1)
	assert.Len(t, b, 2)
}

func TestService_CompleteSession_RejectsBadDevicePubKeyLength(t *testing.T) {
	// Cover the dev.DevicePubKey length check inside CompleteSession.
	// Inject a device with a malformed pub key.
	store := identity.NewStoreInMemory()
	chal := make([]byte, 32)
	es := &errStore{
		Store:                 store,
		consumeChallengeBytes: chal,
		getDevicePassthroughDev: &proto.Device{
			DeviceID:     "dev-1",
			AccountID:    "acc-1",
			DevicePubKey: []byte{1, 2, 3}, // wrong length
		},
	}
	svc := newServiceWithStore(es)

	_, err := svc.CompleteSession(context.Background(), "nass", "dev-1", chal, make([]byte, ed25519.SignatureSize))
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}

func TestService_LookupAccount_HappyPath(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := makeRequest(t, "nass")
	_, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)

	got, err := svc.LookupAccount(context.Background(), "nass")
	require.NoError(t, err)
	assert.Equal(t, "nass", got.Username)
	assert.Equal(t, "acc-1", got.AccountID)
}

func TestService_LookupAccount_RejectsInvalidUsername(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.LookupAccount(context.Background(), "AB")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeUsernameInvalid, apiErr.Code)
}

func TestService_LookupAccount_NotFound(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.LookupAccount(context.Background(), "ghost")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

func TestService_LookupAccount_PropagatesStoreError(t *testing.T) {
	es := &errStore{Store: identity.NewStoreInMemory(), failGetAccountByUser: errors.New("db down")}
	svc := newServiceWithStore(es)

	_, err := svc.LookupAccount(context.Background(), "nass")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

// ----- Restore flow -----

// makeRestoreFixture seeds an account whose identity keypair is known to the
// caller, so the test can sign a challenge with the matching private key.
func makeRestoreFixture(t *testing.T, svc *identity.Service, store *identity.StoreInMemory, username string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	claim := identity.UsernameClaimPayload(username, idPub)
	sig := ed25519.Sign(idPriv, claim)

	_, err = svc.CreateAccount(context.Background(), proto.CreateAccountRequest{
		Username:       username,
		IdentityPubKey: idPub,
		DevicePubKey:   idPub, // v1 single-device: identity == device
		SignedClaim:    sig,
		KeyPackages:    [][]byte{[]byte("kp")},
	})
	require.NoError(t, err)
	_ = store
	return idPub, idPriv
}

func TestService_IssueRestoreChallenge_HappyPath(t *testing.T) {
	svc, store, _ := newServiceForTest()
	makeRestoreFixture(t, svc, store, "nass")

	chal, exp, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)
	assert.Len(t, chal, 32)
	expectedExp := time.Date(2026, 5, 7, 12, 2, 0, 0, time.UTC).Unix()
	assert.Equal(t, expectedExp, exp)
}

func TestService_IssueRestoreChallenge_RejectsInvalidUsername(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, _, err := svc.IssueRestoreChallenge(context.Background(), "BAD")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeUsernameInvalid, apiErr.Code)
}

func TestService_IssueRestoreChallenge_UnknownAccount(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, _, err := svc.IssueRestoreChallenge(context.Background(), "ghost")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

func TestService_IssueRestoreChallenge_PropagatesStoreLookupError(t *testing.T) {
	es := &errStore{Store: identity.NewStoreInMemory(), failGetAccountByUser: errors.New("db down")}
	svc := newServiceWithStore(es)
	_, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_IssueRestoreChallenge_PropagatesStoreChallengeError(t *testing.T) {
	store := identity.NewStoreInMemory()
	es := &errStore{Store: store, failStoreChallenge: errors.New("db down")}
	svc := newServiceWithStore(es)
	makeRestoreFixture(t, newServiceWithStore(store), store, "nass")
	_, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_IssueRestoreChallenge_PropagatesChallengeReaderError(t *testing.T) {
	svc, store, _ := newServiceForTest()
	makeRestoreFixture(t, svc, store, "nass")

	orig := crypto.ChallengeReader
	t.Cleanup(func() { crypto.ChallengeReader = orig })
	crypto.ChallengeReader = iotest.ErrReader(errors.New("rng down"))

	_, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_CompleteRestoreSession_HappyPath(t *testing.T) {
	svc, store, _ := newServiceForTest()
	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")

	// The account was created with a key package; restore must purge it,
	// since the restored device no longer holds its private key.
	require.NotEmpty(t, store.KeyPackagesFor("acc-1"))

	chal, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)

	sig := ed25519.Sign(idPriv, chal)
	resp, err := svc.CompleteRestoreSession(context.Background(), "nass", idPub, chal, sig, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "acc-1", resp.AccountID)
	assert.Equal(t, "dev-1", resp.DeviceID)
	assert.NotEmpty(t, resp.JWT)
	// Stale (now-undecryptable) key packages are gone — peers can't fetch one
	// and build a Welcome the restored device can't open. The client
	// republishes a fresh batch right after restore.
	assert.Empty(t, store.KeyPackagesFor("acc-1"))
}

func TestService_CompleteRestoreSession_MintsNewDeviceAndRevokesOthers(t *testing.T) {
	svc, store, _ := newServiceForTest()
	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")

	chal, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)
	sig := ed25519.Sign(idPriv, chal)

	devPub := make([]byte, ed25519.PublicKeySize)
	xPub := make([]byte, 32)
	resp, err := svc.CompleteRestoreSession(
		context.Background(), "nass", idPub, chal, sig, devPub, xPub)
	require.NoError(t, err)
	assert.Equal(t, "acc-1", resp.AccountID)
	assert.NotEmpty(t, resp.DeviceID)
	assert.NotEqual(t, "dev-1", resp.DeviceID,
		"restore with a device key mints a NEW device id, not the reused one")

	// The old device dev-1 is revoked; the minted device is the sole active one.
	devs, err := store.ListActiveDevicesByAccountID(context.Background(), "acc-1")
	require.NoError(t, err)
	require.Len(t, devs, 1, "old device kicked, only the freshly-minted one remains")
	assert.Equal(t, resp.DeviceID, devs[0].DeviceID)

	_, err = store.GetActiveDeviceByID(context.Background(), "dev-1")
	assert.ErrorIs(t, err, identity.ErrNotFound, "old device no longer active")
}

func TestService_CompleteRestoreSession_KeepOtherDevicesLeavesThemActive(t *testing.T) {
	svc, store, _ := newServiceForTest()
	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")

	chal, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)
	sig := ed25519.Sign(idPriv, chal)

	resp, err := svc.CompleteRestoreSession(
		context.Background(), "nass", idPub, chal, sig,
		make([]byte, ed25519.PublicKeySize), make([]byte, 32),
		identity.KeepOtherDevices())
	require.NoError(t, err)

	devs, err := store.ListActiveDevicesByAccountID(context.Background(), "acc-1")
	require.NoError(t, err)
	assert.Len(t, devs, 2, "the old device stays active beside the new one")
	_, err = store.GetActiveDeviceByID(context.Background(), "dev-1")
	assert.NoError(t, err, "old device not revoked")
	assert.NotEqual(t, "dev-1", resp.DeviceID)
}

func TestService_CompleteRestoreSession_RejectsInvalidUsername(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.CompleteRestoreSession(context.Background(), "BAD", make([]byte, ed25519.PublicKeySize), make([]byte, 32), make([]byte, ed25519.SignatureSize), nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeUsernameInvalid, apiErr.Code)
}

func TestService_CompleteRestoreSession_RejectsBadIdentityKeyLength(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.CompleteRestoreSession(context.Background(), "nass", []byte{1, 2}, make([]byte, 32), make([]byte, ed25519.SignatureSize), nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}

func TestService_CompleteRestoreSession_RejectsBadSignatureLength(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.CompleteRestoreSession(context.Background(), "nass", make([]byte, ed25519.PublicKeySize), make([]byte, 32), []byte{1, 2}, nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}

func TestService_CompleteRestoreSession_RejectsUnknownAccount(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.CompleteRestoreSession(context.Background(), "ghost", make([]byte, ed25519.PublicKeySize), make([]byte, 32), make([]byte, ed25519.SignatureSize), nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

func TestService_CompleteRestoreSession_PropagatesAccountLookupError(t *testing.T) {
	es := &errStore{Store: identity.NewStoreInMemory(), failGetAccountByUser: errors.New("db down")}
	svc := newServiceWithStore(es)
	_, err := svc.CompleteRestoreSession(context.Background(), "nass", make([]byte, ed25519.PublicKeySize), make([]byte, 32), make([]byte, ed25519.SignatureSize), nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_CompleteRestoreSession_RejectsIdentityKeyMismatch(t *testing.T) {
	svc, store, _ := newServiceForTest()
	makeRestoreFixture(t, svc, store, "nass")

	chal, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)

	// Use a *different* keypair than what's registered.
	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sig := ed25519.Sign(otherPriv, chal)

	_, err = svc.CompleteRestoreSession(context.Background(), "nass", otherPub, chal, sig, nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}

func TestService_CompleteRestoreSession_RejectsMissingChallenge(t *testing.T) {
	svc, store, _ := newServiceForTest()
	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")

	// Skip IssueRestoreChallenge — no stored challenge to consume.
	chal := make([]byte, 32)
	sig := ed25519.Sign(idPriv, chal)

	_, err := svc.CompleteRestoreSession(context.Background(), "nass", idPub, chal, sig, nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeChallengeNotFound, apiErr.Code)
}

func TestService_CompleteRestoreSession_RejectsExpiredChallenge(t *testing.T) {
	store := identity.NewStoreInMemory()
	ids := &seqIDs{values: []string{"acc-1", "dev-1"}}
	startTime := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	clock := &mutableClock{t: startTime}
	_, jwtPriv, _ := ed25519.GenerateKey(rand.Reader)
	svc := identity.NewService(identity.ServiceDeps{
		Store: store, Clock: clock, IDGen: ids, JWTSignKey: jwtPriv, JWTLifetime: 24 * time.Hour,
	})

	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")

	chal, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)

	clock.t = startTime.Add(10 * time.Minute) // past 2-min expiry

	sig := ed25519.Sign(idPriv, chal)
	_, err = svc.CompleteRestoreSession(context.Background(), "nass", idPub, chal, sig, nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeChallengeExpired, apiErr.Code)
}

func TestService_CompleteRestoreSession_PropagatesConsumeChallengeError(t *testing.T) {
	store := identity.NewStoreInMemory()
	es := &errStore{Store: store, failConsumeChallenge: errors.New("db down")}
	svc := newServiceWithStore(es)

	idPub, idPriv := makeRestoreFixture(t, newServiceWithStore(store), store, "nass")

	chal := make([]byte, 32)
	sig := ed25519.Sign(idPriv, chal)
	_, err := svc.CompleteRestoreSession(context.Background(), "nass", idPub, chal, sig, nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestService_CompleteRestoreSession_RejectsAChallengeItDidNotIssue(t *testing.T) {
	svc, store, _ := newServiceForTest()
	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")

	storedChal, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)
	_ = storedChal

	tampered := make([]byte, 32)
	tampered[0] = 0x42
	sig := ed25519.Sign(idPriv, tampered)

	_, err = svc.CompleteRestoreSession(context.Background(), "nass", idPub, tampered, sig, nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeChallengeNotFound, apiErr.Code)
}

func TestService_CompleteRestoreSession_RejectsBadSignature(t *testing.T) {
	svc, store, _ := newServiceForTest()
	idPub, _ := makeRestoreFixture(t, svc, store, "nass")

	chal, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)

	// Right key length, but signature is junk over the challenge.
	junkSig := make([]byte, ed25519.SignatureSize)
	_, err = svc.CompleteRestoreSession(context.Background(), "nass", idPub, chal, junkSig, nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}

func TestService_CompleteRestoreSession_DeviceNotFound(t *testing.T) {
	store := identity.NewStoreInMemory()
	es := &errStore{Store: store, failGetDeviceByAccount: identity.ErrNotFound}
	svc := newServiceWithStore(es)

	idPub, idPriv := makeRestoreFixture(t, newServiceWithStore(store), store, "nass")
	chal, _, err := newServiceWithStore(store).IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)
	sig := ed25519.Sign(idPriv, chal)

	_, err = svc.CompleteRestoreSession(context.Background(), "nass", idPub, chal, sig, nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeDeviceNotFound, apiErr.Code)
}

func TestService_CompleteRestoreSession_PropagatesDeviceLookupError(t *testing.T) {
	store := identity.NewStoreInMemory()
	es := &errStore{Store: store, failGetDeviceByAccount: errors.New("db down")}
	svc := newServiceWithStore(es)

	idPub, idPriv := makeRestoreFixture(t, newServiceWithStore(store), store, "nass")
	chal, _, err := newServiceWithStore(store).IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)
	sig := ed25519.Sign(idPriv, chal)

	_, err = svc.CompleteRestoreSession(context.Background(), "nass", idPub, chal, sig, nil, nil)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestStoreInMemory_GetActiveDeviceByAccountID_NotFound(t *testing.T) {
	store := identity.NewStoreInMemory()
	_, err := store.GetActiveDeviceByAccountID(context.Background(), "missing")
	require.ErrorIs(t, err, identity.ErrNotFound)
}

// ----- ListDevices -----

func TestService_ListDevices_HappyPath(t *testing.T) {
	svc, store, _ := newServiceForTest()
	makeRestoreFixture(t, svc, store, "nass")

	devs, err := svc.ListDevices(context.Background(), "acc-1")
	require.NoError(t, err)
	require.Len(t, devs, 1)
	assert.Equal(t, "dev-1", devs[0].DeviceID)
	assert.Equal(t, "acc-1", devs[0].AccountID)
}

func TestService_ListDevices_EmptyForUnknownAccount(t *testing.T) {
	svc, _, _ := newServiceForTest()
	devs, err := svc.ListDevices(context.Background(), "ghost")
	require.NoError(t, err)
	assert.Empty(t, devs)
}

func TestService_ListDevices_PropagatesStoreError(t *testing.T) {
	es := &errStore{Store: identity.NewStoreInMemory(), failListDevices: errors.New("db down")}
	svc := newServiceWithStore(es)

	_, err := svc.ListDevices(context.Background(), "acc-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestStoreInMemory_ListActiveDevicesByAccountID_StableOrder(t *testing.T) {
	// Cover the ordering branch (later-LinkedAt first → swap; equal LinkedAt
	// falls back to DeviceID lexicographic order).
	store := identity.NewStoreInMemory()
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	// Insert in reverse-chronological order so the sort actually has work to do.
	require.NoError(t, store.CreateAccountWithDevice(context.Background(), identity.CreateAccountArgs{
		Account:     proto.Account{AccountID: "acc-X", Username: "u-x"},
		Device:      proto.Device{DeviceID: "dev-late", AccountID: "acc-X", LinkedAt: now.Add(2 * time.Hour)},
		KPExpiresAt: now,
	}))
	store.AddDeviceForTest(proto.Device{DeviceID: "dev-early", AccountID: "acc-X", LinkedAt: now})
	store.AddDeviceForTest(proto.Device{DeviceID: "dev-tie-b", AccountID: "acc-X", LinkedAt: now.Add(time.Hour)})
	store.AddDeviceForTest(proto.Device{DeviceID: "dev-tie-a", AccountID: "acc-X", LinkedAt: now.Add(time.Hour)})

	devs, err := store.ListActiveDevicesByAccountID(context.Background(), "acc-X")
	require.NoError(t, err)
	require.Len(t, devs, 4)
	assert.Equal(t, "dev-early", devs[0].DeviceID)
	assert.Equal(t, "dev-tie-a", devs[1].DeviceID)
	assert.Equal(t, "dev-tie-b", devs[2].DeviceID)
	assert.Equal(t, "dev-late", devs[3].DeviceID)
}

// newServiceWithMutableClock is newServiceForTest with a clock the test can
// advance — needed to exercise the username-hold expiry window.
func newServiceWithMutableClock() (*identity.Service, *identity.StoreInMemory, *mutableClock) {
	store := identity.NewStoreInMemory()
	ids := &seqIDs{values: []string{"acc-1", "dev-1", "acc-2", "dev-2"}}
	clock := &mutableClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	_, jwtPriv, _ := ed25519.GenerateKey(rand.Reader)

	svc := identity.NewService(identity.ServiceDeps{
		Store:       store,
		Clock:       clock,
		IDGen:       ids,
		JWTSignKey:  jwtPriv,
		JWTLifetime: 24 * time.Hour,
	})
	return svc, store, clock
}

func TestService_LookupAccountByDevice_HappyPath(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)

	acc, err := svc.LookupAccountByDevice(context.Background(), "dev-1")
	require.NoError(t, err)
	assert.Equal(t, "nass", acc.Username)
	assert.Equal(t, "acc-1", acc.AccountID)
}

func TestService_LookupAccountByDevice_UnknownDevice(t *testing.T) {
	svc, _, _ := newServiceForTest()

	_, err := svc.LookupAccountByDevice(context.Background(), "dev-ghost")
	var apiErr proto.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

func TestService_LookupAccountByDevice_DeletedAccount(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)
	require.NoError(t, svc.DeleteAccount(context.Background(), "acc-1"))

	_, err = svc.LookupAccountByDevice(context.Background(), "dev-1")
	var apiErr proto.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

func TestService_LookupAccountByID_HappyPath(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)

	acc, err := svc.LookupAccountByID(context.Background(), "acc-1")
	require.NoError(t, err)
	assert.Equal(t, "nass", acc.Username)
	assert.Equal(t, "acc-1", acc.AccountID)
}

func TestService_LookupAccountByID_Unknown(t *testing.T) {
	svc, _, _ := newServiceForTest()

	_, err := svc.LookupAccountByID(context.Background(), "acc-ghost")
	var apiErr proto.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

func TestService_RevokeDevice_RemovesIt(t *testing.T) {
	svc, store, _ := newServiceForTest()
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)

	require.NoError(t, svc.RevokeDevice(context.Background(), "acc-1", "dev-1"))

	devs, err := store.ListActiveDevicesByAccountID(context.Background(), "acc-1")
	require.NoError(t, err)
	assert.Empty(t, devs, "revoked device should no longer be active")
}

func TestService_RevokeDevice_UnknownDeviceNotFound(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)

	err = svc.RevokeDevice(context.Background(), "acc-1", "dev-ghost")
	var apiErr proto.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

func TestService_DeleteAccount_WipesAndHoldsUsername(t *testing.T) {
	svc, store, _ := newServiceForTest()
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)

	require.NoError(t, svc.DeleteAccount(context.Background(), "acc-1"))

	// Account is gone from username lookup.
	_, err = svc.LookupAccount(context.Background(), "nass")
	var apiErr proto.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)

	// Devices revoked and key packages dropped.
	_, err = store.GetActiveDeviceByAccountID(context.Background(), "acc-1")
	assert.ErrorIs(t, err, identity.ErrNotFound)
	assert.Empty(t, store.KeyPackagesFor("acc-1"))

	// Immediate re-registration of the username is blocked by the hold.
	_, err = svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeUsernameOnHold, apiErr.Code)
}

func TestService_DeleteAccount_UsernameFreeAfterHoldExpires(t *testing.T) {
	svc, _, clock := newServiceWithMutableClock()
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)
	require.NoError(t, svc.DeleteAccount(context.Background(), "acc-1"))

	clock.t = clock.t.Add(identity.UsernameHoldDuration + time.Second)

	resp, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)
	assert.Equal(t, "acc-2", resp.AccountID)
}

func TestService_DeleteAccount_NotFound(t *testing.T) {
	svc, _, _ := newServiceForTest()

	err := svc.DeleteAccount(context.Background(), "acc-missing")
	var apiErr proto.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

func TestService_DeleteAccount_SecondDeleteFails(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)

	require.NoError(t, svc.DeleteAccount(context.Background(), "acc-1"))
	err = svc.DeleteAccount(context.Background(), "acc-1")
	var apiErr proto.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

type chanRevokedNotifier struct{ ch chan []string }

func (n chanRevokedNotifier) NotifyDevicesRevoked(ids []string) { n.ch <- ids }

func newServiceWithRevokedNotifier(n identity.DevicesRevokedNotifier) (*identity.Service, *identity.StoreInMemory) {
	store := identity.NewStoreInMemory()
	_, jwtPriv, _ := ed25519.GenerateKey(rand.Reader)
	svc := identity.NewService(identity.ServiceDeps{
		Store:          store,
		Clock:          fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)},
		IDGen:          &seqIDs{values: []string{"acc-1", "dev-1", "dev-2", "dev-3"}},
		JWTSignKey:     jwtPriv,
		JWTLifetime:    24 * time.Hour,
		DevicesRevoked: n,
	})
	return svc, store
}

func receiveRevoked(t *testing.T, n chanRevokedNotifier) []string {
	t.Helper()
	select {
	case ids := <-n.ch:
		return ids
	case <-time.After(2 * time.Second):
		t.Fatal("no revoked devices were reported")
		return nil
	}
}

func TestService_RevokeDevice_ReportsTheDeviceSoItsConnectionCloses(t *testing.T) {
	n := chanRevokedNotifier{ch: make(chan []string, 1)}
	svc, _ := newServiceWithRevokedNotifier(n)
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)

	require.NoError(t, svc.RevokeDevice(context.Background(), "acc-1", "dev-1"))

	assert.Equal(t, []string{"dev-1"}, receiveRevoked(t, n))
}

func TestService_RevokeDevice_UnknownDeviceReportsNothing(t *testing.T) {
	n := chanRevokedNotifier{ch: make(chan []string, 1)}
	svc, _ := newServiceWithRevokedNotifier(n)
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)

	require.Error(t, svc.RevokeDevice(context.Background(), "acc-1", "nope"))

	select {
	case ids := <-n.ch:
		t.Fatalf("a failed revoke reported %v", ids)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestService_CompleteRestoreSession_ReportsTheDevicesItRevoked(t *testing.T) {
	n := chanRevokedNotifier{ch: make(chan []string, 1)}
	svc, store := newServiceWithRevokedNotifier(n)
	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")
	chal, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)

	_, err = svc.CompleteRestoreSession(context.Background(), "nass", idPub, chal,
		ed25519.Sign(idPriv, chal), make([]byte, ed25519.PublicKeySize), make([]byte, 32))
	require.NoError(t, err)

	assert.Equal(t, []string{"dev-1"}, receiveRevoked(t, n))
}

func TestService_DeleteAccount_ReportsEveryDevice(t *testing.T) {
	n := chanRevokedNotifier{ch: make(chan []string, 1)}
	svc, _ := newServiceWithRevokedNotifier(n)
	_, err := svc.CreateAccount(context.Background(), makeRequest(t, "nass"))
	require.NoError(t, err)

	require.NoError(t, svc.DeleteAccount(context.Background(), "acc-1"))

	assert.Equal(t, []string{"dev-1"}, receiveRevoked(t, n))
}
