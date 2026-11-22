package identity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/identity"
	"github.com/nanb/nanb-server/internal/proto"
)

// kindFixture is an account with one primary device, a mutable clock shared by
// the service and the in-memory store, and a helper to link further devices.
type kindFixture struct {
	t       *testing.T
	svc     *identity.Service
	store   *identity.StoreInMemory
	clock   *mutableClock
	idPriv  ed25519.PrivateKey
	primary string
	account string
}

func newKindFixture(t *testing.T, webLifetime time.Duration) *kindFixture {
	t.Helper()
	store := identity.NewStoreInMemory()
	clock := &mutableClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	store.Now = clock.Now
	ids := &seqIDs{values: []string{"acc-1", "dev-1", "dev-2", "dev-3", "dev-4"}}
	_, jwtPriv, _ := ed25519.GenerateKey(rand.Reader)
	svc := identity.NewService(identity.ServiceDeps{
		Store:             store,
		Clock:             clock,
		IDGen:             ids,
		JWTSignKey:        jwtPriv,
		JWTLifetime:       24 * time.Hour,
		WebDeviceLifetime: webLifetime,
	})
	req, idPriv := makeAccountWithIdentity(t, "nass")
	created, err := svc.CreateAccount(context.Background(), req)
	require.NoError(t, err)
	return &kindFixture{t: t, svc: svc, store: store, clock: clock, idPriv: idPriv,
		primary: created.DeviceID, account: created.AccountID}
}

func (f *kindFixture) link(authDevice, kind string) (proto.LinkDeviceResponse, ed25519.PublicKey, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(f.t, err)
	resp, err := f.svc.LinkDevice(context.Background(), authDevice, proto.LinkDeviceRequest{
		DevicePubKey: pub,
		X25519PubKey: make([]byte, 32),
		SignedLink:   ed25519.Sign(f.idPriv, pub),
		KeyPackages:  [][]byte{[]byte("kp")},
		Kind:         kind,
	})
	return resp, pub, err
}

func (f *kindFixture) device(id string) proto.Device {
	d, err := f.store.GetActiveDeviceByID(context.Background(), id)
	require.NoError(f.t, err)
	return d
}

func TestLinkDevice_DefaultKindIsPhone(t *testing.T) {
	f := newKindFixture(t, 0)
	resp, _, err := f.link(f.primary, "")
	require.NoError(t, err)
	assert.Equal(t, proto.DeviceKindPhone, f.device(resp.DeviceID).Kind)
}

func TestLinkDevice_PhoneHasNoExpiry(t *testing.T) {
	f := newKindFixture(t, 0)
	resp, _, err := f.link(f.primary, "phone")
	require.NoError(t, err)
	assert.Nil(t, f.device(resp.DeviceID).ExpiresAt)
}

func TestLinkDevice_RecordsAuthorizingDevice(t *testing.T) {
	f := newKindFixture(t, 0)
	resp, _, err := f.link(f.primary, "phone")
	require.NoError(t, err)
	assert.Equal(t, f.primary, f.device(resp.DeviceID).LinkedByDeviceID)
}

func TestLinkDevice_LinkedByIsTheCallerNotTheFirstDevice(t *testing.T) {
	f := newKindFixture(t, 0)
	second, _, err := f.link(f.primary, "phone")
	require.NoError(t, err)
	third, _, err := f.link(second.DeviceID, "phone")
	require.NoError(t, err)
	assert.Equal(t, second.DeviceID, f.device(third.DeviceID).LinkedByDeviceID)
}

func TestLinkDevice_WebKindIsStored(t *testing.T) {
	f := newKindFixture(t, 0)
	resp, _, err := f.link(f.primary, "web")
	require.NoError(t, err)
	assert.Equal(t, proto.DeviceKindWeb, f.device(resp.DeviceID).Kind)
}

func TestLinkDevice_WebExpiresAfterConfiguredLifetime(t *testing.T) {
	f := newKindFixture(t, 7*24*time.Hour)
	resp, _, err := f.link(f.primary, "web")
	require.NoError(t, err)
	exp := f.device(resp.DeviceID).ExpiresAt
	require.NotNil(t, exp)
	assert.True(t, exp.Equal(f.clock.Now().Add(7*24*time.Hour)))
}

func TestLinkDevice_WebLifetimeDefaultsTo30Days(t *testing.T) {
	f := newKindFixture(t, 0)
	resp, _, err := f.link(f.primary, "web")
	require.NoError(t, err)
	exp := f.device(resp.DeviceID).ExpiresAt
	require.NotNil(t, exp)
	assert.True(t, exp.Equal(f.clock.Now().Add(30*24*time.Hour)))
}

func TestLinkDevice_RejectsUnknownKind(t *testing.T) {
	f := newKindFixture(t, 0)
	_, _, err := f.link(f.primary, "tablet")
	var apiErr proto.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestLinkDevice_RelinkDoesNotExtendExpiry(t *testing.T) {
	f := newKindFixture(t, 0)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	req := proto.LinkDeviceRequest{
		DevicePubKey: pub, X25519PubKey: make([]byte, 32),
		SignedLink: ed25519.Sign(f.idPriv, pub), KeyPackages: [][]byte{[]byte("kp")}, Kind: "web",
	}
	first, err := f.svc.LinkDevice(context.Background(), f.primary, req)
	require.NoError(t, err)
	before := *f.device(first.DeviceID).ExpiresAt

	f.clock.t = f.clock.t.Add(5 * 24 * time.Hour)
	again, err := f.svc.LinkDevice(context.Background(), f.primary, req)
	require.NoError(t, err)

	assert.Equal(t, first.DeviceID, again.DeviceID)
	assert.True(t, f.device(first.DeviceID).ExpiresAt.Equal(before))
}

func TestLinkDevice_RelinkDoesNotChangeLinkedBy(t *testing.T) {
	f := newKindFixture(t, 0)
	second, _, err := f.link(f.primary, "phone")
	require.NoError(t, err)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	req := proto.LinkDeviceRequest{
		DevicePubKey: pub, X25519PubKey: make([]byte, 32),
		SignedLink: ed25519.Sign(f.idPriv, pub), KeyPackages: [][]byte{[]byte("kp")},
	}
	first, err := f.svc.LinkDevice(context.Background(), f.primary, req)
	require.NoError(t, err)
	_, err = f.svc.LinkDevice(context.Background(), second.DeviceID, req)
	require.NoError(t, err)
	assert.Equal(t, f.primary, f.device(first.DeviceID).LinkedByDeviceID)
}

func TestExpiredDevice_ExcludedFromListing(t *testing.T) {
	f := newKindFixture(t, time.Hour)
	web, _, err := f.link(f.primary, "web")
	require.NoError(t, err)
	f.clock.t = f.clock.t.Add(time.Hour)

	devs, err := f.svc.ListDevices(context.Background(), f.account)
	require.NoError(t, err)
	for _, d := range devs {
		assert.NotEqual(t, web.DeviceID, d.DeviceID)
	}
}

func TestUnexpiredWebDevice_StillListed(t *testing.T) {
	f := newKindFixture(t, time.Hour)
	web, _, err := f.link(f.primary, "web")
	require.NoError(t, err)
	f.clock.t = f.clock.t.Add(59 * time.Minute)

	devs, err := f.svc.ListDevices(context.Background(), f.account)
	require.NoError(t, err)
	var ids []string
	for _, d := range devs {
		ids = append(ids, d.DeviceID)
	}
	assert.Contains(t, ids, web.DeviceID)
}

func TestExpiredDevice_SessionChallengeRefused(t *testing.T) {
	f := newKindFixture(t, time.Hour)
	web, _, err := f.link(f.primary, "web")
	require.NoError(t, err)
	f.clock.t = f.clock.t.Add(2 * time.Hour)

	_, _, err = f.svc.IssueChallenge(context.Background(), "nass", web.DeviceID)
	var apiErr proto.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeDeviceNotFound, apiErr.Code)
}

func TestExpiredDevice_CompleteSessionRefused(t *testing.T) {
	f := newKindFixture(t, time.Hour)
	web, _, err := f.link(f.primary, "web")
	require.NoError(t, err)
	f.clock.t = f.clock.t.Add(2 * time.Hour)

	_, err = f.svc.CompleteSession(context.Background(), "nass", web.DeviceID, []byte("c"), []byte("s"))
	var apiErr proto.APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, proto.ErrCodeDeviceNotFound, apiErr.Code)
}

func TestExpiredDevice_NoLongerResolvesToAccount(t *testing.T) {
	f := newKindFixture(t, time.Hour)
	web, _, err := f.link(f.primary, "web")
	require.NoError(t, err)
	f.clock.t = f.clock.t.Add(2 * time.Hour)

	_, err = f.store.GetAccountByDeviceID(context.Background(), web.DeviceID)
	assert.ErrorIs(t, err, identity.ErrNotFound)
}

func TestExpiredDevice_DoesNotCountTowardDeviceCap(t *testing.T) {
	f := newKindFixture(t, time.Hour)
	_, _, err := f.link(f.primary, "web")
	require.NoError(t, err)
	f.clock.t = f.clock.t.Add(2 * time.Hour)

	devs, err := f.store.ListActiveDevicesByAccountID(context.Background(), f.account)
	require.NoError(t, err)
	assert.Len(t, devs, 1)
}
