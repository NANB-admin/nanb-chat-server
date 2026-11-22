package identity_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/identity"
	"github.com/nanb/nanb-server/internal/proto"
)

// fillDevicesToCap links extra devices straight into the store until the
// account holds MaxDevicesPerAccount active ones.
func fillDevicesToCap(t *testing.T, store *identity.StoreInMemory, accountID string) {
	t.Helper()
	ctx := context.Background()
	active, err := store.ListActiveDevicesByAccountID(ctx, accountID)
	require.NoError(t, err)
	for i := len(active); i < identity.MaxDevicesPerAccount; i++ {
		require.NoError(t, store.LinkDevice(ctx, identity.LinkDeviceArgs{Device: proto.Device{
			DeviceID:     fmt.Sprintf("filler-%d", i),
			AccountID:    accountID,
			DevicePubKey: []byte{byte(i), 9, 9},
			LinkedAt:     time.Now(),
		}}))
	}
}

func restoreAtCap(t *testing.T, opts ...identity.RestoreOption) (error, *identity.StoreInMemory) {
	t.Helper()
	svc, store, _ := newServiceForTest()
	idPub, idPriv := makeRestoreFixture(t, svc, store, "nass")
	fillDevicesToCap(t, store, "acc-1")
	chal, _, err := svc.IssueRestoreChallenge(context.Background(), "nass")
	require.NoError(t, err)
	_, err = svc.CompleteRestoreSession(
		context.Background(), "nass", idPub, chal, ed25519.Sign(idPriv, chal),
		make([]byte, ed25519.PublicKeySize), make([]byte, 32), opts...)
	return err, store
}

func TestService_CompleteRestoreSession_KeepOtherDevicesAtCapReturnsDeviceLimit(t *testing.T) {
	err, _ := restoreAtCap(t, identity.KeepOtherDevices())

	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeDeviceLimit, apiErr.Code)
}

func TestService_CompleteRestoreSession_KeepOtherDevicesAtCapAddsNoDevice(t *testing.T) {
	_, store := restoreAtCap(t, identity.KeepOtherDevices())

	devs, err := store.ListActiveDevicesByAccountID(context.Background(), "acc-1")
	require.NoError(t, err)
	assert.Len(t, devs, identity.MaxDevicesPerAccount)
}

func TestService_CompleteRestoreSession_TakeoverAtCapStillSucceeds(t *testing.T) {
	err, _ := restoreAtCap(t)

	assert.NoError(t, err, "takeover revokes the others, so the cap is not exceeded")
}
