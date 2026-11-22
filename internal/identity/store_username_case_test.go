package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/identity"
	"github.com/nanb/nanb-server/internal/proto"
)

func seedAccount(t *testing.T, store *identity.StoreInMemory, username string) {
	t.Helper()
	err := store.CreateAccountWithDevice(context.Background(), identity.CreateAccountArgs{
		Account: proto.Account{AccountID: "acc-" + username, Username: username},
		Device:  proto.Device{DeviceID: "dev-" + username, AccountID: "acc-" + username},
	})
	require.NoError(t, err)
}

func TestStore_GetAccountByUsername_IgnoresCase(t *testing.T) {
	store := identity.NewStoreInMemory()
	seedAccount(t, store, "NassJ")

	acc, err := store.GetAccountByUsername(context.Background(), "nassj")

	require.NoError(t, err)
	assert.Equal(t, "NassJ", acc.Username)
}

func TestStore_CreateAccount_RejectsCaseVariantOfTakenUsername(t *testing.T) {
	store := identity.NewStoreInMemory()
	seedAccount(t, store, "nassj")

	err := store.CreateAccountWithDevice(context.Background(), identity.CreateAccountArgs{
		Account: proto.Account{AccountID: "acc-2", Username: "NASSJ"},
		Device:  proto.Device{DeviceID: "dev-2", AccountID: "acc-2"},
	})

	assert.ErrorIs(t, err, identity.ErrAlreadyExists)
}

func TestStore_HasUsernameHold_IgnoresCase(t *testing.T) {
	store := identity.NewStoreInMemory()
	store.AddUsernameHold("NassJ", time.Now().Add(time.Hour))

	held, err := store.HasUsernameHold(context.Background(), "nassj", time.Now())

	require.NoError(t, err)
	assert.True(t, held)
}
