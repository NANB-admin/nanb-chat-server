package identity_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/identity"
	"github.com/nanb/nanb-server/internal/proto"
)

func seedAccessKeyAccount(t *testing.T, store *identity.StoreInMemory) {
	t.Helper()
	require.NoError(t, store.CreateAccountWithDevice(context.Background(), identity.CreateAccountArgs{
		Account: proto.Account{AccountID: "acct-r", Username: "rosa"},
		Device:  proto.Device{DeviceID: "dev-r", AccountID: "acct-r"},
	}))
}

func TestVerifyAccessKey_MatchAndMismatch(t *testing.T) {
	store := identity.NewStoreInMemory()
	seedAccessKeyAccount(t, store)
	svc := identity.NewService(identity.ServiceDeps{Store: store})
	ctx := context.Background()

	uak := []byte("a-high-entropy-unidentified-access-key-32b!!")
	sum := sha256.Sum256(uak)
	require.NoError(t, svc.SetAccessKeyCommitment(ctx, "acct-r", sum[:]))

	// Correct UAK presented for the recipient's device → authorized; returns the
	// server-authoritative account id derived from the device.
	acct, ok, err := svc.VerifyAccessKey(ctx, "dev-r", uak)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "acct-r", acct)

	// Wrong UAK → not authorized, but NOT an error.
	_, ok, err = svc.VerifyAccessKey(ctx, "dev-r", []byte("not-the-key"))
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyAccessKey_NoCommitment_NotAuthorized(t *testing.T) {
	store := identity.NewStoreInMemory()
	seedAccessKeyAccount(t, store) // account exists but never set a commitment
	svc := identity.NewService(identity.ServiceDeps{Store: store})

	_, ok, err := svc.VerifyAccessKey(context.Background(), "dev-r", []byte("anything"))
	require.NoError(t, err, "no commitment is unauthorized, not a server error")
	assert.False(t, ok)
}

func TestVerifyAccessKey_UnknownDevice_NotAuthorized(t *testing.T) {
	store := identity.NewStoreInMemory()
	svc := identity.NewService(identity.ServiceDeps{Store: store})

	_, ok, err := svc.VerifyAccessKey(context.Background(), "ghost-device", []byte("x"))
	require.NoError(t, err, "unknown recipient is unauthorized, not a server error")
	assert.False(t, ok)
}

func TestSetAccessKeyCommitment_RejectsWrongLength(t *testing.T) {
	store := identity.NewStoreInMemory()
	seedAccessKeyAccount(t, store)
	svc := identity.NewService(identity.ServiceDeps{Store: store})

	err := svc.SetAccessKeyCommitment(context.Background(), "acct-r", []byte("too-short"))
	require.Error(t, err)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestSetAccessKeyCommitment_UnknownAccount(t *testing.T) {
	store := identity.NewStoreInMemory()
	svc := identity.NewService(identity.ServiceDeps{Store: store})

	sum := sha256.Sum256([]byte("k"))
	err := svc.SetAccessKeyCommitment(context.Background(), "nope", sum[:])
	require.Error(t, err)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}
