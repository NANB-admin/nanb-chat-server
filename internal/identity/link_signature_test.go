package identity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/identity"
	"github.com/nanb/nanb-server/internal/proto"
)

// linkWithSignature creates an account, then asks its first device to link a new
// device whose SignedLink is produced by sign(identityKey, devicePub, otherPub).
func linkWithSignature(t *testing.T, sign func(idPriv ed25519.PrivateKey, devPub, otherPub []byte) []byte) error {
	t.Helper()
	svc, _ := newServiceWithNotifier(nil)
	acctReq, idPriv := makeAccountWithIdentity(t, "nass")
	created, err := svc.CreateAccount(context.Background(), acctReq)
	require.NoError(t, err)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	_, err = svc.LinkDevice(context.Background(), created.DeviceID, proto.LinkDeviceRequest{
		DevicePubKey: devPub,
		X25519PubKey: make([]byte, 32),
		SignedLink:   sign(idPriv, devPub, otherPub),
		KeyPackages:  [][]byte{[]byte("kp")},
	})
	return err
}

func TestService_LinkDevice_AcceptsDomainSeparatedSignature(t *testing.T) {
	err := linkWithSignature(t, func(k ed25519.PrivateKey, dev, _ []byte) []byte {
		return ed25519.Sign(k, identity.LinkSignaturePayload(dev))
	})

	assert.NoError(t, err)
}

func TestService_LinkDevice_StillAcceptsLegacyRawKeySignature(t *testing.T) {
	err := linkWithSignature(t, func(k ed25519.PrivateKey, dev, _ []byte) []byte {
		return ed25519.Sign(k, dev)
	})

	assert.NoError(t, err)
}

func TestService_LinkDevice_RejectsSignatureOverADifferentDeviceKey(t *testing.T) {
	err := linkWithSignature(t, func(k ed25519.PrivateKey, _, other []byte) []byte {
		return ed25519.Sign(k, identity.LinkSignaturePayload(other))
	})

	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadSignature, apiErr.Code)
}
