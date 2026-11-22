package identity_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/identity"
)

func TestVerifyUsernameClaim_AcceptsValidSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	claim := identity.UsernameClaimPayload("nass", pub)
	sig := ed25519.Sign(priv, claim)

	err = identity.VerifyUsernameClaim("nass", pub, sig)
	assert.NoError(t, err)
}

func TestVerifyUsernameClaim_RejectsBadSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// signature wrong length
	err = identity.VerifyUsernameClaim("nass", pub, []byte("not-a-signature"))
	assert.ErrorIs(t, err, identity.ErrBadClaimSignature)
}

func TestVerifyUsernameClaim_RejectsValidLengthBadBytesSig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	badSig := make([]byte, ed25519.SignatureSize) // correct length, all zeros — won't verify
	err = identity.VerifyUsernameClaim("nass", pub, badSig)
	assert.ErrorIs(t, err, identity.ErrBadClaimSignature)
}

func TestVerifyUsernameClaim_RejectsWrongUsername(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	claim := identity.UsernameClaimPayload("nass", pub)
	sig := ed25519.Sign(priv, claim)

	err = identity.VerifyUsernameClaim("someone-else", pub, sig)
	assert.ErrorIs(t, err, identity.ErrBadClaimSignature)
}

func TestVerifyUsernameClaim_RejectsWrongPubKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	claim := identity.UsernameClaimPayload("nass", pub)
	sig := ed25519.Sign(priv, claim)

	err = identity.VerifyUsernameClaim("nass", otherPub, sig)
	assert.ErrorIs(t, err, identity.ErrBadClaimSignature)
}

func TestVerifyUsernameClaim_RejectsWrongPubKeyLength(t *testing.T) {
	err := identity.VerifyUsernameClaim("nass", []byte{1, 2, 3}, make([]byte, ed25519.SignatureSize))
	assert.ErrorIs(t, err, identity.ErrBadClaimSignature)
}
