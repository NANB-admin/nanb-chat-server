package crypto_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/crypto"
)

func mustGenerateKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func TestJWT_SignVerifyRoundtrip(t *testing.T) {
	pub, priv := mustGenerateKeyPair(t)

	claims := crypto.JWTClaims{
		AccountID: "acc-1",
		DeviceID:  "dev-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	signed := crypto.SignJWT(priv, claims)

	verified, err := crypto.VerifyJWT(pub, signed, time.Now())
	require.NoError(t, err)
	assert.Equal(t, claims.AccountID, verified.AccountID)
	assert.Equal(t, claims.DeviceID, verified.DeviceID)
	assert.Equal(t, claims.ExpiresAt, verified.ExpiresAt)
}

func TestJWT_ExpiredFails(t *testing.T) {
	pub, priv := mustGenerateKeyPair(t)

	claims := crypto.JWTClaims{
		AccountID: "acc-1",
		DeviceID:  "dev-1",
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	}

	signed := crypto.SignJWT(priv, claims)

	_, err := crypto.VerifyJWT(pub, signed, time.Now())
	assert.ErrorIs(t, err, crypto.ErrJWTExpired)
}

func TestJWT_WrongKeyFails(t *testing.T) {
	_, signingPriv := mustGenerateKeyPair(t)
	otherPub, _ := mustGenerateKeyPair(t)

	claims := crypto.JWTClaims{
		AccountID: "acc-1",
		DeviceID:  "dev-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	signed := crypto.SignJWT(signingPriv, claims)

	_, err := crypto.VerifyJWT(otherPub, signed, time.Now())
	assert.ErrorIs(t, err, crypto.ErrJWTBadSignature)
}

func TestJWT_MalformedToken_TooFewParts(t *testing.T) {
	pub, _ := mustGenerateKeyPair(t)

	_, err := crypto.VerifyJWT(pub, "not.a.proper.jwt", time.Now())
	assert.ErrorIs(t, err, crypto.ErrJWTMalformed)
}

func TestJWT_MalformedToken_BadBase64(t *testing.T) {
	pub, _ := mustGenerateKeyPair(t)

	_, err := crypto.VerifyJWT(pub, "!!!!.!!!!.!!!!", time.Now())
	assert.ErrorIs(t, err, crypto.ErrJWTMalformed)
}

func TestJWT_MalformedToken_WrongAlg(t *testing.T) {
	pub, priv := mustGenerateKeyPair(t)
	claims := crypto.JWTClaims{
		AccountID: "x",
		DeviceID:  "y",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	signed := crypto.SignJWT(priv, claims)

	parts := strings.Split(signed, ".")
	require.Len(t, parts, 3)
	tampered := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + parts[1] + "." + parts[2]

	_, err := crypto.VerifyJWT(pub, tampered, time.Now())
	assert.ErrorIs(t, err, crypto.ErrJWTMalformed)
}

func TestJWT_MalformedToken_BadHeaderJSON(t *testing.T) {
	pub, _ := mustGenerateKeyPair(t)
	tampered := "bm90LWpzb24.eyJzdWIiOiJ4In0.AAAA"
	_, err := crypto.VerifyJWT(pub, tampered, time.Now())
	assert.ErrorIs(t, err, crypto.ErrJWTMalformed)
}

func TestJWT_MalformedToken_BadPayloadBase64(t *testing.T) {
	pub, _ := mustGenerateKeyPair(t)
	tampered := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.!!!!.AAAA"
	_, err := crypto.VerifyJWT(pub, tampered, time.Now())
	assert.ErrorIs(t, err, crypto.ErrJWTMalformed)
}

func TestJWT_MalformedToken_BadPayloadJSON(t *testing.T) {
	pub, _ := mustGenerateKeyPair(t)
	tampered := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.bm90LWpzb24.AAAA"
	_, err := crypto.VerifyJWT(pub, tampered, time.Now())
	assert.ErrorIs(t, err, crypto.ErrJWTMalformed)
}

func TestJWT_MalformedToken_BadSigBase64(t *testing.T) {
	_, priv := mustGenerateKeyPair(t)
	claims := crypto.JWTClaims{AccountID: "x", DeviceID: "y", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	signed := crypto.SignJWT(priv, claims)
	parts := strings.Split(signed, ".")
	require.Len(t, parts, 3)
	tampered := parts[0] + "." + parts[1] + ".!!!!"
	pub := priv.Public().(ed25519.PublicKey)
	_, err := crypto.VerifyJWT(pub, tampered, time.Now())
	assert.ErrorIs(t, err, crypto.ErrJWTMalformed)
}

func TestJWT_SignSetsIssuedAt(t *testing.T) {
	_, priv := mustGenerateKeyPair(t)
	claims := crypto.JWTClaims{
		AccountID: "x",
		DeviceID:  "y",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	signed := crypto.SignJWT(priv, claims)

	pub := priv.Public().(ed25519.PublicKey)
	verified, err := crypto.VerifyJWT(pub, signed, time.Now())
	require.NoError(t, err)
	assert.NotZero(t, verified.IssuedAt)
}

func TestJWT_NoExpiry_AlwaysValid(t *testing.T) {
	pub, priv := mustGenerateKeyPair(t)
	claims := crypto.JWTClaims{
		AccountID: "x",
		DeviceID:  "y",
		// ExpiresAt zero = no expiry
	}
	signed := crypto.SignJWT(priv, claims)

	_, err := crypto.VerifyJWT(pub, signed, time.Now().Add(100*time.Hour))
	assert.NoError(t, err)
}
