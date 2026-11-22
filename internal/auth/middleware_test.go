package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
)

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func okHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := auth.ClaimsFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, "acc-1", claims.AccountID)
		assert.Equal(t, "dev-1", claims.DeviceID)
		w.WriteHeader(http.StatusOK)
	}
}

func TestRequireJWT_ValidToken_PassesThrough(t *testing.T) {
	pub, priv := mustKeypair(t)
	mw := auth.RequireJWT(pub)

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1",
		DeviceID:  "dev-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw(okHandler(t)).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireJWT_NoHeader_Returns401(t *testing.T) {
	pub, _ := mustKeypair(t)
	mw := auth.RequireJWT(pub)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireJWT_WrongScheme_Returns401(t *testing.T) {
	pub, _ := mustKeypair(t)
	mw := auth.RequireJWT(pub)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireJWT_BadToken_Returns401(t *testing.T) {
	pub, _ := mustKeypair(t)
	mw := auth.RequireJWT(pub)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not.a.token")
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireJWT_ExpiredToken_Returns401(t *testing.T) {
	pub, priv := mustKeypair(t)
	mw := auth.RequireJWT(pub)

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1",
		DeviceID:  "dev-1",
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireJWTWithDevice_RevokedDevice_Returns401(t *testing.T) {
	pub, priv := mustKeypair(t)
	// deviceActive reports the token's device as revoked (not active).
	mw := auth.RequireJWTWithDevice(pub, func(_ context.Context, deviceID string) bool {
		return deviceID != "dev-revoked"
	})

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1",
		DeviceID:  "dev-revoked",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), // JWT itself still valid
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run for a revoked device")
	})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireJWTWithDevice_ActiveDevice_PassesThrough(t *testing.T) {
	pub, priv := mustKeypair(t)
	mw := auth.RequireJWTWithDevice(pub, func(context.Context, string) bool { return true })

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1",
		DeviceID:  "dev-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw(okHandler(t)).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestClaimsFromContext_Empty_ReturnsFalse(t *testing.T) {
	_, ok := auth.ClaimsFromContext(context.Background())
	assert.False(t, ok)
}

func TestInjectClaimsForTest_RoundTrips(t *testing.T) {
	claims := crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1", ExpiresAt: 123}
	ctx := auth.InjectClaimsForTest(context.Background(), claims)

	got, ok := auth.ClaimsFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, claims, got)
}
