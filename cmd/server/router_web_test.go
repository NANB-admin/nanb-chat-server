package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const routerWebOrigin = "https://chat.example.org"

// newTestRouter builds the real router with nil handlers: these tests only
// exercise routing and middleware, which run before any handler body.
func newTestRouter(t *testing.T, webOrigins []string) http.Handler {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return buildRouter(pub, nil, nil, nil, nil, nil, nil, nil, nil, nil, webOrigins, nil)
}

func preflight(h http.Handler, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodOptions, "/devices/pending/abc", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRouter_WithWebOrigin_AnswersPreflightFromThatOrigin(t *testing.T) {
	rec := preflight(newTestRouter(t, []string{routerWebOrigin}), routerWebOrigin)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, routerWebOrigin, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestRouter_WithWebOrigin_DoesNotApproveOtherOrigins(t *testing.T) {
	rec := preflight(newTestRouter(t, []string{routerWebOrigin}), "https://evil.example")

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestRouter_WithoutWebOrigins_NeverSendsCORSHeaders(t *testing.T) {
	rec := preflight(newTestRouter(t, nil), routerWebOrigin)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestRouter_WSTicketRoute_RequiresASession(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/ws/ticket", nil)
	rec := httptest.NewRecorder()

	newTestRouter(t, []string{routerWebOrigin}).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
