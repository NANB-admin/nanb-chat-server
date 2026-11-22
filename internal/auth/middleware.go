package auth

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"time"

	"github.com/nanb/nanb-server/internal/crypto"
)

type contextKey int

const claimsKey contextKey = 0

// DeviceActiveFunc reports whether a device is still an active (not-revoked)
// device on a non-deleted account. It is called on every authenticated REST
// request, so callers MUST pass a CACHED lookup (a per-request DB hit would be
// too costly) — see delivery.NewCachedResolver.
//
// Contract: return true when UNCERTAIN (e.g. a transient backend error). The
// JWT signature + expiry remain the primary gate; the active-device check is
// defense-in-depth that kicks a revoked device before its (up to 24h) token
// expires. Failing that check open on a storage blip avoids locking the entire
// API out, matching the "kick on next reconnect" posture of the WS handshake.
type DeviceActiveFunc func(ctx context.Context, deviceID string) bool

// RequireJWT returns a middleware that enforces a valid Bearer JWT signed by
// pubKey (which must be the public half of the Identity service's signing key).
// On success, parsed claims are placed in the request context. Device-revocation
// is NOT enforced — use RequireJWTWithDevice for that.
func RequireJWT(pubKey ed25519.PublicKey) func(http.Handler) http.Handler {
	return RequireJWTWithDevice(pubKey, nil)
}

// RequireJWTWithDevice is RequireJWT plus an active-device check: after the JWT
// verifies, deviceActive is consulted and a revoked/deleted device is rejected
// with 401. This closes the gap where a revoked device (e.g. a recovery-phrase
// takeover on another phone) kept REST access until its JWT expired — the WS
// handshake already enforced this, but REST did not. A nil deviceActive skips
// the check (identical to RequireJWT).
func RequireJWTWithDevice(pubKey ed25519.PublicKey, deviceActive DeviceActiveFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authz := r.Header.Get("Authorization")
			if authz == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			const prefix = "Bearer "
			if !strings.HasPrefix(authz, prefix) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(authz, prefix)
			claims, err := crypto.VerifyJWT(pubKey, token, time.Now())
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if deviceActive != nil && !deviceActive(r.Context(), claims.DeviceID) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext returns the JWT claims previously attached by RequireJWT.
func ClaimsFromContext(ctx context.Context) (crypto.JWTClaims, bool) {
	c, ok := ctx.Value(claimsKey).(crypto.JWTClaims)
	return c, ok
}

// InjectClaimsForTest places claims directly into a context. Intended for unit
// tests of downstream handlers that bypass the real middleware.
func InjectClaimsForTest(ctx context.Context, claims crypto.JWTClaims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}
