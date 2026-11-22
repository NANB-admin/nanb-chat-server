package httputil

import (
	"encoding/json"
	"net/http"

	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/proto"
)

// RateLimit returns a middleware that admits a request only when the shared
// token bucket lim has a token, short-circuiting with 429 BEFORE the wrapped
// handler runs any decode or DB work. It is a COARSE, process-global backstop —
// ONE bucket for every caller, so a single abusive client can drain it for
// everyone. For pre-auth endpoints prefer ClientRateLimiter, which gives each
// client key (client IP / the onion key) its own bucket. Pass a single
// *rate.Limiter to share one budget across several routes. The 429 body matches the APIError shape the rest of the API returns,
// reusing ErrCodeForbidden the same way the sealed-send and key-package
// limiters signal "rate limited".
func RateLimit(lim *rate.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !lim.Allow() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(proto.APIError{Code: proto.ErrCodeForbidden, Message: "rate limited"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
