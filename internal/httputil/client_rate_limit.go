package httputil

import (
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/proto"
	"github.com/nanb/nanb-server/internal/ratelimit"
)

// ClientRateLimiter admits a request against the CALLER'S OWN budget (keyed by
// ClientKey), so one abusive client exhausts only its own bucket instead of a
// single bucket the whole fleet shares. Onion traffic draws from a dedicated
// bucket; clearnet traffic additionally passes a large global ceiling. Over
// budget → 429 with the same APIError body as RateLimit, before the wrapped
// handler does any decode or DB work.
type ClientRateLimiter struct {
	perClient *ratelimit.Keyed
	onion     *rate.Limiter
	ceiling   *rate.Limiter
	now       func() time.Time
}

// NewClientRateLimiter builds a limiter for cfg. now is injectable for tests;
// nil means time.Now. Build ONE per group of routes that should share a budget.
func NewClientRateLimiter(cfg ClientRateLimitConfig, now func() time.Time) *ClientRateLimiter {
	if now == nil {
		now = time.Now
	}
	return &ClientRateLimiter{
		perClient: ratelimit.NewKeyed(ratelimit.KeyedConfig{
			Rate:    cfg.PerClientRate,
			Burst:   cfg.PerClientBurst,
			MaxKeys: cfg.MaxClients,
		}, now),
		onion:   rate.NewLimiter(cfg.OnionRate, cfg.OnionBurst),
		ceiling: rate.NewLimiter(cfg.CeilingRate, cfg.CeilingBurst),
		now:     now,
	}
}

// Middleware enforces the limiter on the wrapped handler.
func (l *ClientRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(proto.APIError{Code: proto.ErrCodeForbidden, Message: "rate limited"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *ClientRateLimiter) allow(r *http.Request) bool {
	now := l.now()
	key := ClientKey(r)
	if key == OnionClientKey {
		return l.onion.AllowN(now, 1)
	}
	// Per-client first: a client already over its own budget is refused
	// without touching the shared ceiling, so it can't drain that for others.
	if !l.perClient.Allow(key) {
		return false
	}
	return l.ceiling.AllowN(now, 1)
}
