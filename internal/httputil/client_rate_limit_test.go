package httputil_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/httputil"
	"github.com/nanb/nanb-server/internal/proto"
)

func frozenNow() time.Time { return time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC) }

// newClientLimiter: per-client burst 2, onion burst 3, ceiling burst 100, and
// no refill within a test.
func newClientLimiter() http.Handler {
	l := httputil.NewClientRateLimiter(httputil.ClientRateLimitConfig{
		PerClientRate:  rate.Every(time.Hour),
		PerClientBurst: 2,
		OnionRate:      rate.Every(time.Hour),
		OnionBurst:     3,
		CeilingRate:    rate.Every(time.Hour),
		CeilingBurst:   100,
		MaxClients:     100,
	}, frozenNow)
	return l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func hit(h http.Handler, peer string, onion bool) int {
	r := httptest.NewRequest(http.MethodPost, "/sessions/challenge", nil)
	r.RemoteAddr = peer
	var handler = h
	if onion {
		handler = httputil.MarkOnion(h)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	return rec.Code
}

func TestClientRateLimit_ThrottlesAClientPastItsOwnBudget(t *testing.T) {
	h := newClientLimiter()
	hit(h, "203.0.113.1:1", false)
	hit(h, "203.0.113.1:1", false)

	assert.Equal(t, http.StatusTooManyRequests, hit(h, "203.0.113.1:1", false))
}

func TestClientRateLimit_OneClientCannotStarveAnother(t *testing.T) {
	h := newClientLimiter()
	for i := 0; i < 10; i++ {
		hit(h, "203.0.113.1:1", false)
	}

	assert.Equal(t, http.StatusOK, hit(h, "198.51.100.2:1", false))
}

func TestClientRateLimit_ClearnetAbuseCannotStarveOnion(t *testing.T) {
	h := newClientLimiter()
	for i := 0; i < 10; i++ {
		hit(h, "203.0.113.1:1", false)
	}

	assert.Equal(t, http.StatusOK, hit(h, "172.18.0.9:1", true))
}

func TestClientRateLimit_OnionTrafficSharesOneBucket(t *testing.T) {
	h := newClientLimiter()
	hit(h, "172.18.0.9:1", true)
	hit(h, "172.18.0.9:2", true)
	hit(h, "172.18.0.9:3", true)

	assert.Equal(t, http.StatusTooManyRequests, hit(h, "172.18.0.9:4", true))
}

func TestClientRateLimit_CeilingCapsAllClearnetClientsTogether(t *testing.T) {
	l := httputil.NewClientRateLimiter(httputil.ClientRateLimitConfig{
		PerClientRate:  rate.Every(time.Hour),
		PerClientBurst: 5,
		OnionRate:      rate.Every(time.Hour),
		OnionBurst:     5,
		CeilingRate:    rate.Every(time.Hour),
		CeilingBurst:   2,
		MaxClients:     100,
	}, frozenNow)
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	hit(h, "203.0.113.1:1", false)
	hit(h, "203.0.113.2:1", false)

	assert.Equal(t, http.StatusTooManyRequests, hit(h, "203.0.113.3:1", false))
}

func TestClientRateLimit_429BodyIsAPIError(t *testing.T) {
	h := newClientLimiter()
	hit(h, "203.0.113.1:1", false)
	hit(h, "203.0.113.1:1", false)
	r := httptest.NewRequest(http.MethodPost, "/sessions/challenge", nil)
	r.RemoteAddr = "203.0.113.1:1"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r)

	var apiErr proto.APIError
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&apiErr))
	assert.Equal(t, proto.ErrCodeForbidden, apiErr.Code)
}
