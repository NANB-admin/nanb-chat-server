package httputil_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/httputil"
	"github.com/nanb/nanb-server/internal/proto"
)

// Once the shared bucket drains, further requests to a rate-limited unauth
// endpoint (e.g. POST /accounts) must be rejected with 429 and never reach the
// wrapped handler. A tiny burst with an effectively-frozen refill isolates the
// "limit exceeded" transition within the test.
func TestRateLimit_RejectsOnceBucketDrained(t *testing.T) {
	const burst = 3
	lim := rate.NewLimiter(rate.Every(time.Hour), burst) // no meaningful refill mid-test

	var served int
	h := httputil.RateLimit(lim)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	}))

	var ok, limited int
	for i := 0; i < burst+2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/accounts", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("unexpected status %d", rec.Code)
		}
	}

	if ok != burst {
		t.Fatalf("expected exactly %d admitted (the burst), got %d", burst, ok)
	}
	if limited != 2 {
		t.Fatalf("expected the 2 over-budget requests to be throttled, got %d", limited)
	}
	if served != burst {
		t.Fatalf("throttled requests must not reach the handler: served=%d want=%d", served, burst)
	}
}

// A throttled response carries the same APIError shape (forbidden code) the rest
// of the API uses for rate limiting, so clients parse it uniformly.
func TestRateLimit_429BodyIsAPIError(t *testing.T) {
	lim := rate.NewLimiter(rate.Every(time.Hour), 1)
	h := httputil.RateLimit(lim)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Drain the single token, then trip the limit.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/accounts", nil))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/accounts", nil))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	var apiErr proto.APIError
	if err := json.NewDecoder(rec.Body).Decode(&apiErr); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if apiErr.Code != proto.ErrCodeForbidden {
		t.Fatalf("429 code = %q, want %q", apiErr.Code, proto.ErrCodeForbidden)
	}
}
