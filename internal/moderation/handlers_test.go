package moderation

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
)

// postReport drives PostReport once with the reporter's claims injected the same
// way the JWT middleware would, and returns the HTTP status.
func postReport(t *testing.T, h *Handlers, accountID string) int {
	t.Helper()
	body, err := json.Marshal(validRequest())
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/reports", bytes.NewReader(body))
	req = req.WithContext(auth.InjectClaimsForTest(req.Context(),
		crypto.JWTClaims{AccountID: accountID, DeviceID: "device-1"}))
	rec := httptest.NewRecorder()
	h.PostReport(rec, req)
	return rec.Code
}

// A single account that floods /reports must eventually get 429 once its
// per-account bucket drains — bounding both the moderation DB and alert inbox.
func TestPostReportPerAccountRateLimit(t *testing.T) {
	store := &fakeStore{}
	h := NewHandlers(newServiceUnderTest(store, &fakeNotifier{}))

	var created, limited int
	for i := 0; i < reportBurst+5; i++ {
		switch postReport(t, h, reporterID) {
		case http.StatusCreated:
			created++
		case http.StatusTooManyRequests:
			limited++
		}
	}

	if created == 0 {
		t.Fatalf("the burst should let some reports through")
	}
	if limited == 0 {
		t.Fatalf("a flood from one account must eventually throttle")
	}
	// Throttled requests must never reach the store (short-circuited pre-write).
	if len(store.inserted) != created {
		t.Fatalf("stored %d reports but %d returned 201", len(store.inserted), created)
	}
}

// One account exhausting its report budget must not spend another account's.
func TestPostReportRateLimitIsPerAccount(t *testing.T) {
	store := &fakeStore{}
	h := NewHandlers(newServiceUnderTest(store, &fakeNotifier{}))

	for i := 0; i < reportBurst+3; i++ {
		postReport(t, h, reporterID)
	}

	if got := postReport(t, h, "another-reporter"); got != http.StatusCreated {
		t.Fatalf("a different account's first report = %d, want 201", got)
	}
}

// The sustained budget is ~10/hour: the burst is exactly reportBurst reports.
func TestPostReportAdmitsExactlyTheBurst(t *testing.T) {
	store := &fakeStore{}
	h := NewHandlers(newServiceUnderTest(store, &fakeNotifier{}))

	created := 0
	for i := 0; i < reportBurst+5; i++ {
		if postReport(t, h, reporterID) == http.StatusCreated {
			created++
		}
	}
	if created != reportBurst {
		t.Fatalf("created %d reports, want exactly the burst of %d", created, reportBurst)
	}
}
