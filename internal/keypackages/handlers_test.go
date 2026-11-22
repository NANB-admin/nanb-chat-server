package keypackages_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/keypackages"
	"github.com/nanb/nanb-server/internal/proto"
)

func newHandlers(t *testing.T) (*keypackages.Handlers, *keypackages.StoreInMemory) {
	t.Helper()
	svc, store := newSvc(t) // already defined in service_test.go
	return keypackages.NewHandlers(svc), store
}

func authedRequest(t *testing.T, method, path string, body []byte, accountID, deviceID string) *http.Request {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, http.NoBody)
	}
	req.Header.Set("Content-Type", "application/json")
	ctx := auth.InjectClaimsForTest(req.Context(), crypto.JWTClaims{
		AccountID: accountID, DeviceID: deviceID,
	})
	return req.WithContext(ctx)
}

func TestHandlers_Publish_Happy(t *testing.T) {
	h, _ := newHandlers(t)
	body, _ := json.Marshal(proto.PublishKeyPackagesRequest{
		KeyPackages: [][]byte{[]byte("a"), []byte("b")},
	})
	req := authedRequest(t, "POST", "/accounts/me/key-packages", body, "acct-alice", "dev-1")
	w := httptest.NewRecorder()
	h.PostMyKeyPackages(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp proto.PublishKeyPackagesResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.StoredCount != 2 {
		t.Fatalf("stored = %d, want 2", resp.StoredCount)
	}
}

func TestHandlers_Publish_BadJSON_Returns400(t *testing.T) {
	h, _ := newHandlers(t)
	req := authedRequest(t, "POST", "/accounts/me/key-packages",
		[]byte("{not json"), "acct-alice", "dev-1")
	w := httptest.NewRecorder()
	h.PostMyKeyPackages(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandlers_FetchByUsername_Happy(t *testing.T) {
	h, store := newHandlers(t)
	_ = store.PublishBatch(context.Background(), "acct-bob", "dev-1",
		[][]byte{[]byte("kp")})

	r := chi.NewRouter()
	r.Get("/accounts/{username}/key-package", h.GetKeyPackageByUsername)
	req := authedRequest(t, "GET", "/accounts/@bob/key-package", nil, "acct-alice", "dev-2")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp proto.FetchKeyPackageResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if string(resp.KeyPackage) != "kp" {
		t.Fatalf("got %q, want kp", resp.KeyPackage)
	}
}

func TestHandlers_FetchByUsername_FloodIsRateLimited(t *testing.T) {
	h, store := newHandlers(t)
	// Publish plenty so a 429 comes from the rate limiter, not exhaustion (410).
	pkgs := make([][]byte, 60)
	for i := range pkgs {
		pkgs[i] = []byte("kp")
	}
	_ = store.PublishBatch(context.Background(), "acct-bob", "dev-1", pkgs)

	r := chi.NewRouter()
	r.Get("/accounts/{username}/key-package", h.GetKeyPackageByUsername)

	var ok, limited int
	for i := 0; i < 40; i++ {
		req := authedRequest(t, "GET", "/accounts/@bob/key-package", nil, "acct-attacker", "dev-x")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		switch w.Code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			limited++
		}
	}
	if ok == 0 {
		t.Fatalf("expected some fetches to succeed within the burst")
	}
	if limited == 0 {
		t.Fatalf("expected a draining flood to eventually be rate limited")
	}
}

func TestHandlers_FetchByUsername_DistinctTargetEnumerationIsRateLimited(t *testing.T) {
	// Probing many DISTINCT (nonexistent) usernames must still be bounded by the
	// caller's rate limit: varying the target must not let an attacker enumerate
	// faster than kpFetchBurst, and each distinct target no longer grows the
	// per-target bucket map without bound (see kpMaxTargetBuckets).
	h, _ := newHandlers(t)
	r := chi.NewRouter()
	r.Get("/accounts/{username}/key-package", h.GetKeyPackageByUsername)

	var passed, limited int
	for i := 0; i < 60; i++ {
		req := authedRequest(t, "GET",
			fmt.Sprintf("/accounts/@ghost%d/key-package", i), nil, "acct-attacker", "dev-x")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			limited++
		} else {
			passed++ // got past the limiter (404 unknown / 410 exhausted)
		}
	}
	if passed == 0 {
		t.Fatalf("expected some lookups to pass within the caller burst")
	}
	if limited == 0 {
		t.Fatalf("expected distinct-target enumeration to be caller-rate-limited")
	}
}

func TestHandlers_FetchByUsername_Gone_When_Exhausted(t *testing.T) {
	h, _ := newHandlers(t)
	r := chi.NewRouter()
	r.Get("/accounts/{username}/key-package", h.GetKeyPackageByUsername)
	req := authedRequest(t, "GET", "/accounts/@bob/key-package", nil, "acct-alice", "dev-2")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", w.Code)
	}
}

func TestHandlers_FetchByUsername_NotFound_For_Unknown(t *testing.T) {
	h, _ := newHandlers(t)
	r := chi.NewRouter()
	r.Get("/accounts/{username}/key-package", h.GetKeyPackageByUsername)
	req := authedRequest(t, "GET", "/accounts/@nobody/key-package", nil, "acct-alice", "dev-2")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestHandlers_CountForMe_Happy(t *testing.T) {
	h, store := newHandlers(t)
	_ = store.PublishBatch(context.Background(), "acct-alice", "dev-1",
		[][]byte{[]byte("a"), []byte("b"), []byte("c")})
	req := authedRequest(t, "GET", "/accounts/me/key-packages/count", nil, "acct-alice", "dev-1")
	w := httptest.NewRecorder()
	h.GetMyKeyPackageCount(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"count":3`) {
		t.Fatalf("body = %s", w.Body.String())
	}
}

func TestHandlers_CountForMe_CountsOnlyTheCallingDevice(t *testing.T) {
	h, store := newHandlers(t)
	_ = store.PublishBatch(context.Background(), "acct-alice", "dev-1", [][]byte{[]byte("a")})
	_ = store.PublishBatch(context.Background(), "acct-alice", "dev-2",
		[][]byte{[]byte("b"), []byte("c")})
	req := authedRequest(t, "GET", "/accounts/me/key-packages/count", nil, "acct-alice", "dev-1")
	w := httptest.NewRecorder()
	h.GetMyKeyPackageCount(w, req)
	if !strings.Contains(w.Body.String(), `"count":1`) {
		t.Fatalf("body = %s", w.Body.String())
	}
}

const (
	ownWebDevice   = "11111111-1111-4111-8111-111111111111"
	ownPhoneDevice = "22222222-2222-4222-8222-222222222222"
)

func claimOwnDevice(t *testing.T, h *keypackages.Handlers, path, accountID, callerDevice string) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	r.Get("/accounts/me/devices/{deviceID}/key-packages", h.GetOwnDeviceKeyPackages)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest(t, "GET", path, nil, accountID, callerDevice))
	return w
}

func TestHandlers_ClaimOwnDevice_ReturnsRequestedCountOfThatDevice(t *testing.T) {
	h, store := newHandlers(t)
	_ = store.PublishBatch(context.Background(), "acct-alice", ownWebDevice,
		[][]byte{[]byte("w1"), []byte("w2"), []byte("w3")})
	_ = store.PublishBatch(context.Background(), "acct-alice", ownPhoneDevice,
		[][]byte{[]byte("p1")})

	w := claimOwnDevice(t, h, "/accounts/me/devices/"+ownWebDevice+"/key-packages?count=2",
		"acct-alice", ownPhoneDevice)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp proto.FetchDeviceKeyPackagesResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Devices) != 2 || resp.Devices[0].DeviceID != ownWebDevice ||
		resp.Devices[1].DeviceID != ownWebDevice {
		t.Fatalf("got %+v, want 2 packages of the web device", resp.Devices)
	}
}

func TestHandlers_ClaimOwnDevice_LeavesCallersOwnPackagesUntouched(t *testing.T) {
	h, store := newHandlers(t)
	_ = store.PublishBatch(context.Background(), "acct-alice", ownWebDevice,
		[][]byte{[]byte("w1")})
	_ = store.PublishBatch(context.Background(), "acct-alice", ownPhoneDevice,
		[][]byte{[]byte("p1")})

	claimOwnDevice(t, h, "/accounts/me/devices/"+ownWebDevice+"/key-packages?count=5",
		"acct-alice", ownPhoneDevice)

	n, _ := store.CountUnconsumedByDevice(context.Background(), "acct-alice", ownPhoneDevice)
	if n != 1 {
		t.Fatalf("caller's own packages = %d, want 1 (untouched)", n)
	}
}

func TestHandlers_ClaimOwnDevice_CannotReachAnotherAccountsDevice(t *testing.T) {
	h, store := newHandlers(t)
	_ = store.PublishBatch(context.Background(), "acct-bob", ownWebDevice,
		[][]byte{[]byte("b1")})

	w := claimOwnDevice(t, h, "/accounts/me/devices/"+ownWebDevice+"/key-packages?count=5",
		"acct-alice", ownPhoneDevice)

	var resp proto.FetchDeviceKeyPackagesResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	n, _ := store.CountUnconsumedByDevice(context.Background(), "acct-bob", ownWebDevice)
	if len(resp.Devices) != 0 || n != 1 {
		t.Fatalf("got %d packages, bob left %d; want 0 and 1", len(resp.Devices), n)
	}
}

func TestHandlers_ClaimOwnDevice_RejectsTheCallingDevice(t *testing.T) {
	h, _ := newHandlers(t)

	w := claimOwnDevice(t, h, "/accounts/me/devices/"+ownPhoneDevice+"/key-packages",
		"acct-alice", ownPhoneDevice)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandlers_ClaimOwnDevice_RejectsMalformedDeviceID(t *testing.T) {
	h, _ := newHandlers(t)

	w := claimOwnDevice(t, h, "/accounts/me/devices/not-a-uuid/key-packages",
		"acct-alice", ownPhoneDevice)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandlers_ClaimOwnDevice_RejectsNonPositiveCount(t *testing.T) {
	h, _ := newHandlers(t)

	w := claimOwnDevice(t, h, "/accounts/me/devices/"+ownWebDevice+"/key-packages?count=0",
		"acct-alice", ownPhoneDevice)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandlers_ClaimOwnDevice_CapsCountAtMax(t *testing.T) {
	h, store := newHandlers(t)
	pkgs := make([][]byte, keypackages.MaxOwnDeviceClaim+10)
	for i := range pkgs {
		pkgs[i] = []byte("w")
	}
	_ = store.PublishBatch(context.Background(), "acct-alice", ownWebDevice, pkgs)

	w := claimOwnDevice(t, h, "/accounts/me/devices/"+ownWebDevice+"/key-packages?count=1000",
		"acct-alice", ownPhoneDevice)

	var resp proto.FetchDeviceKeyPackagesResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Devices) != keypackages.MaxOwnDeviceClaim {
		t.Fatalf("got %d, want %d", len(resp.Devices), keypackages.MaxOwnDeviceClaim)
	}
}
