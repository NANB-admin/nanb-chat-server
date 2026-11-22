package turn_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // matches the production HMAC-SHA1 (coturn REST)
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/proto"
	"github.com/nanb/nanb-server/internal/turn"
)

func ctxWithClaims(accountID string) context.Context {
	return auth.InjectClaimsForTest(context.Background(), crypto.JWTClaims{
		AccountID: accountID,
		DeviceID:  "dev-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
}

func TestGetCredentials_HappyPath(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0)
	h := turn.NewHandlers(turn.Config{
		Secret: "s3cr3t",
		URLs:   []string{"turns:turn.example.org:443?transport=tcp"},
		TTL:    time.Hour,
		Now:    func() time.Time { return fixed },
	})
	req := httptest.NewRequest(http.MethodGet, "/turn/credentials", nil).
		WithContext(ctxWithClaims("acc-1"))
	rec := httptest.NewRecorder()

	h.GetCredentials(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp proto.TurnCredentialsResponse
	assert.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	assert.GreaterOrEqual(t, resp.TTL, 3600, "validity is never shorter than the configured TTL")
	assert.Equal(t, []string{"turns:turn.example.org:443?transport=tcp"}, resp.URLs)

	// The credential must verify against the shared secret.
	mac := hmac.New(sha1.New, []byte("s3cr3t"))
	mac.Write([]byte(resp.Username))
	assert.Equal(t, base64.StdEncoding.EncodeToString(mac.Sum(nil)), resp.Credential)
}

func TestGetCredentials_NoClaims_401(t *testing.T) {
	h := turn.NewHandlers(turn.Config{Secret: "s", URLs: []string{"turns:x"}})
	req := httptest.NewRequest(http.MethodGet, "/turn/credentials", nil)
	rec := httptest.NewRecorder()

	h.GetCredentials(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGetCredentials_NotConfigured_503(t *testing.T) {
	h := turn.NewHandlers(turn.Config{}) // no secret / no urls
	req := httptest.NewRequest(http.MethodGet, "/turn/credentials", nil).
		WithContext(ctxWithClaims("acc-1"))
	rec := httptest.NewRecorder()

	h.GetCredentials(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestEnabled(t *testing.T) {
	assert.True(t, turn.NewHandlers(turn.Config{Secret: "s", URLs: []string{"turns:x"}}).Enabled())
	assert.False(t, turn.NewHandlers(turn.Config{URLs: []string{"turns:x"}}).Enabled())
	assert.False(t, turn.NewHandlers(turn.Config{Secret: "s"}).Enabled())
}

func mint(t *testing.T, h *turn.Handlers, accountID string) (proto.TurnCredentialsResponse, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/turn/credentials", nil).
		WithContext(ctxWithClaims(accountID))
	rec := httptest.NewRecorder()
	h.GetCredentials(rec, req)
	var resp proto.TurnCredentialsResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	return resp, rec.Code
}

func newHandlersAt(now time.Time) (*turn.Handlers, *time.Time) {
	clock := now
	h := turn.NewHandlers(turn.Config{
		Secret: "s3cr3t",
		URLs:   []string{"turns:turn.example.org:443?transport=tcp"},
		TTL:    time.Hour,
		Now:    func() time.Time { return clock },
	})
	return h, &clock
}

func TestGetCredentials_UsernameDoesNotContainTheAccountID(t *testing.T) {
	h, _ := newHandlersAt(time.Unix(1_700_000_000, 0))

	resp, _ := mint(t, h, "acc-1")

	assert.NotContains(t, resp.Username, "acc-1")
}

func TestGetCredentials_UsernameIsExpiryColonOpaqueID(t *testing.T) {
	h, _ := newHandlersAt(time.Unix(1_700_000_000, 0))

	resp, _ := mint(t, h, "acc-1")

	parts := strings.SplitN(resp.Username, ":", 2)
	assert.Len(t, parts, 2)
	_, err := strconv.ParseInt(parts[0], 10, 64)
	assert.NoError(t, err, "coturn REST auth needs a numeric timestamp prefix")
	assert.NotEmpty(t, parts[1])
}

func TestGetCredentials_ExpiryIsNotBeforeNowPlusTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h, _ := newHandlersAt(now)

	resp, _ := mint(t, h, "acc-1")

	expiry, _ := strconv.ParseInt(strings.SplitN(resp.Username, ":", 2)[0], 10, 64)
	assert.GreaterOrEqual(t, expiry, now.Add(time.Hour).Unix())
}

func TestGetCredentials_SameAccountGetsTheSameUsernameWithinAStep(t *testing.T) {
	h, clock := newHandlersAt(time.Unix(1_700_000_000, 0))
	first, _ := mint(t, h, "acc-1")

	*clock = clock.Add(5 * time.Second)
	second, _ := mint(t, h, "acc-1")

	assert.Equal(t, first.Username, second.Username, "stable id so coturn user-quota groups the account")
}

func TestGetCredentials_DifferentAccountsGetDifferentUsernames(t *testing.T) {
	h, _ := newHandlersAt(time.Unix(1_700_000_000, 0))

	a, _ := mint(t, h, "acc-1")
	b, _ := mint(t, h, "acc-2")

	assert.NotEqual(t, a.Username, b.Username)
}

func TestGetCredentials_UsernameChangesOnceTheStepAdvances(t *testing.T) {
	h, clock := newHandlersAt(time.Unix(1_700_000_000, 0))
	first, _ := mint(t, h, "acc-1")

	*clock = clock.Add(2 * time.Hour)
	later, _ := mint(t, h, "acc-1")

	assert.NotEqual(t, first.Username, later.Username, "ids rotate so they cannot be linked across windows")
}

func TestGetCredentials_UsernameDependsOnTheServerSecret(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	a := turn.NewHandlers(turn.Config{Secret: "one", URLs: []string{"turns:x"}, TTL: time.Hour, Now: func() time.Time { return now }})
	b := turn.NewHandlers(turn.Config{Secret: "two", URLs: []string{"turns:x"}, TTL: time.Hour, Now: func() time.Time { return now }})

	ra, _ := mint(t, a, "acc-1")
	rb, _ := mint(t, b, "acc-1")

	assert.NotEqual(t, ra.Username, rb.Username, "ids must not be computable without the secret")
}

func TestGetCredentials_CredentialVerifiesAgainstTheOpaqueUsername(t *testing.T) {
	h, _ := newHandlersAt(time.Unix(1_700_000_000, 0))

	resp, _ := mint(t, h, "acc-1")

	mac := hmac.New(sha1.New, []byte("s3cr3t"))
	mac.Write([]byte(resp.Username))
	assert.Equal(t, base64.StdEncoding.EncodeToString(mac.Sum(nil)), resp.Credential)
}

func TestGetCredentials_AccountMintingTooFastGets429(t *testing.T) {
	h, _ := newHandlersAt(time.Unix(1_700_000_000, 0))

	var last int
	for i := 0; i < 100; i++ {
		_, last = mint(t, h, "acc-1")
	}

	assert.Equal(t, http.StatusTooManyRequests, last)
}

func TestGetCredentials_ThirtyMintsInAMinuteAreAllowed(t *testing.T) {
	h, _ := newHandlersAt(time.Unix(1_700_000_000, 0))

	var last int
	for i := 0; i < 30; i++ {
		_, last = mint(t, h, "acc-1")
	}

	assert.Equal(t, http.StatusOK, last)
}

func TestGetCredentials_OneAccountFloodingDoesNotBlockAnother(t *testing.T) {
	h, _ := newHandlersAt(time.Unix(1_700_000_000, 0))
	for i := 0; i < 100; i++ {
		mint(t, h, "acc-flood")
	}

	_, code := mint(t, h, "acc-calm")

	assert.Equal(t, http.StatusOK, code)
}

func TestGetCredentials_MintBudgetRefills(t *testing.T) {
	h, clock := newHandlersAt(time.Unix(1_700_000_000, 0))
	for i := 0; i < 100; i++ {
		mint(t, h, "acc-1")
	}

	*clock = clock.Add(time.Minute)
	_, code := mint(t, h, "acc-1")

	assert.Equal(t, http.StatusOK, code)
}

func credsURLs(t *testing.T, h *turn.Handlers, country string) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/turn/credentials", nil).
		WithContext(ctxWithClaims("acc-1"))
	if country != "" {
		req.Header.Set("CloudFront-Viewer-Country", country)
	}
	rec := httptest.NewRecorder()
	h.GetCredentials(rec, req)
	var resp proto.TurnCredentialsResponse
	assert.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	return resp.URLs
}

func twoRelayHandlers() *turn.Handlers {
	return turn.NewHandlers(turn.Config{
		Secret:     "s",
		URLs:       []string{"turn:us"},
		URLsEurope: []string{"turn:eu"},
	})
}

func TestGetCredentials_JordanViewerGetsTheFrankfurtRelay(t *testing.T) {
	assert.Equal(t, []string{"turn:eu"}, credsURLs(t, twoRelayHandlers(), "JO"))
}

func TestGetCredentials_GermanViewerGetsTheFrankfurtRelay(t *testing.T) {
	assert.Equal(t, []string{"turn:eu"}, credsURLs(t, twoRelayHandlers(), "DE"))
}

func TestGetCredentials_CountryCodeIsCaseInsensitive(t *testing.T) {
	assert.Equal(t, []string{"turn:eu"}, credsURLs(t, twoRelayHandlers(), "jo"))
}

func TestGetCredentials_AmericanViewerKeepsTheDefaultRelay(t *testing.T) {
	assert.Equal(t, []string{"turn:us"}, credsURLs(t, twoRelayHandlers(), "US"))
}

func TestGetCredentials_NoCountryHeaderKeepsTheDefaultRelay(t *testing.T) {
	assert.Equal(t, []string{"turn:us"}, credsURLs(t, twoRelayHandlers(), ""))
}

func TestGetCredentials_WithoutAFrankfurtRelayEveryoneGetsTheDefault(t *testing.T) {
	h := turn.NewHandlers(turn.Config{Secret: "s", URLs: []string{"turn:us"}})

	assert.Equal(t, []string{"turn:us"}, credsURLs(t, h, "JO"))
}
