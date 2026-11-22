package delivery_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/delivery"
)

const browserOrigin = "https://chat.example.org"

func newTicketHandlers(t *testing.T) (*delivery.Handlers, *delivery.WSTicketStore) {
	t.Helper()
	store := delivery.NewWSTicketStore(30*time.Second, time.Now)
	h := delivery.NewHandlers(&mockSvc{}, delivery.NewHub())
	h.SetWSTickets(store)
	return h, store
}

func postTicket(h *delivery.Handlers, claims *crypto.JWTClaims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ws/ticket", nil)
	if claims != nil {
		req = req.WithContext(auth.InjectClaimsForTest(req.Context(), *claims))
	}
	rec := httptest.NewRecorder()
	h.PostWSTicket(rec, req)
	return rec
}

// dialWSTicket opens a WebSocket the way a browser must: no Authorization
// header, the one-time ticket in the query string, and (optionally) an Origin.
func dialWSTicket(srvURL, ticket, origin string) (*websocket.Conn, *http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts := &websocket.DialOptions{}
	if origin != "" {
		opts.HTTPHeader = http.Header{"Origin": []string{origin}}
	}
	url := "ws" + strings.TrimPrefix(srvURL, "http") + "?ticket=" + ticket
	return websocket.Dial(ctx, url, opts)
}

func TestPostWSTicket_WithoutSession_Returns401(t *testing.T) {
	h, _ := newTicketHandlers(t)

	rec := postTicket(h, nil)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostWSTicket_WithSession_Returns200(t *testing.T) {
	h, _ := newTicketHandlers(t)

	rec := postTicket(h, &crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPostWSTicket_WithSession_ReturnsARedeemableTicket(t *testing.T) {
	h, store := newTicketHandlers(t)
	rec := postTicket(h, &crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})
	var body struct {
		Ticket string `json:"ticket"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	got, ok := store.Redeem(body.Ticket)

	require.True(t, ok)
	assert.Equal(t, "dev-1", got.DeviceID)
}

func TestPostWSTicket_ReportsTheTicketLifetime(t *testing.T) {
	h, _ := newTicketHandlers(t)
	rec := postTicket(h, &crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})
	var body struct {
		ExpiresInSeconds int `json:"expires_in_seconds"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	assert.Equal(t, 30, body.ExpiresInSeconds)
}

func TestPostWSTicket_WhenWebSessionsAreNotConfigured_Returns503(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, delivery.NewHub())

	rec := postTicket(h, &crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleWS_ValidTicket_Connects(t *testing.T) {
	pub, _, _ := ed25519GenForTest(t)
	h, store := newTicketHandlers(t)
	srv := httptest.NewServer(h.HandleWS(pub))
	defer srv.Close()
	ticket, _ := store.Issue(crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})

	c, _, err := dialWSTicket(srv.URL, ticket, "")

	require.NoError(t, err)
	_ = c.Close(websocket.StatusNormalClosure, "")
}

func TestHandleWS_TicketReplay_Returns401(t *testing.T) {
	pub, _, _ := ed25519GenForTest(t)
	h, store := newTicketHandlers(t)
	srv := httptest.NewServer(h.HandleWS(pub))
	defer srv.Close()
	ticket, _ := store.Issue(crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})
	first, _, err := dialWSTicket(srv.URL, ticket, "")
	require.NoError(t, err)
	defer first.Close(websocket.StatusNormalClosure, "")

	_, resp, err := dialWSTicket(srv.URL, ticket, "")

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandleWS_UnknownTicket_Returns401(t *testing.T) {
	pub, _, _ := ed25519GenForTest(t)
	h, _ := newTicketHandlers(t)
	srv := httptest.NewServer(h.HandleWS(pub))
	defer srv.Close()

	_, resp, err := dialWSTicket(srv.URL, "not-a-real-ticket", "")

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandleWS_TicketForRevokedDevice_Returns401(t *testing.T) {
	pub, _, _ := ed25519GenForTest(t)
	h, store := newTicketHandlers(t)
	h.SetDeviceValidator(func(context.Context, string) bool { return false })
	srv := httptest.NewServer(h.HandleWS(pub))
	defer srv.Close()
	ticket, _ := store.Issue(crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})

	_, resp, err := dialWSTicket(srv.URL, ticket, "")

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandleWS_Ticket_IsIgnoredWhenWebSessionsAreNotConfigured(t *testing.T) {
	pub, _, _ := ed25519GenForTest(t)
	h := delivery.NewHandlers(&mockSvc{}, delivery.NewHub())
	srv := httptest.NewServer(h.HandleWS(pub))
	defer srv.Close()

	_, resp, err := dialWSTicket(srv.URL, "anything", "")

	require.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandleWS_BrowserFromAllowedOrigin_Connects(t *testing.T) {
	pub, _, _ := ed25519GenForTest(t)
	h, store := newTicketHandlers(t)
	h.SetWebOrigins([]string{browserOrigin})
	srv := httptest.NewServer(h.HandleWS(pub))
	defer srv.Close()
	ticket, _ := store.Issue(crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})

	c, _, err := dialWSTicket(srv.URL, ticket, browserOrigin)

	require.NoError(t, err)
	_ = c.Close(websocket.StatusNormalClosure, "")
}

func TestHandleWS_BrowserFromUnlistedOrigin_IsRejected(t *testing.T) {
	pub, _, _ := ed25519GenForTest(t)
	h, store := newTicketHandlers(t)
	h.SetWebOrigins([]string{browserOrigin})
	srv := httptest.NewServer(h.HandleWS(pub))
	defer srv.Close()
	ticket, _ := store.Issue(crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})

	_, resp, err := dialWSTicket(srv.URL, ticket, "https://evil.example")

	require.Error(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestHandleWS_CrossOriginBrowser_IsRejectedWhenNoOriginsAreConfigured(t *testing.T) {
	pub, _, _ := ed25519GenForTest(t)
	h, store := newTicketHandlers(t)
	srv := httptest.NewServer(h.HandleWS(pub))
	defer srv.Close()
	ticket, _ := store.Issue(crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})

	_, resp, err := dialWSTicket(srv.URL, ticket, browserOrigin)

	require.Error(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func postTicketAs(t *testing.T, h *delivery.Handlers, accountID string) int {
	t.Helper()
	return postTicket(h, &crypto.JWTClaims{AccountID: accountID, DeviceID: "dev-1"}).Code
}

func TestPostWSTicket_AccountOverItsBudget_Returns429(t *testing.T) {
	h, _ := newTicketHandlers(t)
	var last int
	for i := 0; i < 50; i++ {
		last = postTicketAs(t, h, "acc-flood")
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once the account's ticket budget is spent", last)
	}
}

func TestPostWSTicket_OtherAccountStillServedWhileOneFloods(t *testing.T) {
	h, _ := newTicketHandlers(t)
	for i := 0; i < 50; i++ {
		postTicketAs(t, h, "acc-flood")
	}
	if got := postTicketAs(t, h, "acc-calm"); got != http.StatusOK {
		t.Fatalf("calm account status = %d, want 200", got)
	}
}
