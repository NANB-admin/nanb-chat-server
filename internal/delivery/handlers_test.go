package delivery_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/delivery"
	"github.com/nanb/nanb-server/internal/proto"
)

type mockSvc struct {
	submit      func(ctx context.Context, senderDeviceID string, req proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error)
	catch       func(ctx context.Context, deviceID string, req proto.CatchupRequest) (proto.CatchupResponse, error)
	ack         func(ctx context.Context, deviceID string, req proto.AckRequest) (proto.AckResponse, error)
	received    func(ctx context.Context, deviceID, envelopeID string) (proto.ConfirmReceivedResponse, error)
	getEnvelope func(ctx context.Context, envelopeID, recipientDeviceID string) (proto.Envelope, error)
}

func (m *mockSvc) SubmitMessage(ctx context.Context, sender string, req proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
	return m.submit(ctx, sender, req)
}
func (m *mockSvc) CatchupMessages(ctx context.Context, dev string, req proto.CatchupRequest) (proto.CatchupResponse, error) {
	return m.catch(ctx, dev, req)
}
func (m *mockSvc) AckMessages(ctx context.Context, dev string, req proto.AckRequest) (proto.AckResponse, error) {
	return m.ack(ctx, dev, req)
}
func (m *mockSvc) ConfirmReceived(ctx context.Context, dev, envelopeID string) (proto.ConfirmReceivedResponse, error) {
	return m.received(ctx, dev, envelopeID)
}
func (m *mockSvc) GetEnvelopeByIDForRecipient(ctx context.Context, envelopeID, recipientDeviceID string) (proto.Envelope, error) {
	return m.getEnvelope(ctx, envelopeID, recipientDeviceID)
}

func ctxWithClaims(deviceID, accountID string) context.Context {
	return auth.InjectClaimsForTest(context.Background(), crypto.JWTClaims{
		AccountID: accountID,
		DeviceID:  deviceID,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
}

func TestPostMessage_HappyPath(t *testing.T) {
	svc := &mockSvc{
		submit: func(ctx context.Context, sender string, r proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			assert.Equal(t, "sender-dev-1", sender)
			return proto.SubmitMessageResponse{EnvelopeID: "env-1", ServerTS: time.Unix(1, 0).UTC()}, nil
		},
	}
	h := delivery.NewHandlers(svc, nil)

	body, _ := json.Marshal(proto.SubmitMessageRequest{
		ConversationID:     "c1",
		EnvelopeType:       proto.EnvelopeTypeMLSApplication,
		RecipientAccountID: "acc-2",
		RecipientDeviceID:  "dev-2",
		Ciphertext:         []byte("ct"),
	})
	req := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(body)).
		WithContext(ctxWithClaims("sender-dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostMessage(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	var resp proto.SubmitMessageResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "env-1", resp.EnvelopeID)
}

func TestPostMessage_AccountNotFound_Returns404(t *testing.T) {
	// A revoked/deleted recipient device is a DEFINITIVE verdict about the
	// addressee, so it must not masquerade as a server fault: the client keys its
	// "peer switched phones" recovery on this code, and a 5xx makes its transient
	// retry swallow the send instead of re-resolving the peer.
	svc := &mockSvc{
		submit: func(ctx context.Context, sender string, r proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			return proto.SubmitMessageResponse{}, proto.APIError{
				Code:    proto.ErrCodeAccountNotFound,
				Message: "recipient account deleted or device revoked",
			}
		},
	}
	h := delivery.NewHandlers(svc, nil)

	body, _ := json.Marshal(proto.SubmitMessageRequest{
		ConversationID:     "c1",
		EnvelopeType:       proto.EnvelopeTypeMLSApplication,
		RecipientAccountID: "acc-2",
		RecipientDeviceID:  "dead-dev",
		Ciphertext:         []byte("ct"),
	})
	req := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(body)).
		WithContext(ctxWithClaims("sender-dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostMessage(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// A full recipient mailbox is reported as 507: a real answer (so the client's
// transient retry doesn't spin) that its fan-out leg retry (status >= 500)
// re-tries later, and NOT 429, which app builds render as "Sending too fast".
func TestPostMessage_MailboxFull_Returns507(t *testing.T) {
	svc := &mockSvc{
		submit: func(context.Context, string, proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			return proto.SubmitMessageResponse{}, proto.APIError{Code: proto.ErrCodeMailboxFull, Message: "full"}
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.SubmitMessageRequest{
		EnvelopeType:       proto.EnvelopeTypeSealed,
		RecipientAccountID: "acc-2",
		RecipientDeviceID:  "dev-2",
		Ciphertext:         []byte("ct"),
	})
	req := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(body)).
		WithContext(ctxWithClaims("sender-dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostMessage(rec, req)

	assert.Equal(t, http.StatusInsufficientStorage, rec.Code)
}

func TestPostReceived_HappyPath(t *testing.T) {
	svc := &mockSvc{
		received: func(ctx context.Context, dev, envelopeID string) (proto.ConfirmReceivedResponse, error) {
			assert.Equal(t, "recipient-dev-1", dev)
			assert.Equal(t, "env-1", envelopeID)
			return proto.ConfirmReceivedResponse{Relayed: true}, nil
		},
	}
	h := delivery.NewHandlers(svc, nil)

	body, _ := json.Marshal(proto.ConfirmReceivedRequest{EnvelopeID: "env-1"})
	req := httptest.NewRequest(http.MethodPost, "/messages/received", bytes.NewReader(body)).
		WithContext(ctxWithClaims("recipient-dev-1", "acc-2"))
	rec := httptest.NewRecorder()

	h.PostReceived(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp proto.ConfirmReceivedResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Relayed)
}

func TestPostReceived_NoClaims_Returns401(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, nil)
	body, _ := json.Marshal(proto.ConfirmReceivedRequest{EnvelopeID: "env-1"})
	req := httptest.NewRequest(http.MethodPost, "/messages/received", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostReceived(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostReceived_BadJSON_Returns400(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/messages/received", bytes.NewReader([]byte("not-json"))).
		WithContext(ctxWithClaims("recipient-dev-1", "acc-2"))
	rec := httptest.NewRecorder()

	h.PostReceived(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostMessage_NoClaims_Returns401(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, nil)
	body, _ := json.Marshal(proto.SubmitMessageRequest{})
	req := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostMessage(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostMessage_BadJSON_Returns400(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader([]byte("not-json"))).
		WithContext(ctxWithClaims("sender-dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostMessage(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostMessage_PayloadTooLarge_Returns413(t *testing.T) {
	svc := &mockSvc{
		submit: func(ctx context.Context, sender string, r proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			return proto.SubmitMessageResponse{}, proto.APIError{Code: proto.ErrCodePayloadTooLarge, Message: "too big"}
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.SubmitMessageRequest{ConversationID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(body)).
		WithContext(ctxWithClaims("sender-dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostMessage(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestPostMessage_ForbiddenError_Returns403(t *testing.T) {
	svc := &mockSvc{
		submit: func(ctx context.Context, sender string, r proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			return proto.SubmitMessageResponse{}, proto.APIError{Code: proto.ErrCodeForbidden, Message: "blocked"}
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.SubmitMessageRequest{ConversationID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(body)).
		WithContext(ctxWithClaims("sender-dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostMessage(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestPostMessage_UnauthorizedAPIError_Returns401(t *testing.T) {
	svc := &mockSvc{
		submit: func(ctx context.Context, sender string, r proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			return proto.SubmitMessageResponse{}, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "x"}
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.SubmitMessageRequest{ConversationID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(body)).
		WithContext(ctxWithClaims("sender-dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostMessage(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostMessage_GenericInternalError_Returns500(t *testing.T) {
	svc := &mockSvc{
		submit: func(ctx context.Context, sender string, r proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			return proto.SubmitMessageResponse{}, errors.New("boom")
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.SubmitMessageRequest{ConversationID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(body)).
		WithContext(ctxWithClaims("sender-dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostMessage(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPostMessage_APIErrorInternal_Returns500(t *testing.T) {
	svc := &mockSvc{
		submit: func(ctx context.Context, sender string, r proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			return proto.SubmitMessageResponse{}, proto.APIError{Code: proto.ErrCodeInternal, Message: "x"}
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.SubmitMessageRequest{ConversationID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/messages", bytes.NewReader(body)).
		WithContext(ctxWithClaims("sender-dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostMessage(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPostCatchup_HappyPath(t *testing.T) {
	svc := &mockSvc{
		catch: func(ctx context.Context, dev string, r proto.CatchupRequest) (proto.CatchupResponse, error) {
			assert.Equal(t, "dev-1", dev)
			return proto.CatchupResponse{Envelopes: []proto.Envelope{{EnvelopeID: "env-1"}}}, nil
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.CatchupRequest{Limit: 10})
	req := httptest.NewRequest(http.MethodPost, "/messages/catchup", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostCatchup(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPostCatchup_NoClaims_Returns401(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, nil)
	body, _ := json.Marshal(proto.CatchupRequest{})
	req := httptest.NewRequest(http.MethodPost, "/messages/catchup", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostCatchup(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostCatchup_BadJSON_Returns400(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/messages/catchup", bytes.NewReader([]byte("garbage"))).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostCatchup(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostCatchup_ServiceError_Returns500(t *testing.T) {
	svc := &mockSvc{
		catch: func(ctx context.Context, dev string, r proto.CatchupRequest) (proto.CatchupResponse, error) {
			return proto.CatchupResponse{}, errors.New("boom")
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.CatchupRequest{})
	req := httptest.NewRequest(http.MethodPost, "/messages/catchup", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostCatchup(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPostAck_HappyPath(t *testing.T) {
	svc := &mockSvc{
		ack: func(ctx context.Context, dev string, r proto.AckRequest) (proto.AckResponse, error) {
			return proto.AckResponse{AckedCount: len(r.EnvelopeIDs)}, nil
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.AckRequest{EnvelopeIDs: []string{"a", "b"}})
	req := httptest.NewRequest(http.MethodPost, "/messages/ack", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostAck(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPostAck_NoClaims_Returns401(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, nil)
	body, _ := json.Marshal(proto.AckRequest{})
	req := httptest.NewRequest(http.MethodPost, "/messages/ack", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostAck(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostAck_BadJSON_Returns400(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/messages/ack", bytes.NewReader([]byte("nope"))).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostAck(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostAck_BadRequest_FromService(t *testing.T) {
	svc := &mockSvc{
		ack: func(ctx context.Context, dev string, r proto.AckRequest) (proto.AckResponse, error) {
			return proto.AckResponse{}, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "x"}
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.AckRequest{EnvelopeIDs: []string{}})
	req := httptest.NewRequest(http.MethodPost, "/messages/ack", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostAck(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostAck_ServiceError_Returns500(t *testing.T) {
	svc := &mockSvc{
		ack: func(ctx context.Context, dev string, r proto.AckRequest) (proto.AckResponse, error) {
			return proto.AckResponse{}, errors.New("boom")
		},
	}
	h := delivery.NewHandlers(svc, nil)
	body, _ := json.Marshal(proto.AckRequest{EnvelopeIDs: []string{"a"}})
	req := httptest.NewRequest(http.MethodPost, "/messages/ack", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostAck(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// extractToken is exercised indirectly by HandleWS in production. We test it
// here via the WS handler's behavior on missing token (covers the "no
// Authorization header" branch returning 401).
func TestHandleWS_NoToken_Returns401(t *testing.T) {
	pub, _, _ := ed25519GenForTest(t)
	h := delivery.NewHandlers(&mockSvc{}, nil)
	wsHandler := h.HandleWS(pub)

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	rec := httptest.NewRecorder()

	wsHandler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// The ?token= query param is deliberately NOT honored anymore — request URLs
// land verbatim in the request log (and proxy logs), so a token there is a
// leaked credential. Even a VALID token via query param must be rejected.
func TestHandleWS_ValidTokenInQueryParam_IsIgnored_Returns401(t *testing.T) {
	pub, priv, _ := ed25519GenForTest(t)
	h := delivery.NewHandlers(&mockSvc{}, nil)
	wsHandler := h.HandleWS(pub)

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1",
		DeviceID:  "dev-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	req := httptest.NewRequest(http.MethodGet, "/ws?token="+token, nil)
	rec := httptest.NewRecorder()

	wsHandler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleWS_BearerHeaderBadToken_Returns401(t *testing.T) {
	pub, _, _ := ed25519GenForTest(t)
	h := delivery.NewHandlers(&mockSvc{}, nil)
	wsHandler := h.HandleWS(pub)

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.token")
	rec := httptest.NewRecorder()

	wsHandler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// dialWS opens a real WebSocket to a test server with the bearer token.
func dialWS(t *testing.T, ctx context.Context, serverURL, token string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(serverURL, "http")
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
	})
	require.NoError(t, err)
	return c
}

// A "send" frame over the live socket takes the SAME path as POST /messages:
// SubmitMessage runs with the JWT-authenticated sender (never a frame field),
// and the server replies with a send_ack correlated by client_ref.
func TestHandleWS_SendFrame_AcksAndUsesAuthedSender(t *testing.T) {
	pub, priv, _ := ed25519GenForTest(t)
	var gotSender string
	var gotReq proto.SubmitMessageRequest
	svc := &mockSvc{
		submit: func(_ context.Context, sender string, r proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			gotSender = sender
			gotReq = r
			return proto.SubmitMessageResponse{EnvelopeID: "env-ws-1", ServerTS: time.Unix(42, 0).UTC()}, nil
		},
	}
	srv := httptest.NewServer(delivery.NewHandlers(svc, delivery.NewHub()).HandleWS(pub))
	defer srv.Close()

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1", DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := dialWS(t, ctx, srv.URL, token)
	defer c.Close(websocket.StatusNormalClosure, "")

	require.NoError(t, wsjson.Write(ctx, c, map[string]any{
		"type":                 "send",
		"client_ref":           "ref-1",
		"conversation_id":      "c1",
		"envelope_type":        proto.EnvelopeTypeMLSApplication,
		"recipient_account_id": "acc-2",
		"recipient_device_id":  "dev-2",
		"ciphertext":           []byte("ct"), // []byte -> base64 in JSON, as the HTTP body does
	}))

	var ack map[string]any
	require.NoError(t, wsjson.Read(ctx, c, &ack))
	assert.Equal(t, "send_ack", ack["type"])
	assert.Equal(t, "ref-1", ack["client_ref"])
	assert.Equal(t, "env-ws-1", ack["envelope_id"])

	// Sender is the JWT's device id, NOT anything the client could put in the frame.
	assert.Equal(t, "dev-1", gotSender)
	assert.Equal(t, "c1", gotReq.ConversationID)
	assert.Equal(t, proto.EnvelopeTypeMLSApplication, gotReq.EnvelopeType)
	assert.Equal(t, []byte("ct"), gotReq.Ciphertext)
}

// An app-level "ping" liveness probe comes straight back as a "pong" so the
// client can confirm the socket is responsive on resume and skip a needless
// (Tor-costly) reconnect.
func TestHandleWS_PingFrame_RepliesPong(t *testing.T) {
	pub, priv, _ := ed25519GenForTest(t)
	srv := httptest.NewServer(delivery.NewHandlers(&mockSvc{}, delivery.NewHub()).HandleWS(pub))
	defer srv.Close()

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1", DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := dialWS(t, ctx, srv.URL, token)
	defer c.Close(websocket.StatusNormalClosure, "")

	require.NoError(t, wsjson.Write(ctx, c, map[string]any{"type": "ping"}))

	var pong map[string]any
	require.NoError(t, wsjson.Read(ctx, c, &pong))
	assert.Equal(t, "pong", pong["type"])
}

// A service error comes back as a send_error frame carrying the APIError's code,
// correlated by the same client_ref.
func TestHandleWS_SendFrame_SurfacesServiceError(t *testing.T) {
	pub, priv, _ := ed25519GenForTest(t)
	svc := &mockSvc{
		submit: func(_ context.Context, _ string, _ proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			return proto.SubmitMessageResponse{}, proto.APIError{Code: proto.ErrCodeDeviceNotFound, Message: "no such device"}
		},
	}
	srv := httptest.NewServer(delivery.NewHandlers(svc, delivery.NewHub()).HandleWS(pub))
	defer srv.Close()

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1", DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := dialWS(t, ctx, srv.URL, token)
	defer c.Close(websocket.StatusNormalClosure, "")

	require.NoError(t, wsjson.Write(ctx, c, map[string]any{
		"type":                 "send",
		"client_ref":           "ref-err",
		"conversation_id":      "c1",
		"envelope_type":        proto.EnvelopeTypeMLSApplication,
		"recipient_account_id": "acc-2",
		"recipient_device_id":  "dev-gone",
		"ciphertext":           []byte("ct"),
	}))

	var resp map[string]any
	require.NoError(t, wsjson.Read(ctx, c, &resp))
	assert.Equal(t, "send_error", resp["type"])
	assert.Equal(t, "ref-err", resp["client_ref"])
	assert.Equal(t, string(proto.ErrCodeDeviceNotFound), resp["code"])
}

// A "catchup" frame drains the receive path over the live socket instead of a
// fresh HTTPS POST. Measured on-device, that POST cost 644-957ms of connection
// setup for a query the server answers in under 10ms.
func TestHandleWS_CatchupFrame_ReturnsEnvelopes(t *testing.T) {
	pub, priv, _ := ed25519GenForTest(t)
	svc := &mockSvc{
		catch: func(_ context.Context, dev string, r proto.CatchupRequest) (proto.CatchupResponse, error) {
			assert.Equal(t, "dev-1", dev) // device from the JWT, never the frame
			assert.Equal(t, 200, r.Limit)
			return proto.CatchupResponse{Envelopes: []proto.Envelope{
				{EnvelopeID: "e1", ConversationID: "c1"},
			}}, nil
		},
	}
	srv := httptest.NewServer(delivery.NewHandlers(svc, delivery.NewHub()).HandleWS(pub))
	defer srv.Close()

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1", DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := dialWS(t, ctx, srv.URL, token)
	defer c.Close(websocket.StatusNormalClosure, "")

	require.NoError(t, wsjson.Write(ctx, c, map[string]any{
		"type":       "catchup",
		"client_ref": "ref-1",
		"limit":      200,
	}))

	var resp map[string]any
	require.NoError(t, wsjson.Read(ctx, c, &resp))
	assert.Equal(t, "catchup_result", resp["type"])
	assert.Equal(t, "ref-1", resp["client_ref"])
	envs, _ := resp["envelopes"].([]any)
	require.Len(t, envs, 1)
}

func TestHandleWS_CatchupFrame_ReportsServiceFailure(t *testing.T) {
	// The client must be able to tell "nothing to drain" apart from "that
	// failed, use HTTP" — a swallowed error would look like an empty inbox.
	pub, priv, _ := ed25519GenForTest(t)
	svc := &mockSvc{
		catch: func(_ context.Context, _ string, _ proto.CatchupRequest) (proto.CatchupResponse, error) {
			return proto.CatchupResponse{}, proto.APIError{
				Code: proto.ErrCodeInternal, Message: "db down",
			}
		},
	}
	srv := httptest.NewServer(delivery.NewHandlers(svc, delivery.NewHub()).HandleWS(pub))
	defer srv.Close()

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1", DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := dialWS(t, ctx, srv.URL, token)
	defer c.Close(websocket.StatusNormalClosure, "")

	require.NoError(t, wsjson.Write(ctx, c, map[string]any{
		"type": "catchup", "client_ref": "ref-2", "limit": 10,
	}))

	var resp map[string]any
	require.NoError(t, wsjson.Read(ctx, c, &resp))
	assert.Equal(t, "catchup_error", resp["type"])
	assert.Equal(t, "ref-2", resp["client_ref"])
}

// An "ack" frame consumes envelopes via AckMessages with the JWT sender —
// fire-and-forget (no reply frame).
func TestHandleWS_AckFrame_ConsumesEnvelopes(t *testing.T) {
	pub, priv, _ := ed25519GenForTest(t)
	var gotDevice string
	var gotIDs []string
	done := make(chan struct{})
	svc := &mockSvc{
		ack: func(_ context.Context, dev string, r proto.AckRequest) (proto.AckResponse, error) {
			gotDevice = dev
			gotIDs = r.EnvelopeIDs
			close(done)
			return proto.AckResponse{AckedCount: len(r.EnvelopeIDs)}, nil
		},
	}
	srv := httptest.NewServer(delivery.NewHandlers(svc, delivery.NewHub()).HandleWS(pub))
	defer srv.Close()

	token := crypto.SignJWT(priv, crypto.JWTClaims{
		AccountID: "acc-1", DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := dialWS(t, ctx, srv.URL, token)
	defer c.Close(websocket.StatusNormalClosure, "")

	require.NoError(t, wsjson.Write(ctx, c, map[string]any{
		"type":         "ack",
		"envelope_ids": []string{"e1", "e2"},
	}))

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("AckMessages was not called for the ack frame")
	}
	assert.Equal(t, "dev-1", gotDevice) // sender from the JWT
	assert.Equal(t, []string{"e1", "e2"}, gotIDs)
}

func TestGetEnvelopeByID_AuthedOk(t *testing.T) {
	svc := &mockSvc{
		getEnvelope: func(_ context.Context, envID, devID string) (proto.Envelope, error) {
			assert.Equal(t, "env-1", envID)
			assert.Equal(t, "dev-bob", devID)
			return proto.Envelope{EnvelopeID: "env-1", RecipientDeviceID: "dev-bob", Ciphertext: []byte("hi")}, nil
		},
	}
	h := delivery.NewHandlers(svc, nil)
	r := chi.NewRouter()
	r.Get("/messages/by-id/{envelope_id}", h.GetEnvelopeByID)

	req := httptest.NewRequest(http.MethodGet, "/messages/by-id/env-1", http.NoBody).
		WithContext(ctxWithClaims("dev-bob", "acct-bob"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var got proto.Envelope
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "env-1", got.EnvelopeID)
}

func TestGetEnvelopeByID_NotRecipient_Returns404(t *testing.T) {
	svc := &mockSvc{
		getEnvelope: func(_ context.Context, _, _ string) (proto.Envelope, error) {
			return proto.Envelope{}, proto.APIError{Code: proto.ErrCodeEnvelopeNotFound, Message: "envelope not found"}
		},
	}
	h := delivery.NewHandlers(svc, nil)
	r := chi.NewRouter()
	r.Get("/messages/by-id/{envelope_id}", h.GetEnvelopeByID)

	req := httptest.NewRequest(http.MethodGet, "/messages/by-id/env-1", http.NoBody).
		WithContext(ctxWithClaims("dev-mallory", "acct-mallory"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// typingResolverFake maps every device to account "acc-<device>"; dev-1 (the
// sender) is live only while senderActive is set.
type typingResolverFake struct{ senderActive *atomic.Bool }

func (f typingResolverFake) RecipientLive(ctx context.Context, deviceID string) (bool, error) {
	_, live, err := f.AccountForDevice(ctx, deviceID)
	return live, err
}

func (f typingResolverFake) AccountForDevice(_ context.Context, deviceID string) (string, bool, error) {
	if deviceID == "dev-1" && !f.senderActive.Load() {
		return "", false, nil
	}
	return "acc-" + deviceID, true, nil
}

// genuineTypingConversation is THE 1:1 between dev-1's and dev-2's accounts.
const genuineTypingConversation = "1to1:acc-dev-1:acc-dev-2"

type typingFixture struct {
	send     func(conversationID string)
	received func() bool
	// receivedCount drains dev-2's socket and counts typing frames.
	receivedCount func() int
}

// newTypingFixture connects a receiver (dev-2) and a sender (dev-1) whose
// liveness the test controls. withResolver=false leaves the typing resolver
// unwired.
func newTypingFixture(t *testing.T, senderActive *atomic.Bool, withResolver bool) typingFixture {
	t.Helper()
	pub, priv, _ := ed25519GenForTest(t)
	h := delivery.NewHandlers(&mockSvc{}, delivery.NewHub())
	if withResolver {
		h.SetTypingResolver(typingResolverFake{senderActive: senderActive})
	}
	srv := httptest.NewServer(h.HandleWS(pub))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	token := func(dev string) string {
		return crypto.SignJWT(priv, crypto.JWTClaims{
			AccountID: "acc-" + dev, DeviceID: dev, ExpiresAt: time.Now().Add(time.Hour).Unix(),
		})
	}
	receiver := dialWS(t, ctx, srv.URL, token("dev-2"))
	t.Cleanup(func() { receiver.Close(websocket.StatusNormalClosure, "") })
	sender := dialWS(t, ctx, srv.URL, token("dev-1"))
	t.Cleanup(func() { sender.Close(websocket.StatusNormalClosure, "") })
	// Both sockets registered with the hub before the first frame.
	time.Sleep(100 * time.Millisecond)

	readOne := func() bool {
		rctx, rcancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer rcancel()
		var env proto.Envelope
		return wsjson.Read(rctx, receiver, &env) == nil && env.EnvelopeType == proto.EnvelopeTypeTyping
	}
	return typingFixture{
		send: func(conversationID string) {
			require.NoError(t, wsjson.Write(ctx, sender, map[string]any{
				"type": proto.EnvelopeTypeTyping, "conversation_id": conversationID,
				"recipient_device_id": "dev-2", "is_typing": true,
			}))
		},
		received: readOne,
		receivedCount: func() int {
			n := 0
			for readOne() {
				n++
			}
			return n
		},
	}
}

func activeSender() *atomic.Bool {
	a := &atomic.Bool{}
	a.Store(true)
	return a
}

func TestHandleWS_Typing_RelayedFromAnActiveDevice(t *testing.T) {
	f := newTypingFixture(t, activeSender(), true)

	f.send(genuineTypingConversation)

	assert.True(t, f.received())
}

func TestHandleWS_Typing_DroppedOnceTheSenderIsRevoked(t *testing.T) {
	active := activeSender()
	f := newTypingFixture(t, active, true)

	active.Store(false) // revoked after its socket opened
	f.send(genuineTypingConversation)

	assert.False(t, f.received())
}

// Spoofing: dev-1 claims a conversation it is not part of.
func TestHandleWS_Typing_DroppedForAConversationTheSenderIsNotIn(t *testing.T) {
	f := newTypingFixture(t, activeSender(), true)

	f.send("1to1:acc-dev-2:acc-dev-9")

	assert.False(t, f.received())
}

func TestHandleWS_Typing_DroppedForAGroupConversation(t *testing.T) {
	f := newTypingFixture(t, activeSender(), true)

	f.send("group:6f1c1c2e-8e2b-4a43-9a51-2f0b8d9f0c11")

	assert.False(t, f.received())
}

func TestHandleWS_Typing_DroppedWhenTheConversationIDIsOversized(t *testing.T) {
	f := newTypingFixture(t, activeSender(), true)

	f.send(genuineTypingConversation + strings.Repeat("x", 600))

	assert.False(t, f.received())
}

func TestHandleWS_Typing_ExcessFramesAreDropped(t *testing.T) {
	f := newTypingFixture(t, activeSender(), true)

	for i := 0; i < 60; i++ {
		f.send(genuineTypingConversation)
	}

	assert.Less(t, f.receivedCount(), 60)
}

func TestHandleWS_Typing_DroppedWithoutAResolver(t *testing.T) {
	f := newTypingFixture(t, activeSender(), false)

	f.send(genuineTypingConversation)

	assert.False(t, f.received())
}
