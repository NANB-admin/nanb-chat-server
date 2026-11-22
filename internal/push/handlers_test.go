package push_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/proto"
	"github.com/nanb/nanb-server/internal/push"
)

type mockSvc struct {
	register func(ctx context.Context, accountID, deviceID string, req proto.RegisterPushTokenRequest) error
	del      func(ctx context.Context, deviceID string) error
}

func (m *mockSvc) RegisterToken(ctx context.Context, acc, dev string, req proto.RegisterPushTokenRequest) error {
	return m.register(ctx, acc, dev, req)
}

func (m *mockSvc) DeleteToken(ctx context.Context, dev string) error { return m.del(ctx, dev) }

func ctxWithClaims(deviceID, accountID string) context.Context {
	return auth.InjectClaimsForTest(context.Background(), crypto.JWTClaims{
		AccountID: accountID,
		DeviceID:  deviceID,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
}

func TestPostPushToken_HappyPath(t *testing.T) {
	svc := &mockSvc{
		register: func(ctx context.Context, acc, dev string, req proto.RegisterPushTokenRequest) error {
			assert.Equal(t, "acc-1", acc)
			assert.Equal(t, "dev-1", dev)
			assert.Equal(t, "apns", req.Platform)
			return nil
		},
	}
	h := push.NewHandlers(svc)
	body, _ := json.Marshal(proto.RegisterPushTokenRequest{Platform: "apns", Token: "raw"})
	req := httptest.NewRequest(http.MethodPost, "/devices/push-token", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostPushToken(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPostPushToken_NoClaims_Returns401(t *testing.T) {
	h := push.NewHandlers(&mockSvc{})
	body, _ := json.Marshal(proto.RegisterPushTokenRequest{})
	req := httptest.NewRequest(http.MethodPost, "/devices/push-token", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostPushToken(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostPushToken_BadJSON_Returns400(t *testing.T) {
	h := push.NewHandlers(&mockSvc{})
	req := httptest.NewRequest(http.MethodPost, "/devices/push-token", bytes.NewReader([]byte("not-json"))).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostPushToken(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostPushToken_BadRequest_FromService(t *testing.T) {
	svc := &mockSvc{
		register: func(ctx context.Context, acc, dev string, req proto.RegisterPushTokenRequest) error {
			return proto.APIError{Code: proto.ErrCodeBadRequest, Message: "x"}
		},
	}
	h := push.NewHandlers(svc)
	body, _ := json.Marshal(proto.RegisterPushTokenRequest{})
	req := httptest.NewRequest(http.MethodPost, "/devices/push-token", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostPushToken(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostPushToken_GenericError_Returns500(t *testing.T) {
	svc := &mockSvc{
		register: func(ctx context.Context, acc, dev string, req proto.RegisterPushTokenRequest) error {
			return errors.New("boom")
		},
	}
	h := push.NewHandlers(svc)
	body, _ := json.Marshal(proto.RegisterPushTokenRequest{})
	req := httptest.NewRequest(http.MethodPost, "/devices/push-token", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostPushToken(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPostPushToken_APIUnauthorized_Returns401(t *testing.T) {
	svc := &mockSvc{
		register: func(ctx context.Context, acc, dev string, req proto.RegisterPushTokenRequest) error {
			return proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "x"}
		},
	}
	h := push.NewHandlers(svc)
	body, _ := json.Marshal(proto.RegisterPushTokenRequest{})
	req := httptest.NewRequest(http.MethodPost, "/devices/push-token", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostPushToken(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostPushToken_APIInternal_Returns500(t *testing.T) {
	svc := &mockSvc{
		register: func(ctx context.Context, acc, dev string, req proto.RegisterPushTokenRequest) error {
			return proto.APIError{Code: proto.ErrCodeInternal, Message: "x"}
		},
	}
	h := push.NewHandlers(svc)
	body, _ := json.Marshal(proto.RegisterPushTokenRequest{})
	req := httptest.NewRequest(http.MethodPost, "/devices/push-token", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostPushToken(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestDeletePushToken_HappyPath(t *testing.T) {
	svc := &mockSvc{
		del: func(ctx context.Context, dev string) error {
			assert.Equal(t, "dev-1", dev)
			return nil
		},
	}
	h := push.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodDelete, "/devices/push-token", nil).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.DeletePushToken(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDeletePushToken_NoClaims_Returns401(t *testing.T) {
	h := push.NewHandlers(&mockSvc{})
	req := httptest.NewRequest(http.MethodDelete, "/devices/push-token", nil)
	rec := httptest.NewRecorder()

	h.DeletePushToken(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDeletePushToken_ServiceError_Returns500(t *testing.T) {
	svc := &mockSvc{
		del: func(ctx context.Context, dev string) error { return errors.New("boom") },
	}
	h := push.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodDelete, "/devices/push-token", nil).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.DeletePushToken(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
