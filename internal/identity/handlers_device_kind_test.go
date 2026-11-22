package identity_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/identity"
	"github.com/nanb/nanb-server/internal/proto"
)

func getDevicesBody(t *testing.T, devs []proto.Device) []map[string]any {
	t.Helper()
	svc := &mockSvc{listDev: func(_ context.Context, _ string) ([]proto.Device, error) { return devs, nil }}
	h := identity.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	req = req.WithContext(auth.InjectClaimsForTest(req.Context(), crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"}))
	rec := httptest.NewRecorder()
	h.GetDevices(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Devices []map[string]any `json:"devices"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body.Devices
}

func TestGetDevices_IncludesKind(t *testing.T) {
	out := getDevicesBody(t, []proto.Device{{DeviceID: "dev-1", Kind: "web"}})
	assert.Equal(t, "web", out[0]["kind"])
}

func TestGetDevices_EmptyKindReportsPhone(t *testing.T) {
	out := getDevicesBody(t, []proto.Device{{DeviceID: "dev-1"}})
	assert.Equal(t, "phone", out[0]["kind"])
}

func TestGetDevices_LinkedByIsNullForPrimary(t *testing.T) {
	out := getDevicesBody(t, []proto.Device{{DeviceID: "dev-1"}})
	v, present := out[0]["linked_by_device_id"]
	assert.True(t, present, "key must be present")
	assert.Nil(t, v)
}

func TestGetDevices_LinkedByIsReportedWhenSet(t *testing.T) {
	out := getDevicesBody(t, []proto.Device{{DeviceID: "dev-2", LinkedByDeviceID: "dev-1"}})
	assert.Equal(t, "dev-1", out[0]["linked_by_device_id"])
}

func TestGetDevices_ExpiresAtIsNullWhenUnset(t *testing.T) {
	out := getDevicesBody(t, []proto.Device{{DeviceID: "dev-1"}})
	v, present := out[0]["expires_at"]
	assert.True(t, present, "key must be present")
	assert.Nil(t, v)
}

func TestGetDevices_ExpiresAtIsRFC3339WhenSet(t *testing.T) {
	exp := time.Date(2026, 6, 1, 3, 4, 5, 0, time.UTC)
	out := getDevicesBody(t, []proto.Device{{DeviceID: "dev-1", ExpiresAt: &exp}})
	assert.Equal(t, "2026-06-01T03:04:05Z", out[0]["expires_at"])
}

func TestPostDeviceLink_PassesKindToService(t *testing.T) {
	var got proto.LinkDeviceRequest
	svc := &mockSvc{linkDev: func(_ context.Context, _ string, req proto.LinkDeviceRequest) (proto.LinkDeviceResponse, error) {
		got = req
		return proto.LinkDeviceResponse{DeviceID: "d"}, nil
	}}
	h := identity.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodPost, "/devices/link", strings.NewReader(`{"kind":"web"}`))
	req = req.WithContext(auth.InjectClaimsForTest(req.Context(), crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"}))
	rec := httptest.NewRecorder()
	h.PostDeviceLink(rec, req)
	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "web", got.Kind)
}
