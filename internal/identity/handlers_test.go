package identity_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/identity"
	"github.com/nanb/nanb-server/internal/proto"
)

type mockSvc struct {
	republishedX25519 []byte
	republishErr      error
	createAcc      func(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error)
	lookup         func(ctx context.Context, username string) (proto.Account, error)
	chal           func(ctx context.Context, username, deviceID string) ([]byte, int64, error)
	session        func(ctx context.Context, username, deviceID string, challenge, signature []byte) (string, error)
	restoreChal    func(ctx context.Context, username string) ([]byte, int64, error)
	restoreSession func(ctx context.Context, username string, identityPubKey, challenge, signature []byte) (proto.RestoreSessionResponse, error)
	listDev        func(ctx context.Context, accountID string) ([]proto.Device, error)
	lookupByDevice func(ctx context.Context, deviceID string) (proto.Account, error)
	lookupByID     func(ctx context.Context, accountID string) (proto.Account, error)
	revokeDevice   func(ctx context.Context, accountID, deviceID string) error
	deleteAcc      func(ctx context.Context, accountID string) error
	checkUsername  func(ctx context.Context, username string) (proto.UsernameAvailability, error)
	linkDev        func(ctx context.Context, authDeviceID string, req proto.LinkDeviceRequest) (proto.LinkDeviceResponse, error)
	pendingDev     func(ctx context.Context, devicePubKey []byte) (proto.PendingDeviceResponse, error)
	updateProfile  func(ctx context.Context, accountID string, req proto.UpdateProfileRequest) error
}

func (m *mockSvc) CreateAccount(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
	return m.createAcc(ctx, req)
}
func (m *mockSvc) LookupAccount(ctx context.Context, username string) (proto.Account, error) {
	return m.lookup(ctx, username)
}
func (m *mockSvc) IssueChallenge(ctx context.Context, username, deviceID string) ([]byte, int64, error) {
	return m.chal(ctx, username, deviceID)
}
func (m *mockSvc) CompleteSession(ctx context.Context, username, deviceID string, challenge, signature []byte) (string, error) {
	return m.session(ctx, username, deviceID, challenge, signature)
}
func (m *mockSvc) IssueRestoreChallenge(ctx context.Context, username string) ([]byte, int64, error) {
	return m.restoreChal(ctx, username)
}
func (m *mockSvc) CompleteRestoreSession(ctx context.Context, username string, identityPubKey, challenge, signature, devicePubKey, x25519PubKey []byte, opts ...identity.RestoreOption) (proto.RestoreSessionResponse, error) {
	return m.restoreSession(ctx, username, identityPubKey, challenge, signature)
}
func (m *mockSvc) ListDevices(ctx context.Context, accountID string) ([]proto.Device, error) {
	return m.listDev(ctx, accountID)
}
func (m *mockSvc) SetDeviceSupportsSealed(ctx context.Context, deviceID string) error {
	return nil
}
func (m *mockSvc) RepublishDeviceX25519(ctx context.Context, deviceID string, pub []byte) error {
	m.republishedX25519 = pub
	if m.republishErr != nil {
		return m.republishErr
	}
	return nil
}
func (m *mockSvc) SetAccessKeyCommitment(ctx context.Context, accountID string, commitment []byte) error {
	return nil
}
func (m *mockSvc) LookupAccountByDevice(ctx context.Context, deviceID string) (proto.Account, error) {
	return m.lookupByDevice(ctx, deviceID)
}
func (m *mockSvc) LookupAccountByID(ctx context.Context, accountID string) (proto.Account, error) {
	if m.lookupByID == nil {
		return proto.Account{}, nil
	}
	return m.lookupByID(ctx, accountID)
}
func (m *mockSvc) RevokeDevice(ctx context.Context, accountID, deviceID string) error {
	if m.revokeDevice == nil {
		return nil
	}
	return m.revokeDevice(ctx, accountID, deviceID)
}
func (m *mockSvc) DeleteAccount(ctx context.Context, accountID string) error {
	return m.deleteAcc(ctx, accountID)
}
func (m *mockSvc) UpdateProfile(ctx context.Context, accountID string, req proto.UpdateProfileRequest) error {
	if m.updateProfile == nil {
		return nil
	}
	return m.updateProfile(ctx, accountID, req)
}
func (m *mockSvc) LinkDevice(ctx context.Context, authDeviceID string, req proto.LinkDeviceRequest) (proto.LinkDeviceResponse, error) {
	if m.linkDev == nil {
		return proto.LinkDeviceResponse{}, nil
	}
	return m.linkDev(ctx, authDeviceID, req)
}
func (m *mockSvc) PendingDevice(ctx context.Context, devicePubKey []byte) (proto.PendingDeviceResponse, error) {
	if m.pendingDev == nil {
		return proto.PendingDeviceResponse{}, nil
	}
	return m.pendingDev(ctx, devicePubKey)
}
func (m *mockSvc) CheckUsername(ctx context.Context, username string) (proto.UsernameAvailability, error) {
	return m.checkUsername(ctx, username)
}

func TestPostMyDeviceCapabilities_RepublishesX25519(t *testing.T) {
	// A device whose local sealing keypair was regenerated must be able to
	// re-publish it, or peers keep sealing to the dead key and it silently
	// receives nothing.
	svc := &mockSvc{}
	h := identity.NewHandlers(svc)

	key := bytes.Repeat([]byte{7}, 32)
	body, _ := json.Marshal(proto.SetDeviceCapabilitiesRequest{X25519PubKey: key})
	req := httptest.NewRequest(http.MethodPost, "/devices/me/capabilities", bytes.NewReader(body))
	ctx := auth.InjectClaimsForTest(req.Context(), crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})
	rec := httptest.NewRecorder()

	h.PostMyDeviceCapabilities(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, key, svc.republishedX25519)
}

func TestPostMyDeviceCapabilities_EmptyBodyStillSucceeds(t *testing.T) {
	// Older clients POST no body at all, purely to advertise sealed-receive
	// support. That must stay a 204, not become a 400.
	svc := &mockSvc{}
	h := identity.NewHandlers(svc)

	req := httptest.NewRequest(http.MethodPost, "/devices/me/capabilities", nil)
	ctx := auth.InjectClaimsForTest(req.Context(), crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})
	rec := httptest.NewRecorder()

	h.PostMyDeviceCapabilities(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Nil(t, svc.republishedX25519)
}

func TestPostAccount_HappyPath(t *testing.T) {
	svc := &mockSvc{
		createAcc: func(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
			assert.Equal(t, "nass", req.Username)
			return proto.CreateAccountResponse{AccountID: "acc-1", DeviceID: "dev-1", JWT: "jwt-token"}, nil
		},
	}
	h := identity.NewHandlers(svc)

	body, _ := json.Marshal(proto.CreateAccountRequest{Username: "nass"})
	req := httptest.NewRequest(http.MethodPost, "/accounts", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostAccount(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	var resp proto.CreateAccountResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "acc-1", resp.AccountID)
	assert.Equal(t, "jwt-token", resp.JWT)
}

func TestPostAccount_BadJSON(t *testing.T) {
	svc := &mockSvc{}
	h := identity.NewHandlers(svc)

	req := httptest.NewRequest(http.MethodPost, "/accounts", bytes.NewReader([]byte("{not-json")))
	rec := httptest.NewRecorder()

	h.PostAccount(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostAccount_UsernameTaken(t *testing.T) {
	svc := &mockSvc{
		createAcc: func(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
			return proto.CreateAccountResponse{}, proto.APIError{Code: proto.ErrCodeUsernameTaken, Message: "taken"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.CreateAccountRequest{Username: "nass"})
	req := httptest.NewRequest(http.MethodPost, "/accounts", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostAccount(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestPostAccount_UsernameOnHold(t *testing.T) {
	svc := &mockSvc{
		createAcc: func(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
			return proto.CreateAccountResponse{}, proto.APIError{Code: proto.ErrCodeUsernameOnHold, Message: "held"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.CreateAccountRequest{Username: "nass"})
	req := httptest.NewRequest(http.MethodPost, "/accounts", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostAccount(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestPostAccount_UsernameInvalid(t *testing.T) {
	svc := &mockSvc{
		createAcc: func(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
			return proto.CreateAccountResponse{}, proto.APIError{Code: proto.ErrCodeUsernameInvalid, Message: "bad"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.CreateAccountRequest{Username: "Nass"})
	req := httptest.NewRequest(http.MethodPost, "/accounts", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostAccount(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostAccount_KeyPackageInvalid(t *testing.T) {
	svc := &mockSvc{
		createAcc: func(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
			return proto.CreateAccountResponse{}, proto.APIError{Code: proto.ErrCodeKeyPackageInvalid, Message: "bad"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.CreateAccountRequest{Username: "nass"})
	req := httptest.NewRequest(http.MethodPost, "/accounts", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostAccount(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostAccount_BadSignature(t *testing.T) {
	svc := &mockSvc{
		createAcc: func(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
			return proto.CreateAccountResponse{}, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "bad"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.CreateAccountRequest{Username: "nass"})
	req := httptest.NewRequest(http.MethodPost, "/accounts", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostAccount(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostAccount_GenericInternalError(t *testing.T) {
	svc := &mockSvc{
		createAcc: func(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
			return proto.CreateAccountResponse{}, errors.New("db down")
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.CreateAccountRequest{Username: "nass"})
	req := httptest.NewRequest(http.MethodPost, "/accounts", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostAccount(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPostAccount_APIErrorInternal(t *testing.T) {
	// APIError with explicit Internal code → 500 via the mapping table.
	svc := &mockSvc{
		createAcc: func(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
			return proto.CreateAccountResponse{}, proto.APIError{Code: proto.ErrCodeInternal, Message: "boom"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.CreateAccountRequest{Username: "nass"})
	req := httptest.NewRequest(http.MethodPost, "/accounts", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostAccount(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPostChallenge_HappyPath(t *testing.T) {
	svc := &mockSvc{
		chal: func(ctx context.Context, username, deviceID string) ([]byte, int64, error) {
			assert.Equal(t, "nass", username)
			assert.Equal(t, "dev-1", deviceID)
			return []byte("a-challenge"), 1234567890, nil
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.ChallengeRequest{Username: "nass", DeviceID: "dev-1"})
	req := httptest.NewRequest(http.MethodPost, "/sessions/challenge", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostChallenge(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp proto.ChallengeResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, []byte("a-challenge"), resp.Challenge)
	assert.Equal(t, int64(1234567890), resp.ExpiresAt)
}

func TestPostChallenge_AccountNotFound(t *testing.T) {
	svc := &mockSvc{
		chal: func(ctx context.Context, username, deviceID string) ([]byte, int64, error) {
			return nil, 0, proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "x"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.ChallengeRequest{Username: "ghost", DeviceID: "dev-1"})
	req := httptest.NewRequest(http.MethodPost, "/sessions/challenge", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostChallenge(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPostChallenge_DeviceNotFound(t *testing.T) {
	svc := &mockSvc{
		chal: func(ctx context.Context, username, deviceID string) ([]byte, int64, error) {
			return nil, 0, proto.APIError{Code: proto.ErrCodeDeviceNotFound, Message: "x"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.ChallengeRequest{Username: "nass", DeviceID: "ghost"})
	req := httptest.NewRequest(http.MethodPost, "/sessions/challenge", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostChallenge(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPostChallenge_BadJSON(t *testing.T) {
	svc := &mockSvc{}
	h := identity.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodPost, "/sessions/challenge", bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()

	h.PostChallenge(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostSession_HappyPath(t *testing.T) {
	svc := &mockSvc{
		session: func(ctx context.Context, username, deviceID string, challenge, signature []byte) (string, error) {
			return "jwt-token", nil
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.SessionRequest{Username: "nass", DeviceID: "dev-1", Challenge: []byte("c"), Signature: []byte("s")})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostSession(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp proto.SessionResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "jwt-token", resp.JWT)
}

func TestGetDevices_HappyPath(t *testing.T) {
	svc := &mockSvc{
		listDev: func(ctx context.Context, accountID string) ([]proto.Device, error) {
			assert.Equal(t, "acc-1", accountID)
			return []proto.Device{
				{DeviceID: "dev-1", AccountID: "acc-1", DevicePubKey: []byte{1, 2, 3}, DisplayName: "Pixel", LinkedAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)},
				{DeviceID: "dev-2", AccountID: "acc-1", DevicePubKey: []byte{4, 5, 6}, LinkedAt: time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)},
			}, nil
		},
	}
	h := identity.NewHandlers(svc)

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	ctx := auth.InjectClaimsForTest(req.Context(), crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	h.GetDevices(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	devs := body["devices"].([]any)
	require.Len(t, devs, 2)
	first := devs[0].(map[string]any)
	assert.Equal(t, "dev-1", first["device_id"])
	assert.Equal(t, true, first["is_this_device"])
	assert.Equal(t, "Pixel", first["display_name"])
	second := devs[1].(map[string]any)
	assert.Equal(t, false, second["is_this_device"])
	_, hasName := second["display_name"]
	assert.False(t, hasName, "missing display_name should be omitted")
}

func TestGetDevices_MissingClaims(t *testing.T) {
	svc := &mockSvc{
		listDev: func(ctx context.Context, accountID string) ([]proto.Device, error) {
			t.Fatal("should not reach service when claims are missing")
			return nil, nil
		},
	}
	h := identity.NewHandlers(svc)

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	rec := httptest.NewRecorder()

	h.GetDevices(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGetDevices_PropagatesServiceError(t *testing.T) {
	svc := &mockSvc{
		listDev: func(ctx context.Context, accountID string) ([]proto.Device, error) {
			return nil, proto.APIError{Code: proto.ErrCodeInternal, Message: "boom"}
		},
	}
	h := identity.NewHandlers(svc)

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	ctx := auth.InjectClaimsForTest(req.Context(), crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	h.GetDevices(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestGetAccountByDevice_HappyPath(t *testing.T) {
	svc := &mockSvc{
		lookupByDevice: func(ctx context.Context, deviceID string) (proto.Account, error) {
			assert.Equal(t, "dev-9", deviceID)
			return proto.Account{AccountID: "acc-9", Username: "zara", IdentityPubKey: []byte{1, 2}}, nil
		},
		listDev: func(ctx context.Context, accountID string) ([]proto.Device, error) {
			return []proto.Device{{DeviceID: "dev-9", AccountID: "acc-9"}}, nil
		},
	}
	h := identity.NewHandlers(svc)

	r := chi.NewRouter()
	r.Get("/devices/{device_id}/account", h.GetAccountByDevice)
	req := httptest.NewRequest(http.MethodGet, "/devices/dev-9/account", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "zara", body["username"])
	assert.Equal(t, "acc-9", body["account_id"])
	assert.Equal(t, "dev-9", body["device_id"])
}

func TestGetAccountByDevice_NotFound(t *testing.T) {
	svc := &mockSvc{
		lookupByDevice: func(ctx context.Context, deviceID string) (proto.Account, error) {
			return proto.Account{}, proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		},
	}
	h := identity.NewHandlers(svc)

	r := chi.NewRouter()
	r.Get("/devices/{device_id}/account", h.GetAccountByDevice)
	req := httptest.NewRequest(http.MethodGet, "/devices/ghost/account", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDeleteMyAccount_HappyPath(t *testing.T) {
	svc := &mockSvc{
		deleteAcc: func(ctx context.Context, accountID string) error {
			assert.Equal(t, "acc-1", accountID)
			return nil
		},
	}
	h := identity.NewHandlers(svc)

	req := httptest.NewRequest(http.MethodDelete, "/accounts/me", nil)
	ctx := auth.InjectClaimsForTest(req.Context(), crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	h.DeleteMyAccount(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp proto.DeleteAccountResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.OK)
}

func TestDeleteMyAccount_MissingClaims(t *testing.T) {
	svc := &mockSvc{
		deleteAcc: func(ctx context.Context, accountID string) error {
			t.Fatal("should not reach service when claims are missing")
			return nil
		},
	}
	h := identity.NewHandlers(svc)

	req := httptest.NewRequest(http.MethodDelete, "/accounts/me", nil)
	rec := httptest.NewRecorder()

	h.DeleteMyAccount(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestDeleteMyAccount_PropagatesServiceError(t *testing.T) {
	svc := &mockSvc{
		deleteAcc: func(ctx context.Context, accountID string) error {
			return proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		},
	}
	h := identity.NewHandlers(svc)

	req := httptest.NewRequest(http.MethodDelete, "/accounts/me", nil)
	ctx := auth.InjectClaimsForTest(req.Context(), crypto.JWTClaims{AccountID: "acc-gone", DeviceID: "dev-1"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	h.DeleteMyAccount(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPostRestoreChallenge_HappyPath(t *testing.T) {
	svc := &mockSvc{
		restoreChal: func(ctx context.Context, username string) ([]byte, int64, error) {
			assert.Equal(t, "nass", username)
			return []byte("a-challenge"), 1234567890, nil
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.RestoreChallengeRequest{Username: "nass"})
	req := httptest.NewRequest(http.MethodPost, "/sessions/restore/challenge", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostRestoreChallenge(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp proto.ChallengeResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, []byte("a-challenge"), resp.Challenge)
}

func TestPostRestoreChallenge_BadJSON(t *testing.T) {
	svc := &mockSvc{}
	h := identity.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodPost, "/sessions/restore/challenge", bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()

	h.PostRestoreChallenge(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostRestoreChallenge_AccountNotFound(t *testing.T) {
	svc := &mockSvc{
		restoreChal: func(ctx context.Context, username string) ([]byte, int64, error) {
			return nil, 0, proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "x"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.RestoreChallengeRequest{Username: "ghost"})
	req := httptest.NewRequest(http.MethodPost, "/sessions/restore/challenge", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostRestoreChallenge(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPostRestoreSession_HappyPath(t *testing.T) {
	svc := &mockSvc{
		restoreSession: func(ctx context.Context, username string, identityPubKey, challenge, signature []byte) (proto.RestoreSessionResponse, error) {
			assert.Equal(t, "nass", username)
			return proto.RestoreSessionResponse{AccountID: "acc-1", DeviceID: "dev-1", JWT: "jwt-token"}, nil
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.RestoreSessionRequest{
		Username: "nass", IdentityPubKey: []byte("pk"), Challenge: []byte("c"), Signature: []byte("s"),
	})
	req := httptest.NewRequest(http.MethodPost, "/sessions/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostRestoreSession(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp proto.RestoreSessionResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "acc-1", resp.AccountID)
	assert.Equal(t, "dev-1", resp.DeviceID)
	assert.Equal(t, "jwt-token", resp.JWT)
}

func TestPostRestoreSession_BadJSON(t *testing.T) {
	svc := &mockSvc{}
	h := identity.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodPost, "/sessions/restore", bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()

	h.PostRestoreSession(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostRestoreSession_BadSignature(t *testing.T) {
	svc := &mockSvc{
		restoreSession: func(ctx context.Context, username string, identityPubKey, challenge, signature []byte) (proto.RestoreSessionResponse, error) {
			return proto.RestoreSessionResponse{}, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "x"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.RestoreSessionRequest{Username: "nass", IdentityPubKey: []byte("pk"), Challenge: []byte("c"), Signature: []byte("s")})
	req := httptest.NewRequest(http.MethodPost, "/sessions/restore", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostRestoreSession(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostSession_ChallengeNotFound(t *testing.T) {
	svc := &mockSvc{
		session: func(ctx context.Context, username, deviceID string, challenge, signature []byte) (string, error) {
			return "", proto.APIError{Code: proto.ErrCodeChallengeNotFound, Message: "x"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.SessionRequest{Username: "nass", DeviceID: "dev-1", Challenge: []byte("c"), Signature: []byte("s")})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostSession(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPostSession_ChallengeExpired(t *testing.T) {
	svc := &mockSvc{
		session: func(ctx context.Context, username, deviceID string, challenge, signature []byte) (string, error) {
			return "", proto.APIError{Code: proto.ErrCodeChallengeExpired, Message: "x"}
		},
	}
	h := identity.NewHandlers(svc)
	body, _ := json.Marshal(proto.SessionRequest{Username: "nass", DeviceID: "dev-1", Challenge: []byte("c"), Signature: []byte("s")})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostSession(rec, req)

	assert.Equal(t, http.StatusGone, rec.Code)
}

func TestPostSession_BadJSON(t *testing.T) {
	svc := &mockSvc{}
	h := identity.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte("garbage")))
	rec := httptest.NewRecorder()

	h.PostSession(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGetAccount_HappyPath(t *testing.T) {
	svc := &mockSvc{
		lookup: func(ctx context.Context, username string) (proto.Account, error) {
			assert.Equal(t, "nass", username)
			return proto.Account{
				AccountID:      "acc-1",
				Username:       "nass",
				IdentityPubKey: []byte{1, 2, 3, 4},
			}, nil
		},
		listDev: func(ctx context.Context, accountID string) ([]proto.Device, error) {
			assert.Equal(t, "acc-1", accountID)
			return []proto.Device{{DeviceID: "dev-1"}, {DeviceID: "dev-2"}}, nil
		},
	}
	h := identity.NewHandlers(svc)

	r := chi.NewRouter()
	r.Get("/accounts/{username}", h.GetAccount)

	req := httptest.NewRequest(http.MethodGet, "/accounts/nass", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "acc-1", resp["account_id"])
	assert.Equal(t, "nass", resp["username"])
	// The lookup must surface the peer's device_id(s) so callers can address
	// messages to a real device (server routes per device_id).
	assert.Equal(t, "dev-1", resp["device_id"])
}

func TestGetAccount_NotFound_Returns404(t *testing.T) {
	svc := &mockSvc{
		lookup: func(ctx context.Context, username string) (proto.Account, error) {
			return proto.Account{}, proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "x"}
		},
	}
	h := identity.NewHandlers(svc)
	r := chi.NewRouter()
	r.Get("/accounts/{username}", h.GetAccount)

	req := httptest.NewRequest(http.MethodGet, "/accounts/ghost", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGetUsernameAvailability_Available(t *testing.T) {
	svc := &mockSvc{
		checkUsername: func(ctx context.Context, username string) (proto.UsernameAvailability, error) {
			assert.Equal(t, "nass", username)
			return proto.UsernameAvailability{Username: username, Available: true}, nil
		},
	}
	h := identity.NewHandlers(svc)
	r := chi.NewRouter()
	r.Get("/usernames/{username}", h.GetUsernameAvailability)

	req := httptest.NewRequest(http.MethodGet, "/usernames/nass", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body proto.UsernameAvailability
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.True(t, body.Available)
	assert.Empty(t, body.Reason)
}

func TestGetUsernameAvailability_Taken_Is200NotError(t *testing.T) {
	svc := &mockSvc{
		checkUsername: func(ctx context.Context, username string) (proto.UsernameAvailability, error) {
			return proto.UsernameAvailability{Username: username, Reason: "taken"}, nil
		},
	}
	h := identity.NewHandlers(svc)
	r := chi.NewRouter()
	r.Get("/usernames/{username}", h.GetUsernameAvailability)

	req := httptest.NewRequest(http.MethodGet, "/usernames/nass", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body proto.UsernameAvailability
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.False(t, body.Available)
	assert.Equal(t, "taken", body.Reason)
}

func TestGetAccount_InvalidUsername_Returns400(t *testing.T) {
	svc := &mockSvc{
		lookup: func(ctx context.Context, username string) (proto.Account, error) {
			return proto.Account{}, proto.APIError{Code: proto.ErrCodeUsernameInvalid, Message: "bad"}
		},
	}
	h := identity.NewHandlers(svc)
	r := chi.NewRouter()
	r.Get("/accounts/{username}", h.GetAccount)

	req := httptest.NewRequest(http.MethodGet, "/accounts/AB", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGetAccount_ServiceInternalError_Returns500(t *testing.T) {
	svc := &mockSvc{
		lookup: func(ctx context.Context, username string) (proto.Account, error) {
			return proto.Account{}, errors.New("boom")
		},
	}
	h := identity.NewHandlers(svc)
	r := chi.NewRouter()
	r.Get("/accounts/{username}", h.GetAccount)

	req := httptest.NewRequest(http.MethodGet, "/accounts/nass", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestGetAccount_EmptyUsername_Returns400(t *testing.T) {
	// Calling the handler directly (not through chi) → chi.URLParam returns "".
	svc := &mockSvc{}
	h := identity.NewHandlers(svc)

	req := httptest.NewRequest(http.MethodGet, "/accounts/", nil)
	rec := httptest.NewRecorder()
	h.GetAccount(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGetAccount_HappyPath_IncludesDisplayNameAndAvatar(t *testing.T) {
	svc := &mockSvc{
		lookup: func(ctx context.Context, username string) (proto.Account, error) {
			return proto.Account{
				AccountID:      "acc-1",
				Username:       "nass",
				IdentityPubKey: []byte{1, 2, 3, 4},
				DisplayName:    "Nass",
				AvatarURL:      "https://example.com/a.png",
			}, nil
		},
		listDev: func(ctx context.Context, accountID string) ([]proto.Device, error) {
			return nil, nil // no devices → response omits device_id (still 200)
		},
	}
	h := identity.NewHandlers(svc)
	r := chi.NewRouter()
	r.Get("/accounts/{username}", h.GetAccount)

	req := httptest.NewRequest(http.MethodGet, "/accounts/nass", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "Nass", resp["display_name"])
	assert.Equal(t, "https://example.com/a.png", resp["avatar_url"])
}
