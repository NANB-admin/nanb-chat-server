package identity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/proto"
)

// ServiceAPI is the subset of Service the HTTP handlers depend on.
// Defined here (consumer side) per Go convention; production wires *Service.
type ServiceAPI interface {
	CreateAccount(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error)
	LookupAccount(ctx context.Context, username string) (proto.Account, error)
	CheckUsername(ctx context.Context, username string) (proto.UsernameAvailability, error)
	IssueChallenge(ctx context.Context, username, deviceID string) ([]byte, int64, error)
	CompleteSession(ctx context.Context, username, deviceID string, challenge, signature []byte) (string, error)
	IssueRestoreChallenge(ctx context.Context, username string) ([]byte, int64, error)
	CompleteRestoreSession(ctx context.Context, username string, identityPubKey, challenge, signature, devicePubKey, x25519PubKey []byte, opts ...RestoreOption) (proto.RestoreSessionResponse, error)
	ListDevices(ctx context.Context, accountID string) ([]proto.Device, error)
	LookupAccountByDevice(ctx context.Context, deviceID string) (proto.Account, error)
	LookupAccountByID(ctx context.Context, accountID string) (proto.Account, error)
	DeleteAccount(ctx context.Context, accountID string) error
	UpdateProfile(ctx context.Context, accountID string, req proto.UpdateProfileRequest) error
	LinkDevice(ctx context.Context, authDeviceID string, req proto.LinkDeviceRequest) (proto.LinkDeviceResponse, error)
	PendingDevice(ctx context.Context, devicePubKey []byte) (proto.PendingDeviceResponse, error)
	RevokeDevice(ctx context.Context, accountID, deviceID string) error
	SetDeviceSupportsSealed(ctx context.Context, deviceID string) error
	RepublishDeviceX25519(ctx context.Context, deviceID string, pub []byte) error
	SetAccessKeyCommitment(ctx context.Context, accountID string, commitment []byte) error
}

type Handlers struct {
	svc ServiceAPI
}

func NewHandlers(svc ServiceAPI) *Handlers {
	return &Handlers{svc: svc}
}

func (h *Handlers) PostAccount(w http.ResponseWriter, r *http.Request) {
	var req proto.CreateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: "bad_json", Message: "invalid JSON"})
		return
	}

	req.Username = NormalizeUsername(req.Username)
	resp, err := h.svc.CreateAccount(r.Context(), req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// GetAccount handles GET /accounts/{username}. Returns the public account
// record (account_id, username, identity_pub_key) so callers can start a chat.
// Auth-gated.
func (h *Handlers) GetAccount(w http.ResponseWriter, r *http.Request) {
	username := NormalizeUsername(chi.URLParam(r, "username"))
	if username == "" {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "username required"})
		return
	}
	acc, err := h.svc.LookupAccount(r.Context(), username)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	// Include the account's active device IDs so the caller can address
	// messages to a real device. The client routes by recipient_device_id and
	// the server delivers per-device, so without this the caller has no way to
	// learn the peer's device_id from a username lookup. Best-effort: a lookup
	// still succeeds (sans devices) if the device read fails.
	devs, _ := h.svc.ListDevices(r.Context(), acc.AccountID)
	writeJSON(w, http.StatusOK, accountResponse(acc, devs))
}

// accountResponse produces the JSON shape clients consume.
func accountResponse(a proto.Account, devices []proto.Device) map[string]any {
	out := map[string]any{
		"account_id":       a.AccountID,
		"username":         a.Username,
		"identity_pub_key": a.IdentityPubKey,
	}
	if len(devices) > 0 {
		ids := make([]string, 0, len(devices))
		for _, d := range devices {
			ids = append(ids, d.DeviceID)
		}
		// device_id = primary (first active) device, for v1 single-device
		// callers. device_ids carries the full set for future multi-device.
		out["device_id"] = ids[0]
		out["device_ids"] = ids
		// Per-device key list: multi-device clients fan out a separate
		// ratchet to each device, keyed by its own X25519 pub key. Older
		// clients ignore this and fall back to device_id + x25519_pub_key.
		devList := make([]map[string]any, 0, len(devices))
		for _, d := range devices {
			entry := map[string]any{"device_id": d.DeviceID}
			if len(d.X25519PubKey) > 0 {
				entry["x25519_pub_key"] = d.X25519PubKey
			}
			// Sealed-sender capability: senders only seal to a device that
			// advertises it can open sealed envelopes.
			entry["supports_sealed"] = d.SupportsSealed
			devList = append(devList, entry)
		}
		out["devices"] = devList
	}
	if len(a.X25519PubKey) > 0 {
		out["x25519_pub_key"] = a.X25519PubKey
	}
	if a.DisplayName != "" {
		out["display_name"] = a.DisplayName
	}
	if a.AvatarURL != "" {
		out["avatar_url"] = a.AvatarURL
	}
	return out
}

// GetUsernameAvailability handles GET /usernames/{username}. Unauthenticated
// — the signup flow runs it before any session exists, so the user learns a
// name is taken/held before saving a recovery phrase. Taken/held/invalid are
// 200s with available=false, not errors.
func (h *Handlers) GetUsernameAvailability(w http.ResponseWriter, r *http.Request) {
	username := NormalizeUsername(chi.URLParam(r, "username"))
	if username == "" {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "username required"})
		return
	}
	avail, err := h.svc.CheckUsername(r.Context(), username)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, avail)
}

func (h *Handlers) PostChallenge(w http.ResponseWriter, r *http.Request) {
	var req proto.ChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: "bad_json", Message: "invalid JSON"})
		return
	}

	chal, exp, err := h.svc.IssueChallenge(r.Context(), NormalizeUsername(req.Username), req.DeviceID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.ChallengeResponse{Challenge: chal, ExpiresAt: exp})
}

func (h *Handlers) PostSession(w http.ResponseWriter, r *http.Request) {
	var req proto.SessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: "bad_json", Message: "invalid JSON"})
		return
	}

	jwt, err := h.svc.CompleteSession(r.Context(), NormalizeUsername(req.Username), req.DeviceID, req.Challenge, req.Signature)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.SessionResponse{JWT: jwt})
}

// GetDevices returns the calling account's active devices. Auth-gated;
// reads account_id from the JWT claims so a client cannot enumerate other
// accounts' devices.
func (h *Handlers) GetDevices(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "missing claims"})
		return
	}
	devs, err := h.svc.ListDevices(r.Context(), claims.AccountID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(devs))
	for _, d := range devs {
		entry := map[string]any{
			"device_id":      d.DeviceID,
			"account_id":     d.AccountID,
			"device_pub_key": d.DevicePubKey,
			"linked_at":      d.LinkedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			"is_this_device": d.DeviceID == claims.DeviceID,
		}
		// Per-device X25519 lets a multi-device client self-sync (fan a 1:1
		// send out to its own other devices, each via its own ratchet).
		if len(d.X25519PubKey) > 0 {
			entry["x25519_pub_key"] = d.X25519PubKey
		}
		if d.DisplayName != "" {
			entry["display_name"] = d.DisplayName
		}
		entry["supports_sealed"] = d.SupportsSealed
		kind := d.Kind
		if kind == "" {
			kind = proto.DeviceKindPhone
		}
		entry["kind"] = kind
		// null (not omitted) when absent, so clients can rely on the keys.
		if d.LinkedByDeviceID != "" {
			entry["linked_by_device_id"] = d.LinkedByDeviceID
		} else {
			entry["linked_by_device_id"] = nil
		}
		if d.ExpiresAt != nil {
			entry["expires_at"] = d.ExpiresAt.UTC().Format(time.RFC3339)
		} else {
			entry["expires_at"] = nil
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// PostMyDeviceCapabilities handles POST /devices/me/capabilities. Auth-gated:
// the calling device advertises that it runs a build with the sealed-envelope
// RECEIVE path, so peers may seal messages to it (sealed-sender capability
// negotiation). Idempotent; the body is ignored — the call itself is the signal.
func (h *Handlers) PostMyDeviceCapabilities(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "missing claims"})
		return
	}
	if err := h.svc.SetDeviceSupportsSealed(r.Context(), claims.DeviceID); err != nil {
		writeAPIError(w, err)
		return
	}
	// The body is OPTIONAL: older clients POST nothing here and must keep
	// working, so an empty//absent body is success, not a 400. A body that is
	// present but malformed is still a client bug worth reporting.
	var req proto.SetDeviceCapabilitiesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid JSON"})
		return
	}
	if len(req.X25519PubKey) > 0 {
		if err := h.svc.RepublishDeviceX25519(r.Context(), claims.DeviceID, req.X25519PubKey); err != nil {
			writeAPIError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// PostMyAccessKey handles POST /accounts/me/access-key. Auth-gated: the caller
// publishes (or rotates) its account's unidentified-access-key COMMITMENT
// H(UAK) — sealed-sender Phase 2. The server stores only the commitment; the UAK
// itself is shared with contacts over the E2EE channel, never with the server
// here. Idempotent (rotation overwrites). 204 on success.
func (h *Handlers) PostMyAccessKey(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "missing claims"})
		return
	}
	var req proto.SetAccessKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: "bad_json", Message: "invalid JSON"})
		return
	}
	if err := h.svc.SetAccessKeyCommitment(r.Context(), claims.AccountID, req.Commitment); err != nil {
		writeAPIError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PostDeviceLink handles POST /devices/link. Auth-gated: the caller is an
// already-authenticated device; account_id comes from its JWT claims (via the
// authorizing device_id, so the link is bound to the caller's own account).
func (h *Handlers) PostDeviceLink(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "missing claims"})
		return
	}
	var req proto.LinkDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: "bad_json", Message: "invalid JSON"})
		return
	}
	resp, err := h.svc.LinkDevice(r.Context(), claims.DeviceID, req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// GetPendingDevice handles GET /devices/pending/{device_pub_key}.
// Unauthenticated — a freshly-keyed device has no session yet and polls this
// (keyed by its own hex Ed25519 pub key) to learn whether the primary has
// authorized the link, and if so its server-assigned device_id + account.
func (h *Handlers) GetPendingDevice(w http.ResponseWriter, r *http.Request) {
	pkHex := chi.URLParam(r, "device_pub_key")
	pk, err := hex.DecodeString(pkHex)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "device_pub_key must be hex"})
		return
	}
	resp, err := h.svc.PendingDevice(r.Context(), pk)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetAccountByDevice handles GET /devices/{device_id}/account. Resolves
// an envelope's sender_device_id to its public account record so the
// receiving client can name an unknown sender and seed the conversation.
// Auth-gated; same response shape as GET /accounts/{username}.
func (h *Handlers) GetAccountByDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "device_id required"})
		return
	}
	acc, err := h.svc.LookupAccountByDevice(r.Context(), deviceID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	// Best-effort device list, mirroring GetAccount.
	devs, _ := h.svc.ListDevices(r.Context(), acc.AccountID)
	writeJSON(w, http.StatusOK, accountResponse(acc, devs))
}

// GetAccountByID handles GET /accounts/by-id/{account_id}. Resolves an
// account id (which a linked device parses from a 1to1 conversation id) to its
// public account record so a self-synced Welcome can name the peer.
// Auth-gated; same response shape as GET /accounts/{username}.
func (h *Handlers) GetAccountByID(w http.ResponseWriter, r *http.Request) {
	accountID := chi.URLParam(r, "account_id")
	if accountID == "" {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "account_id required"})
		return
	}
	acc, err := h.svc.LookupAccountByID(r.Context(), accountID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	devs, _ := h.svc.ListDevices(r.Context(), acc.AccountID)
	writeJSON(w, http.StatusOK, accountResponse(acc, devs))
}

// DeleteMyAccount handles DELETE /accounts/me. Auth-gated; the account
// comes from the JWT claims so a caller can only ever delete itself.
func (h *Handlers) DeleteMyAccount(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "missing claims"})
		return
	}
	if err := h.svc.DeleteAccount(r.Context(), claims.AccountID); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.DeleteAccountResponse{OK: true})
}

// RevokeDevice handles DELETE /devices/{device_id}. Auth-gated; revokes one of
// the calling account's OWN other devices (freeing a device slot). Revoking the
// device the request came from is rejected — that's self-eviction, use
// DELETE /accounts/me instead.
func (h *Handlers) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "missing claims"})
		return
	}
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "device_id required"})
		return
	}
	if deviceID == claims.DeviceID {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "cannot revoke the device you are signed in on"})
		return
	}
	if err := h.svc.RevokeDevice(r.Context(), claims.AccountID, deviceID); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// PatchMe handles PATCH /accounts/me. Auth-gated; updates the calling
// account's display name / avatar URL from the JWT claims, so a caller can
// only ever edit its own profile.
func (h *Handlers) PatchMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "missing claims"})
		return
	}
	var req proto.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: "bad_json", Message: "invalid JSON"})
		return
	}
	if err := h.svc.UpdateProfile(r.Context(), claims.AccountID, req); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// PostRestoreChallenge issues a challenge for the recovery-phrase restore
// flow. Keyed by username only — the restoring client doesn't know its
// device_id yet.
func (h *Handlers) PostRestoreChallenge(w http.ResponseWriter, r *http.Request) {
	var req proto.RestoreChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: "bad_json", Message: "invalid JSON"})
		return
	}

	chal, exp, err := h.svc.IssueRestoreChallenge(r.Context(), NormalizeUsername(req.Username))
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.ChallengeResponse{Challenge: chal, ExpiresAt: exp})
}

// PostRestoreSession completes the recovery-phrase restore. The client signs
// the previously-issued challenge with the identity key it re-derived from
// the BIP-39 phrase. Returns account_id + device_id + JWT.
func (h *Handlers) PostRestoreSession(w http.ResponseWriter, r *http.Request) {
	var req proto.RestoreSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: "bad_json", Message: "invalid JSON"})
		return
	}

	var opts []RestoreOption
	if req.KeepOtherDevices {
		opts = append(opts, KeepOtherDevices())
	}
	resp, err := h.svc.CompleteRestoreSession(r.Context(), NormalizeUsername(req.Username), req.IdentityPubKey, req.Challenge, req.Signature, req.DevicePubKey, req.X25519PubKey, opts...)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, err error) {
	var apiErr proto.APIError
	if errors.As(err, &apiErr) {
		writeJSON(w, statusForCode(apiErr.Code), apiErr)
		return
	}
	writeJSON(w, http.StatusInternalServerError, proto.APIError{Code: proto.ErrCodeInternal, Message: "internal"})
}

func statusForCode(code proto.ErrorCode) int {
	switch code {
	case proto.ErrCodeUsernameTaken, proto.ErrCodeUsernameOnHold, proto.ErrCodeIdentityKeyTaken:
		return http.StatusConflict
	case proto.ErrCodeUsernameInvalid, proto.ErrCodeKeyPackageInvalid:
		return http.StatusBadRequest
	case proto.ErrCodeBadSignature:
		return http.StatusUnauthorized
	case proto.ErrCodeAccountNotFound, proto.ErrCodeDeviceNotFound, proto.ErrCodeChallengeNotFound:
		return http.StatusNotFound
	case proto.ErrCodeChallengeExpired:
		return http.StatusGone
	default:
		return http.StatusInternalServerError
	}
}
