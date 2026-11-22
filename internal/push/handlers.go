package push

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/proto"
)

type ServiceAPI interface {
	RegisterToken(ctx context.Context, accountID, deviceID string, req proto.RegisterPushTokenRequest) error
	DeleteToken(ctx context.Context, deviceID string) error
}

type Handlers struct {
	svc ServiceAPI
}

func NewHandlers(svc ServiceAPI) *Handlers { return &Handlers{svc: svc} }

func (h *Handlers) PostPushToken(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}
	var req proto.RegisterPushTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid JSON"})
		return
	}
	if err := h.svc.RegisterToken(r.Context(), claims.AccountID, claims.DeviceID, req); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.RegisterPushTokenResponse{OK: true})
}

func (h *Handlers) DeletePushToken(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}
	if err := h.svc.DeleteToken(r.Context(), claims.DeviceID); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.DeletePushTokenResponse{OK: true})
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
	case proto.ErrCodeBadRequest:
		return http.StatusBadRequest
	case proto.ErrCodeUnauthorized:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}
