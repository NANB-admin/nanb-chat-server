package moderation

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/proto"
	"github.com/nanb/nanb-server/internal/ratelimit"
)

// Filing a report is a rare, deliberate human action — a user taps through a
// menu, picks a reason, and submits; a handful across a whole session is a lot.
// Every accepted report writes a moderation-queue row AND fires an alert email,
// so without a bound one authenticated account could flood both the DB and the
// alert inbox. A per-account token bucket lets a user file a burst
// back-to-back (e.g. reporting several accounts after a spam wave) then refills
// at ~10/hour; a scripted flood is clamped to that trickle and gets 429. This
// is moderation traffic, not message traffic, so it is deliberately tight.
// Buckets live in the shared ratelimit.Keyed (bounded memory, idle ones swept).
const (
	reportBurst       = 10
	reportRefillEvery = 6 * time.Minute // 10 reports/hour sustained
	reportMaxAccounts = 100_000
)

// Handlers serves the report endpoint.
type Handlers struct {
	svc *Service

	// Per-reporter-account token buckets, created lazily on first report.
	acctLim *ratelimit.Keyed
}

func NewHandlers(svc *Service) *Handlers {
	return &Handlers{svc: svc, acctLim: ratelimit.NewKeyed(ratelimit.KeyedConfig{
		Rate:    rate.Every(reportRefillEvery),
		Burst:   reportBurst,
		MaxKeys: reportMaxAccounts,
	}, nil)}
}

// allowReport reports whether reporterAccountID's bucket has a token to spend on
// a new report, consuming one when it does.
func (h *Handlers) allowReport(reporterAccountID string) bool {
	return h.acctLim.Allow(reporterAccountID)
}

// PostReport handles POST /reports. Authenticated: the reporter is taken from
// the JWT claims, never the body.
func (h *Handlers) PostReport(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "missing claims"})
		return
	}
	// Bound the per-account report rate BEFORE any decode / DB write / notify, so
	// a flood can't drive the moderation queue or the alert inbox. 429 → the
	// client backs off; a genuine burst is still admitted (see reportBurst).
	if !h.allowReport(claims.AccountID) {
		writeJSON(w, http.StatusTooManyRequests, proto.APIError{Code: proto.ErrCodeForbidden, Message: "rate limited"})
		return
	}
	var req proto.ReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid JSON"})
		return
	}
	resp, err := h.svc.CreateReport(r.Context(), claims.AccountID, claims.DeviceID, req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
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
	case proto.ErrCodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case proto.ErrCodeUnauthorized:
		return http.StatusUnauthorized
	case proto.ErrCodeForbidden:
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}
