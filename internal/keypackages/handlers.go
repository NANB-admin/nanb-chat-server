package keypackages

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/apierr"
	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/proto"
)

// Single-use MLS key packages are a SCARCE resource: each fetch consumes one,
// and once a user's supply is drained peers can no longer add that user's
// devices to new groups until the client republishes. So the fetch endpoints
// are rate-limited both per CALLER (bounds one authenticated account's draw) and
// per TARGET (protects one victim from a distributed drain). Tuned to pass normal
// bursts — a client legitimately fetches a handful when starting chats / adding
// devices — while throttling a flood.
//
// On top of these, the service's ClaimQuota caps how many of ONE target
// account's packages ONE requester account may claim per window (see
// pair_claim_quota.go), so a single account can no longer drain a victim.
//
// Residual: many colluding accounts can still drain a victim slowly. The real
// backstop is a client-side LAST-RESORT (reusable) key package the server serves
// once single-use ones are exhausted — recommended follow-up; until then an
// exhausted fetch returns key_package_exhausted (410) and the caller retries.
const (
	kpFetchRatePerSec = 4
	kpFetchBurst      = 20
	// Cap on the per-TARGET bucket map. The target is an attacker-chosen URL
	// param (any username, even a nonexistent one), so without a cap an
	// authenticated caller could grow this map without bound by probing — a slow
	// memory DoS. At the cap we reclaim idle (fully replenished) buckets; if the
	// map is still full (many actively-throttled targets = a real distributed
	// drain) the request skips per-target tracking and relies on the caller
	// bucket rather than growing the map. See allowFetch.
	kpMaxTargetBuckets = 4096
)

type Handlers struct {
	svc *Service

	// Per-caller / per-target token buckets, created lazily. callerLim is keyed
	// on the authenticated account id, so it is bounded by the real account
	// count. targetLim is keyed on an attacker-chosen username, so it is
	// explicitly size-capped (kpMaxTargetBuckets) with idle-bucket reclamation —
	// see allowFetch.
	limMu     sync.Mutex
	callerLim map[string]*rate.Limiter
	targetLim map[string]*rate.Limiter
}

func NewHandlers(svc *Service) *Handlers {
	return &Handlers{
		svc:       svc,
		callerLim: map[string]*rate.Limiter{},
		targetLim: map[string]*rate.Limiter{},
	}
}

// allowFetch reports whether a key-package fetch by callerAccountID for
// targetUsername may proceed: BOTH the caller's and the target's buckets must
// have a token. The pre-check avoids spending one bucket's token when the other
// would deny, so a throttled request doesn't perturb the innocent party's rate.
func (h *Handlers) allowFetch(callerAccountID, targetUsername string) bool {
	h.limMu.Lock()
	defer h.limMu.Unlock()
	cl := h.callerLim[callerAccountID]
	if cl == nil {
		cl = rate.NewLimiter(rate.Limit(kpFetchRatePerSec), kpFetchBurst)
		h.callerLim[callerAccountID] = cl
	}
	tl := h.targetLim[targetUsername]
	if tl == nil {
		// Bound the per-target map (attacker-chosen key). At the cap, reclaim
		// idle buckets first — a fully-replenished limiter holds no live throttle
		// state, so dropping it loses nothing.
		if len(h.targetLim) >= kpMaxTargetBuckets {
			for k, v := range h.targetLim {
				if v.Tokens() >= float64(kpFetchBurst) {
					delete(h.targetLim, k)
				}
			}
			// Still full ⇒ many targets are actively throttled (a real
			// distributed drain). Don't grow the map further; the caller bucket
			// still bounds this request.
			if len(h.targetLim) >= kpMaxTargetBuckets {
				return cl.Allow()
			}
		}
		tl = rate.NewLimiter(rate.Limit(kpFetchRatePerSec), kpFetchBurst)
		h.targetLim[targetUsername] = tl
	}
	if cl.Tokens() < 1 || tl.Tokens() < 1 {
		return false
	}
	return cl.Allow() && tl.Allow()
}

// PostMyKeyPackages — POST /accounts/me/key-packages
func (h *Handlers) PostMyKeyPackages(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, proto.APIError{
			Code: proto.ErrCodeUnauthorized, Message: "no session",
		})
		return
	}
	var req proto.PublishKeyPackagesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, proto.APIError{
			Code: proto.ErrCodeBadRequest, Message: "bad json",
		})
		return
	}
	resp, err := h.svc.Publish(r.Context(), claims.AccountID, claims.DeviceID, req)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetKeyPackageByUsername — GET /accounts/{username}/key-package
func (h *Handlers) GetKeyPackageByUsername(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, proto.APIError{
			Code: proto.ErrCodeUnauthorized, Message: "no session",
		})
		return
	}
	username := chi.URLParam(r, "username")
	if !h.allowFetch(claims.AccountID, username) {
		writeAPIError(w, http.StatusTooManyRequests, proto.APIError{
			Code: proto.ErrCodeForbidden, Message: "rate limited",
		})
		return
	}
	resp, err := h.svc.FetchForUsername(r.Context(), claims.AccountID, username)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetDeviceKeyPackagesByUsername — GET /accounts/{username}/key-packages
// Returns one fresh KeyPackage per active device of the account, for adding
// every device of a peer to an MLS group (full multi-device membership).
func (h *Handlers) GetDeviceKeyPackagesByUsername(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, proto.APIError{
			Code: proto.ErrCodeUnauthorized, Message: "no session",
		})
		return
	}
	username := chi.URLParam(r, "username")
	if !h.allowFetch(claims.AccountID, username) {
		writeAPIError(w, http.StatusTooManyRequests, proto.APIError{
			Code: proto.ErrCodeForbidden, Message: "rate limited",
		})
		return
	}
	resp, err := h.svc.FetchAllDevicesForUsername(r.Context(), claims.AccountID, username)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetOwnDeviceKeyPackages — GET /accounts/me/devices/{deviceID}/key-packages?count=N
// Claims up to N packages of ANOTHER device of the caller's own account (see
// Service.ClaimForOwnDevice). One call, so it costs one caller-bucket token.
func (h *Handlers) GetOwnDeviceKeyPackages(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, proto.APIError{
			Code: proto.ErrCodeUnauthorized, Message: "no session",
		})
		return
	}
	deviceID := chi.URLParam(r, "deviceID")
	if _, err := uuid.Parse(deviceID); err != nil {
		writeAPIError(w, http.StatusBadRequest, proto.APIError{
			Code: proto.ErrCodeBadRequest, Message: "bad device id",
		})
		return
	}
	count := 1
	if raw := r.URL.Query().Get("count"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeAPIError(w, http.StatusBadRequest, proto.APIError{
				Code: proto.ErrCodeBadRequest, Message: "bad count",
			})
			return
		}
		count = n
	}
	// Own account only, so the target bucket is the caller's own account.
	if !h.allowFetch(claims.AccountID, "own:"+claims.AccountID) {
		writeAPIError(w, http.StatusTooManyRequests, proto.APIError{
			Code: proto.ErrCodeForbidden, Message: "rate limited",
		})
		return
	}
	resp, err := h.svc.ClaimForOwnDevice(r.Context(), claims.AccountID, claims.DeviceID, deviceID, count)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetMyKeyPackageCount — GET /accounts/me/key-packages/count
func (h *Handlers) GetMyKeyPackageCount(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusUnauthorized, proto.APIError{
			Code: proto.ErrCodeUnauthorized, Message: "no session",
		})
		return
	}
	resp, err := h.svc.Count(r.Context(), claims.AccountID, claims.DeviceID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeAPIError(w http.ResponseWriter, status int, e proto.APIError) {
	// Write the APIError at the top level ({code, message}) to match every
	// other handler (and what the client's ApiError parser expects). The old
	// {"error": {...}} wrapper left the client unable to read `code`, which
	// crashed it on a null cast and masked the real error (e.g. exhausted key
	// packages during group creation).
	writeJSON(w, status, e)
}

// writeServiceError maps APIErrors from the service layer to HTTP statuses.
func writeServiceError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrClaimQuotaExceeded) {
		// Same 429 body the fetch limiters already send.
		writeAPIError(w, http.StatusTooManyRequests, proto.APIError{
			Code: proto.ErrCodeForbidden, Message: "rate limited",
		})
		return
	}
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) {
		writeAPIError(w, http.StatusInternalServerError, apierr.Internal(err))
		return
	}
	switch apiErr.Code {
	case proto.ErrCodeAccountNotFound:
		writeAPIError(w, http.StatusNotFound, apiErr)
	case proto.ErrCodeKeyPackageExhausted:
		writeAPIError(w, http.StatusGone, apiErr)
	case proto.ErrCodeKeyPackageInvalid, proto.ErrCodeBadRequest:
		writeAPIError(w, http.StatusBadRequest, apiErr)
	default:
		writeAPIError(w, http.StatusInternalServerError, apiErr)
	}
}
