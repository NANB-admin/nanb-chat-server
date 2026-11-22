// Package turn issues short-lived WebRTC TURN credentials for 1:1 calls,
// using coturn's use-auth-secret (TURN REST) scheme so the static secret never
// leaves the server. The relay itself only ever forwards encrypted SRTP — the
// server holds no media keys (see docs/voice-calls-design.md).
package turn

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is required by the coturn use-auth-secret spec
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/proto"
	"github.com/nanb/nanb-server/internal/ratelimit"
)

// Config holds the coturn use-auth-secret parameters. Secret + URLs come from
// the environment; TTL bounds how long an issued credential is valid.
type Config struct {
	Secret string           // shared with coturn (static-auth-secret)
	URLs   []string         // turn(s):/stun: URIs handed to the client (default relay)
	// URLsEurope, when set, is handed instead of URLs to viewers whose country is
	// nearer to the Frankfurt relay (see nearEurope). It must share Secret.
	URLsEurope []string
	TTL    time.Duration    // credential lifetime
	Now    func() time.Time // injectable clock; defaults to time.Now
}

type Handlers struct {
	cfg     Config
	minting *ratelimit.Keyed // per-account credential-mint budget
}

func NewHandlers(cfg Config) *Handlers {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	return &Handlers{cfg: cfg, minting: newMintLimiter(cfg.Now)}
}

// Enabled reports whether credentials can be issued (a secret and at least one
// URL are configured). When disabled the endpoint returns 503 and the client
// falls back to direct/STUN candidates.
func (h *Handlers) Enabled() bool {
	return h.cfg.Secret != "" && len(h.cfg.URLs) > 0
}

// GetCredentials issues a short-lived TURN credential bound to the caller's
// account using coturn's use-auth-secret scheme:
//
//	username   = "<expiry-unix>:<opaque-id>"   (opaque-id = HMAC of the account
//	             id, NOT the account id — see opaqueID / expiryFor)
//	credential = base64(HMAC-SHA1(secret, username))
func (h *Handlers) GetCredentials(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}
	if !h.Enabled() {
		writeJSON(w, http.StatusServiceUnavailable, proto.APIError{Code: proto.ErrCodeInternal, Message: "TURN not configured"})
		return
	}
	if !h.minting.Allow(claims.AccountID) {
		writeJSON(w, http.StatusTooManyRequests, proto.APIError{Code: proto.ErrCodeForbidden, Message: "rate limited"})
		return
	}
	username, credential, remaining := h.credential(claims.AccountID)
	writeJSON(w, http.StatusOK, proto.TurnCredentialsResponse{
		Username:   username,
		Credential: credential,
		TTL:        int(remaining.Seconds()),
		URLs:       h.urlsFor(r),
	})
}

// urlsFor picks the relay list for the requester: the Frankfurt relay for
// viewers in nearEuropeCountries (CloudFront adds their country as
// CloudFront-Viewer-Country), the default relay otherwise.
func (h *Handlers) urlsFor(r *http.Request) []string {
	if len(h.cfg.URLsEurope) > 0 && nearEurope(r.Header.Get("CloudFront-Viewer-Country")) {
		return h.cfg.URLsEurope
	}
	return h.cfg.URLs
}

// credential computes the (username, credential) pair for accountID under the
// configured secret + TTL, plus how long it stays valid (>= the configured TTL;
// the expiry is rounded up to a step so one account's credentials in a step
// share a username). Pure given the clock — unit-tested via GetCredentials.
func (h *Handlers) credential(accountID string) (username, credential string, remaining time.Duration) {
	now := h.cfg.Now()
	expiry := expiryFor(now, h.cfg.TTL)
	username = strconv.FormatInt(expiry.Unix(), 10) + ":" + opaqueID(h.cfg.Secret, accountID, expiry)
	mac := hmac.New(sha1.New, []byte(h.cfg.Secret))
	mac.Write([]byte(username))
	credential = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return username, credential, expiry.Sub(now)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
