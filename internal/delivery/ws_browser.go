package delivery

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/proto"
)

// WSTicketLifetime is how long a freshly issued WebSocket ticket stays valid.
const WSTicketLifetime = 30 * time.Second

// SetWSTickets enables ticket authentication on /ws for browser clients. Optional;
// when unset, POST /ws/ticket returns 503 and /ws ignores ?ticket=.
func (h *Handlers) SetWSTickets(store *WSTicketStore) { h.tickets = store }

// SetWebOrigins allows browsers served from the given origins (for example
// "https://chat.example.org") to open /ws. Only the host[:port] of each origin is
// used, because that is what the WebSocket library compares. Entries that do not
// parse as an absolute URL are ignored. Optional; when unset the library's
// same-origin default applies, which rejects every cross-origin browser.
func (h *Handlers) SetWebOrigins(origins []string) {
	hosts := make([]string, 0, len(origins))
	for _, o := range origins {
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		hosts = append(hosts, u.Host)
	}
	h.webOriginHosts = hosts
}

type wsTicketResponse struct {
	Ticket           string `json:"ticket"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

// PostWSTicket (POST /ws/ticket, JWT-authenticated) exchanges the caller's
// session for a single-use ticket that opens exactly one WebSocket. The ticket
// travels in the /ws query string, which is safe only because it is useless
// after one use or WSTicketLifetime — unlike a bearer token it cannot be
// replayed from a log line.
func (h *Handlers) PostWSTicket(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}
	if h.tickets == nil {
		writeJSON(w, http.StatusServiceUnavailable, proto.APIError{Code: proto.ErrCodeInternal, Message: "web sessions unavailable"})
		return
	}
	ticket, err := h.tickets.Issue(claims)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrTooManyWSTickets) {
			status = http.StatusServiceUnavailable
		}
		if errors.Is(err, ErrWSTicketRateLimited) {
			status = http.StatusTooManyRequests
		}
		writeJSON(w, status, proto.APIError{Code: proto.ErrCodeInternal, Message: "could not issue ticket"})
		return
	}
	writeJSON(w, http.StatusOK, wsTicketResponse{
		Ticket:           ticket,
		ExpiresInSeconds: int(WSTicketLifetime / time.Second),
	})
}

// authenticateWS resolves the caller of a /ws handshake. A Bearer token (native
// clients) is checked first and, if present, is the ONLY credential considered —
// a bad token is never rescued by a ticket. Without one, a browser's one-time
// ?ticket= is redeemed, but only when ticket auth is enabled.
func (h *Handlers) authenticateWS(r *http.Request, jwtPubKey ed25519.PublicKey) (crypto.JWTClaims, bool) {
	if token := extractToken(r); token != "" {
		claims, err := crypto.VerifyJWT(jwtPubKey, token, time.Now())
		return claims, err == nil
	}
	if h.tickets == nil {
		return crypto.JWTClaims{}, false
	}
	return h.tickets.Redeem(r.URL.Query().Get("ticket"))
}
