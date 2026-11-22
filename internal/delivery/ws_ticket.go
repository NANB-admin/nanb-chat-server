package delivery

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/ratelimit"
)

// MaxPendingWSTickets caps how many un-redeemed tickets are held at once, so an
// authenticated client cannot grow server memory without bound by requesting
// tickets and never using them. Expired tickets are swept on every Issue, so in
// practice the live count is tiny (one per connecting browser, ~30s lifetime).
const MaxPendingWSTickets = 10_000

// Per-account ticket budget. A browser asks for one ticket per (re)connect, so a
// real user needs a handful; the burst absorbs a reconnect storm (several tabs
// waking after sleep) and the refill is far above any legitimate steady rate.
// Without a per-account bound, ONE authenticated account could fill the global
// MaxPendingWSTickets pool (a 30s hold each) and lock every other browser out
// of /ws. With it, an account holds at most ~burst + lifetime/refill tickets.
const (
	wsTicketAccountBurst  = 10
	wsTicketAccountRefill = 2 * time.Second
	wsTicketMaxAccounts   = 100_000
)

// ErrTooManyWSTickets is returned by Issue when MaxPendingWSTickets live tickets
// are already held (the global ceiling).
var ErrTooManyWSTickets = errors.New("too many pending websocket tickets")

// ErrWSTicketRateLimited is returned by Issue when ONE account has requested
// tickets faster than its own budget allows; other accounts are unaffected.
var ErrWSTicketRateLimited = errors.New("websocket ticket rate limit exceeded for account")

type wsTicket struct {
	claims  crypto.JWTClaims
	expires time.Time
}

// WSTicketStore issues short-lived, single-use tickets that let a BROWSER open
// the /ws WebSocket. Browsers cannot set an Authorization header on a WebSocket
// handshake, and a long-lived bearer token in the URL would leak into request
// logs, so a client first exchanges its JWT (over an authenticated REST call)
// for a ticket that is useless after one redemption or ~30 seconds.
//
// In-memory and per-process: fine for a single server instance. If the server
// is ever scaled horizontally, the ticket must move to a shared store.
type WSTicketStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	now     func() time.Time
	tickets map[string]wsTicket
	perAcct *ratelimit.Keyed
}

// NewWSTicketStore returns a store whose tickets live for ttl. now is injected
// so tests can control the clock.
func NewWSTicketStore(ttl time.Duration, now func() time.Time) *WSTicketStore {
	return &WSTicketStore{
		ttl:     ttl,
		now:     now,
		tickets: map[string]wsTicket{},
		perAcct: ratelimit.NewKeyed(ratelimit.KeyedConfig{
			Rate:    rate.Every(wsTicketAccountRefill),
			Burst:   wsTicketAccountBurst,
			MaxKeys: wsTicketMaxAccounts,
		}, now),
	}
}

// Issue creates a ticket bound to claims (the caller's authenticated session).
func (s *WSTicketStore) Issue(claims crypto.JWTClaims) (string, error) {
	if !s.perAcct.Allow(claims.AccountID) {
		return "", ErrWSTicketRateLimited
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	ticket := hex.EncodeToString(raw[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, t := range s.tickets {
		if !now.Before(t.expires) {
			delete(s.tickets, k)
		}
	}
	if len(s.tickets) >= MaxPendingWSTickets {
		return "", ErrTooManyWSTickets
	}
	s.tickets[ticket] = wsTicket{claims: claims, expires: now.Add(s.ttl)}
	return ticket, nil
}

// Redeem consumes a ticket and returns the claims it was issued for. It reports
// false for an unknown, already-used or expired ticket. A ticket can never be
// redeemed twice.
func (s *WSTicketStore) Redeem(ticket string) (crypto.JWTClaims, bool) {
	if ticket == "" {
		return crypto.JWTClaims{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[ticket]
	if !ok {
		return crypto.JWTClaims{}, false
	}
	delete(s.tickets, ticket)
	if !s.now().Before(t.expires) {
		return crypto.JWTClaims{}, false
	}
	return t.claims, true
}

// Pending reports how many tickets are currently held (for tests and metrics).
func (s *WSTicketStore) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tickets)
}
