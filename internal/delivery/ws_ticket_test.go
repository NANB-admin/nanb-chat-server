package delivery_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/delivery"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTicketStore(ttl time.Duration) (*delivery.WSTicketStore, *fakeClock) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	return delivery.NewWSTicketStore(ttl, clock.Now), clock
}

var ticketClaims = crypto.JWTClaims{AccountID: "acc-1", DeviceID: "dev-1"}

func TestWSTicketStore_Redeem_ReturnsTheClaimsItWasIssuedFor(t *testing.T) {
	store, _ := newTicketStore(30 * time.Second)
	ticket, err := store.Issue(ticketClaims)
	require.NoError(t, err)

	got, ok := store.Redeem(ticket)

	require.True(t, ok)
	assert.Equal(t, ticketClaims.DeviceID, got.DeviceID)
	assert.Equal(t, ticketClaims.AccountID, got.AccountID)
}

func TestWSTicketStore_Redeem_IsSingleUse(t *testing.T) {
	store, _ := newTicketStore(30 * time.Second)
	ticket, _ := store.Issue(ticketClaims)
	_, _ = store.Redeem(ticket)

	_, ok := store.Redeem(ticket)

	assert.False(t, ok)
}

func TestWSTicketStore_Redeem_RejectsAnExpiredTicket(t *testing.T) {
	store, clock := newTicketStore(30 * time.Second)
	ticket, _ := store.Issue(ticketClaims)
	clock.Advance(31 * time.Second)

	_, ok := store.Redeem(ticket)

	assert.False(t, ok)
}

func TestWSTicketStore_Redeem_AcceptsATicketJustInsideItsLifetime(t *testing.T) {
	store, clock := newTicketStore(30 * time.Second)
	ticket, _ := store.Issue(ticketClaims)
	clock.Advance(29 * time.Second)

	_, ok := store.Redeem(ticket)

	assert.True(t, ok)
}

func TestWSTicketStore_Redeem_RejectsAnUnknownTicket(t *testing.T) {
	store, _ := newTicketStore(30 * time.Second)

	_, ok := store.Redeem("never-issued")

	assert.False(t, ok)
}

func TestWSTicketStore_Redeem_RejectsAnEmptyTicket(t *testing.T) {
	store, _ := newTicketStore(30 * time.Second)

	_, ok := store.Redeem("")

	assert.False(t, ok)
}

func TestWSTicketStore_Issue_ReturnsDistinctTickets(t *testing.T) {
	store, _ := newTicketStore(30 * time.Second)

	a, _ := store.Issue(ticketClaims)
	b, _ := store.Issue(ticketClaims)

	assert.NotEqual(t, a, b)
}

func TestWSTicketStore_Issue_ReturnsAnUnguessableTicket(t *testing.T) {
	store, _ := newTicketStore(30 * time.Second)

	ticket, _ := store.Issue(ticketClaims)

	// 32 random bytes, hex-encoded.
	assert.GreaterOrEqual(t, len(ticket), 64)
}

func TestWSTicketStore_Issue_DropsExpiredTicketsSoMemoryStaysBounded(t *testing.T) {
	store, clock := newTicketStore(30 * time.Second)
	for i := 0; i < 5; i++ {
		_, _ = store.Issue(ticketClaims)
	}
	clock.Advance(time.Minute)

	_, _ = store.Issue(ticketClaims)

	assert.Equal(t, 1, store.Pending())
}

func TestWSTicketStore_Issue_RefusesToHoldUnboundedTickets(t *testing.T) {
	store, _ := newTicketStore(30 * time.Second)
	var lastErr error
	for i := 0; i < delivery.MaxPendingWSTickets+1; i++ {
		// A distinct account each time: the global ceiling, not the per-account
		// budget, is what is under test here.
		_, lastErr = store.Issue(crypto.JWTClaims{AccountID: fmt.Sprintf("acc-%d", i)})
	}

	assert.ErrorIs(t, lastErr, delivery.ErrTooManyWSTickets)
}

func TestWSTicketStore_Issue_RateLimitsOneAccountRequestingTooFast(t *testing.T) {
	store, _ := newTicketStore(30 * time.Second)
	var lastErr error
	for i := 0; i < 100; i++ {
		_, lastErr = store.Issue(ticketClaims)
	}

	assert.ErrorIs(t, lastErr, delivery.ErrWSTicketRateLimited)
}

func TestWSTicketStore_Issue_OneAccountFloodingDoesNotBlockAnother(t *testing.T) {
	store, _ := newTicketStore(30 * time.Second)
	for i := 0; i < 100; i++ {
		_, _ = store.Issue(ticketClaims)
	}

	_, err := store.Issue(crypto.JWTClaims{AccountID: "acc-other", DeviceID: "dev-x"})

	assert.NoError(t, err)
}

func TestWSTicketStore_Issue_AccountBudgetRefillsOverTime(t *testing.T) {
	store, clock := newTicketStore(30 * time.Second)
	for i := 0; i < 100; i++ {
		_, _ = store.Issue(ticketClaims)
	}
	clock.Advance(10 * time.Second)

	_, err := store.Issue(ticketClaims)

	assert.NoError(t, err)
}
