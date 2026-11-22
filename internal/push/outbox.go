package push

import (
	"context"
	"time"
)

// OutboxItem is one wakeup push awaiting a retry: everything DispatchWakeup
// needs to rebuild the send, plus the backoff bookkeeping.
type OutboxItem struct {
	ID             int64
	DeviceID       string
	EnvelopeID     string
	ConversationID string
	PushKind       string
	SealedPayload  []byte
	Attempts       int
	NextAttemptAt  time.Time
	CreatedAt      time.Time
}

// Outbox is the durable queue of wakeup pushes whose first send failed.
//
// Enqueue is idempotent per (device, envelope): a duplicate submit refreshes the
// pending row rather than queueing a second buzz for the same message.
type Outbox interface {
	// Enqueue records a failed push for retry, or refreshes the existing row for
	// the same (device, envelope) pair.
	Enqueue(ctx context.Context, item OutboxItem) error

	// DueItems returns up to [limit] items whose next attempt is at or before
	// [now], oldest first.
	DueItems(ctx context.Context, now time.Time, limit int) ([]OutboxItem, error)

	// Reschedule bumps an item's attempt count and pushes its next attempt out
	// to [next] after a failed retry.
	Reschedule(ctx context.Context, id int64, attempts int, next time.Time) error

	// Delete drops a single item — the push finally landed, the token was proven
	// dead, or it exhausted its attempts.
	Delete(ctx context.Context, id int64) error

	// DeleteForDevice drops every queued push for a device whose token is dead,
	// so pruning the token doesn't leave a queue draining into nothing.
	DeleteForDevice(ctx context.Context, deviceID string) error

	// DeleteOlderThan drops items created at or before [cutoff] regardless of
	// attempt count — the age backstop, so a push nobody can deliver can't
	// accumulate. Returns how many went.
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int, error)
}
