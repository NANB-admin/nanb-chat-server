package delivery

import (
	"context"
	"errors"
	"time"

	"github.com/nanb/nanb-server/internal/proto"
)

// ErrNotFound is returned by Store implementations when a requested
// record does not exist or is not visible to the caller.
var ErrNotFound = errors.New("not found")

// Store abstracts persistence for the delivery package.
// Implementations:
//   - StoreInMemory for unit tests
//   - StorePostgres for production
type Store interface {
	InsertEnvelope(ctx context.Context, env proto.Envelope, expiresAt time.Time) error

	// CatchupForDevice returns up to limit unacked envelopes for deviceID with
	// server_ts >= since, ordered by server_ts ASC.
	CatchupForDevice(ctx context.Context, deviceID string, since time.Time, limit int) ([]proto.Envelope, error)

	// AckEnvelopes marks the envelopes as acked for this device. Returns the
	// number of rows affected.
	AckEnvelopes(ctx context.Context, deviceID string, envelopeIDs []string, now time.Time) (int, error)

	// EnvelopeConsumed reports whether there is nothing left to notify
	// recipientDeviceID about for envelopeID: it has been acked (the recipient
	// pulled and decrypted it) or the row is gone (retention swept it). A
	// missing row counts as consumed — there is no message to wake anyone for.
	// Backs the push retry queue, so a retry can't buzz someone about a message
	// they already read.
	EnvelopeConsumed(ctx context.Context, envelopeID, recipientDeviceID string) (bool, error)

	// MarkReceived records that recipientDeviceID confirmed physical receipt of
	// the envelope (its wakeup push landed) WITHOUT acking it — the foreground
	// still owes a real ack once it decrypts. Returns the envelope's sender
	// device + conversation (so the caller can relay a "delivered" signal) and
	// firstTransition=true ONLY on the first confirmation, so a redelivered
	// push doesn't re-notify. The recipientDeviceID match is the authorization
	// gate: a device can only confirm envelopes addressed to it. A missing,
	// wrong-recipient, or already-confirmed envelope returns firstTransition
	// false with no error.
	MarkReceived(ctx context.Context, envelopeID, recipientDeviceID string, now time.Time) (senderDeviceID, conversationID string, firstTransition bool, err error)

	// EvictOldestForConversation deletes the oldest unacked envelopes for a
	// (recipient_account_id, conversation_id) pair so that the count drops to keep.
	// Returns the number deleted.
	EvictOldestForConversation(ctx context.Context, recipientAccountID, conversationID string, keep int) (int, error)

	// CountForConversation returns the count of unacked envelopes for a
	// (recipient_account_id, conversation_id) pair.
	CountForConversation(ctx context.Context, recipientAccountID, conversationID string) (int, error)

	// CountForDeviceConversation returns the number of unacked, unexpired
	// envelopes for a (recipient_device_id, conversation_id) pair: the
	// DEVICE-scoped mailbox cap the normal (non-sealed) path checks before
	// storing a new envelope.
	CountForDeviceConversation(ctx context.Context, recipientDeviceID, conversationID string) (int, error)

	// EvictOldestForDeviceConversation / EvictOldestForDevice ack the oldest
	// unacked envelopes so only the newest `keep` remain. NOT used on the
	// submit path any more: evicting on a sender's submit let anyone delete a
	// device's real undelivered envelopes by flooding it. A full mailbox now
	// refuses the NEW envelope instead (Service.mailboxFull).
	EvictOldestForDeviceConversation(ctx context.Context, recipientDeviceID, conversationID string, keep int) (int, error)
	EvictOldestForDevice(ctx context.Context, recipientDeviceID string, keep int) (int, error)

	// CountForDevice returns the number of unacked, unexpired envelopes for a
	// recipient device — the per-device mailbox cap for sealed envelopes, which
	// have no stored conversation to group by.
	CountForDevice(ctx context.Context, recipientDeviceID string) (int, error)

	// GetEnvelopeByID returns the envelope with the given id ONLY if it is
	// addressed to recipientDeviceID. Returns ErrNotFound otherwise (do not
	// distinguish "wrong recipient" from "missing" — same error code so
	// callers can't enumerate by trial).
	GetEnvelopeByID(ctx context.Context, envelopeID, recipientDeviceID string) (proto.Envelope, error)

	// DeleteExpiredEnvelopes hard-deletes up to limit envelopes whose
	// expires_at <= now. Returns the number deleted. Driven by the
	// retention worker.
	DeleteExpiredEnvelopes(ctx context.Context, now time.Time, limit int) (int, error)
}
