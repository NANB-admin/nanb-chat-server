package delivery

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nanb/nanb-server/internal/proto"
)

type StorePostgres struct {
	pool *pgxpool.Pool
}

func NewStorePostgres(pool *pgxpool.Pool) *StorePostgres {
	return &StorePostgres{pool: pool}
}

func (s *StorePostgres) InsertEnvelope(ctx context.Context, env proto.Envelope, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO delivery_db.message_envelopes(
			envelope_id, conversation_id, sender_device_id,
			recipient_account_id, recipient_device_id,
			envelope_type, payload, server_ts, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		env.EnvelopeID, env.ConversationID, env.SenderDeviceID,
		env.RecipientAccountID, env.RecipientDeviceID,
		env.EnvelopeType, env.Ciphertext, env.ServerTS, expiresAt,
	)
	return err
}

func (s *StorePostgres) CatchupForDevice(ctx context.Context, deviceID string, since time.Time, limit int) ([]proto.Envelope, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT envelope_id, conversation_id, sender_device_id,
		       recipient_account_id, recipient_device_id,
		       envelope_type, payload, server_ts
		FROM delivery_db.message_envelopes
		WHERE recipient_device_id = $1
		  AND acked_at IS NULL
		  AND expires_at > now()
		  AND ($2::timestamptz IS NULL OR server_ts >= $2)
		ORDER BY server_ts ASC
		LIMIT $3
	`, deviceID, nullableTime(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []proto.Envelope
	for rows.Next() {
		var e proto.Envelope
		e.Version = "v1"
		if err := rows.Scan(
			&e.EnvelopeID, &e.ConversationID, &e.SenderDeviceID,
			&e.RecipientAccountID, &e.RecipientDeviceID,
			&e.EnvelopeType, &e.Ciphertext, &e.ServerTS,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *StorePostgres) AckEnvelopes(ctx context.Context, deviceID string, envelopeIDs []string, now time.Time) (int, error) {
	if len(envelopeIDs) == 0 {
		return 0, nil
	}
	// An acked envelope is DELETED, not just marked: the recipient has it, so
	// the server has no reason to keep the ciphertext (or its metadata) until
	// expiry. Every reader already treats "acked" and "gone" the same
	// (catch-up, counts and EnvelopeConsumed all filter acked_at IS NULL, and
	// MarkReceived on a missing row is a no-op). `now` is unused but kept in
	// the Store signature.
	_ = now
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM delivery_db.message_envelopes
		 WHERE recipient_device_id = $1
		   AND envelope_id = ANY($2)
		   AND acked_at IS NULL
	`, deviceID, envelopeIDs)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *StorePostgres) EnvelopeConsumed(ctx context.Context, envelopeID, recipientDeviceID string) (bool, error) {
	// One row at most (envelope_id is the PK); the recipient match is the
	// authorization gate, same as everywhere else. `true` means either acked or
	// no such row — both mean "nothing left to notify about".
	var pending bool
	err := s.pool.QueryRow(ctx, `
		SELECT true
		FROM delivery_db.message_envelopes
		WHERE envelope_id = $1
		  AND recipient_device_id = $2
		  AND acked_at IS NULL
	`, envelopeID, recipientDeviceID).Scan(&pending)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return true, nil
		}
		return false, err
	}
	return !pending, nil
}

// MarkReceived stamps received_at on the envelope addressed to
// recipientDeviceID, but only if not already stamped. The RETURNING clause
// gives the caller the sender device + conversation for the delivery-status
// relay; pgx.ErrNoRows means "no first transition" (missing, wrong recipient,
// or already received) and is reported as firstTransition=false, nil error.
// Deliberately no expires_at filter — a confirmation on a just-expired (but
// not yet swept) row is harmless and we'd rather relay than drop.
func (s *StorePostgres) MarkReceived(ctx context.Context, envelopeID, recipientDeviceID string, now time.Time) (string, string, bool, error) {
	var senderDeviceID, conversationID string
	err := s.pool.QueryRow(ctx, `
		UPDATE delivery_db.message_envelopes
		   SET received_at = $3
		 WHERE envelope_id = $1
		   AND recipient_device_id = $2
		   AND received_at IS NULL
		RETURNING sender_device_id, conversation_id
	`, envelopeID, recipientDeviceID, now).Scan(&senderDeviceID, &conversationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return senderDeviceID, conversationID, true, nil
}

// EvictOldestForConversation marks the oldest unacked envelopes for
// (recipient_account_id, conversation_id) as acked, keeping the newest
// `keep` rows in place. FIFO trim: newest stays, oldest goes.
//
// Implementation note: order DESC + OFFSET $keep yields "everything older
// than the keep-newest" — those are the rows we want to ack.
// (An ASC ordering with OFFSET would be inverted: it'd keep the OLDEST and
// evict the newest, which is exactly the opposite of FIFO trim.)
func (s *StorePostgres) EvictOldestForConversation(ctx context.Context, recipientAccountID, conversationID string, keep int) (int, error) {
	if keep <= 0 {
		// A non-positive keep would tell the OFFSET clause to return every
		// row, evicting the message we just inserted — refuse instead.
		// Service-layer config clamps to >= 1 so this guards against direct
		// misuse.
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE delivery_db.message_envelopes
		   SET acked_at = now()
		 WHERE envelope_id IN (
		   SELECT envelope_id FROM delivery_db.message_envelopes
		    WHERE recipient_account_id = $1
		      AND conversation_id = $2
		      AND acked_at IS NULL
		    ORDER BY server_ts DESC
		    OFFSET $3
		 )
	`, recipientAccountID, conversationID, keep)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *StorePostgres) CountForConversation(ctx context.Context, recipientAccountID, conversationID string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM delivery_db.message_envelopes
		 WHERE recipient_account_id = $1
		   AND conversation_id = $2
		   AND acked_at IS NULL
	`, recipientAccountID, conversationID).Scan(&count)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	return count, nil
}

// CountForDeviceConversation returns the count of unacked envelopes for a
// (recipient_device_id, conversation_id) pair — the device-scoped FIFO cap for
// the normal (non-sealed) path.
func (s *StorePostgres) CountForDeviceConversation(ctx context.Context, recipientDeviceID, conversationID string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM delivery_db.message_envelopes
		 WHERE recipient_device_id = $1
		   AND conversation_id = $2
		   AND acked_at IS NULL
		   AND expires_at > now()
	`, recipientDeviceID, conversationID).Scan(&count)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	return count, nil
}

// EvictOldestForDeviceConversation marks the oldest unacked envelopes for a
// (recipient_device_id, conversation_id) pair as acked, keeping the newest
// `keep` rows. Device-scoped so one device's flood can never evict another
// device's — or another account's — queue. Same DESC+OFFSET FIFO pattern as
// EvictOldestForConversation.
func (s *StorePostgres) EvictOldestForDeviceConversation(ctx context.Context, recipientDeviceID, conversationID string, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE delivery_db.message_envelopes
		   SET acked_at = now()
		 WHERE envelope_id IN (
		   SELECT envelope_id FROM delivery_db.message_envelopes
		    WHERE recipient_device_id = $1
		      AND conversation_id = $2
		      AND acked_at IS NULL
		    ORDER BY server_ts DESC
		    OFFSET $3
		 )
	`, recipientDeviceID, conversationID, keep)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// EvictOldestForDevice is the sealed-sender FIFO trim: per recipient device
// (sealed envelopes have no stored conversation to group by). Keeps the newest
// `keep`, acks the rest — same DESC+OFFSET pattern as EvictOldestForConversation.
func (s *StorePostgres) EvictOldestForDevice(ctx context.Context, recipientDeviceID string, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE delivery_db.message_envelopes
		   SET acked_at = now()
		 WHERE envelope_id IN (
		   SELECT envelope_id FROM delivery_db.message_envelopes
		    WHERE recipient_device_id = $1
		      AND acked_at IS NULL
		    ORDER BY server_ts DESC
		    OFFSET $2
		 )
	`, recipientDeviceID, keep)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *StorePostgres) CountForDevice(ctx context.Context, recipientDeviceID string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM delivery_db.message_envelopes
		 WHERE recipient_device_id = $1
		   AND acked_at IS NULL
		   AND expires_at > now()
	`, recipientDeviceID).Scan(&count)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	return count, nil
}

func (s *StorePostgres) GetEnvelopeByID(ctx context.Context, envID, devID string) (proto.Envelope, error) {
	const query = `
		SELECT envelope_id, conversation_id, sender_device_id, recipient_account_id,
		       recipient_device_id, envelope_type, payload, server_ts
		FROM delivery_db.message_envelopes
		WHERE envelope_id = $1 AND recipient_device_id = $2
		  AND expires_at > now()
	`
	var e proto.Envelope
	e.Version = "v1"
	err := s.pool.QueryRow(ctx, query, envID, devID).Scan(
		&e.EnvelopeID, &e.ConversationID, &e.SenderDeviceID,
		&e.RecipientAccountID, &e.RecipientDeviceID, &e.EnvelopeType,
		&e.Ciphertext, &e.ServerTS,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return proto.Envelope{}, ErrNotFound
	}
	if err != nil {
		return proto.Envelope{}, err
	}
	return e, nil
}

// DeleteExpiredEnvelopes hard-deletes up to `limit` envelopes whose
// expires_at has passed. Called by the retention worker — query-time
// filters already hide expired rows, this reclaims the disk space.
func (s *StorePostgres) DeleteExpiredEnvelopes(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 100
	}
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM delivery_db.message_envelopes
		 WHERE envelope_id IN (
		   SELECT envelope_id FROM delivery_db.message_envelopes
		    WHERE expires_at <= $1
		       OR acked_at IS NOT NULL
		    LIMIT $2
		 )
	`, now, limit)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
