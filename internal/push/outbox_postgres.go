package push

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OutboxPostgres is the production [Outbox], backed by delivery_db.push_outbox.
type OutboxPostgres struct {
	pool *pgxpool.Pool
}

func NewOutboxPostgres(pool *pgxpool.Pool) *OutboxPostgres { return &OutboxPostgres{pool: pool} }

func (o *OutboxPostgres) Enqueue(ctx context.Context, item OutboxItem) error {
	// ON CONFLICT keeps ONE pending retry per (device, envelope). A re-submitted
	// duplicate resets the schedule rather than adding a second buzz; the
	// attempt counter is deliberately kept (not reset) so a device that keeps
	// failing still ages out of the queue instead of looping forever.
	_, err := o.pool.Exec(ctx, `
		INSERT INTO delivery_db.push_outbox
		    (device_id, envelope_id, conversation_id, push_kind, sealed_payload,
		     attempts, next_attempt_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (device_id, envelope_id) DO UPDATE
		  SET conversation_id = EXCLUDED.conversation_id,
		      push_kind       = EXCLUDED.push_kind,
		      sealed_payload  = EXCLUDED.sealed_payload,
		      next_attempt_at = EXCLUDED.next_attempt_at
	`,
		item.DeviceID, item.EnvelopeID, item.ConversationID, item.PushKind,
		item.SealedPayload, item.Attempts, item.NextAttemptAt)
	return err
}

func (o *OutboxPostgres) DueItems(ctx context.Context, now time.Time, limit int) ([]OutboxItem, error) {
	rows, err := o.pool.Query(ctx, `
		SELECT id, device_id, envelope_id, conversation_id, push_kind,
		       sealed_payload, attempts, next_attempt_at, created_at
		FROM delivery_db.push_outbox
		WHERE next_attempt_at <= $1
		ORDER BY next_attempt_at ASC
		LIMIT $2
	`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []OutboxItem
	for rows.Next() {
		var it OutboxItem
		if err := rows.Scan(
			&it.ID, &it.DeviceID, &it.EnvelopeID, &it.ConversationID, &it.PushKind,
			&it.SealedPayload, &it.Attempts, &it.NextAttemptAt, &it.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (o *OutboxPostgres) Reschedule(ctx context.Context, id int64, attempts int, next time.Time) error {
	_, err := o.pool.Exec(ctx, `
		UPDATE delivery_db.push_outbox
		SET attempts = $2, next_attempt_at = $3
		WHERE id = $1
	`, id, attempts, next)
	return err
}

func (o *OutboxPostgres) Delete(ctx context.Context, id int64) error {
	_, err := o.pool.Exec(ctx, `DELETE FROM delivery_db.push_outbox WHERE id = $1`, id)
	return err
}

func (o *OutboxPostgres) DeleteForDevice(ctx context.Context, deviceID string) error {
	_, err := o.pool.Exec(ctx, `DELETE FROM delivery_db.push_outbox WHERE device_id = $1`, deviceID)
	return err
}

func (o *OutboxPostgres) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int, error) {
	tag, err := o.pool.Exec(ctx, `DELETE FROM delivery_db.push_outbox WHERE created_at <= $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
