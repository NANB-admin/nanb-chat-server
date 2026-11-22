package moderation

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nanb/nanb-server/internal/proto"
)

// StorePostgres is the Postgres-backed moderation report store.
type StorePostgres struct {
	pool *pgxpool.Pool
}

func NewStorePostgres(pool *pgxpool.Pool) *StorePostgres {
	return &StorePostgres{pool: pool}
}

// InsertReport writes one report row. Forwarded evidence messages are stored as
// JSONB so the schema needs no child table for what is opaque review-only data.
func (s *StorePostgres) InsertReport(ctx context.Context, r Report) error {
	messages := r.Messages
	if messages == nil {
		messages = []proto.ReportedMessage{}
	}
	msgJSON, err := json.Marshal(messages)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO moderation_db.reports(
			report_id, reporter_account_id, reporter_device_id,
			reported_account_id, reported_username, conversation_id,
			reason, note, context_messages, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`,
		r.ID, r.ReporterAccountID, r.ReporterDeviceID,
		r.ReportedAccountID, r.ReportedUsername, r.ConversationID,
		r.Reason, r.Note, msgJSON, r.CreatedAt,
	)
	return err
}
