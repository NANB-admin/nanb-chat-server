package media

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

func (s *StorePostgres) Insert(ctx context.Context, m proto.MediaRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO delivery_db.media_metadata(
			media_id, uploader_account_id, uploader_device_id,
			sha256, size_bytes, mime_type, object_key,
			uploaded_at, expires_at, authorized_account_ids
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`, m.MediaID, m.UploaderAccountID, m.UploaderDeviceID,
		m.SHA256, m.SizeBytes, m.MimeType, m.ObjectKey,
		m.UploadedAt, m.ExpiresAt, nilIfEmpty(m.AuthorizedAccountIDs))
	return err
}

func (s *StorePostgres) GetByID(ctx context.Context, mediaID string) (proto.MediaRecord, error) {
	var m proto.MediaRecord
	var deletedAt *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT media_id, uploader_account_id, uploader_device_id,
		       sha256, size_bytes, mime_type, object_key,
		       uploaded_at, expires_at, deleted_at, authorized_account_ids
		FROM delivery_db.media_metadata
		WHERE media_id = $1 AND deleted_at IS NULL
	`, mediaID).Scan(
		&m.MediaID, &m.UploaderAccountID, &m.UploaderDeviceID,
		&m.SHA256, &m.SizeBytes, &m.MimeType, &m.ObjectKey,
		&m.UploadedAt, &m.ExpiresAt, &deletedAt, &m.AuthorizedAccountIDs,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return m, ErrNotFound
		}
		return m, err
	}
	m.DeletedAt = deletedAt
	return m, nil
}

func (s *StorePostgres) MarkDeleted(ctx context.Context, mediaID string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE delivery_db.media_metadata SET deleted_at = $1
		WHERE media_id = $2 AND deleted_at IS NULL
	`, now, mediaID)
	return err
}

// nilIfEmpty maps an empty/nil slice to nil so pgx stores SQL NULL for the
// text[] column (legacy "open access") rather than an empty '{}' array.
func nilIfEmpty(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	return ids
}

func (s *StorePostgres) ListExpired(ctx context.Context, now time.Time, limit int) ([]proto.MediaRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT media_id, uploader_account_id, uploader_device_id,
		       sha256, size_bytes, mime_type, object_key,
		       uploaded_at, expires_at
		FROM delivery_db.media_metadata
		WHERE expires_at <= $1 AND deleted_at IS NULL
		LIMIT $2
	`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proto.MediaRecord
	for rows.Next() {
		var m proto.MediaRecord
		if err := rows.Scan(
			&m.MediaID, &m.UploaderAccountID, &m.UploaderDeviceID,
			&m.SHA256, &m.SizeBytes, &m.MimeType, &m.ObjectKey,
			&m.UploadedAt, &m.ExpiresAt,
		); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
