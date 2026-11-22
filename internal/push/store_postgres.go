package push

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type StorePostgres struct {
	pool *pgxpool.Pool
}

func NewStorePostgres(pool *pgxpool.Pool) *StorePostgres { return &StorePostgres{pool: pool} }

func (s *StorePostgres) Upsert(ctx context.Context, t Token) error {
	// A provider token addresses ONE app install, so it can only belong to one
	// live device. When the same install comes back under a new device id
	// (signed out / erased while offline, so the old row was never deleted, then
	// signed in to another account) the stale row kept pushing at this phone:
	// the old account's traffic surfaced as phantom "New message" banners that
	// opened nothing. Claiming the token for the registering device drops it.
	_, err := s.pool.Exec(ctx, `
		WITH released AS (
		  DELETE FROM delivery_db.push_tokens
		  WHERE token = $4 AND device_id <> $1
		)
		INSERT INTO delivery_db.push_tokens(device_id, account_id, platform, token, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (device_id) DO UPDATE
		  SET account_id = EXCLUDED.account_id,
		      platform = EXCLUDED.platform,
		      token = EXCLUDED.token,
		      updated_at = now()
	`, t.DeviceID, t.AccountID, t.Platform, t.Token)
	return err
}

func (s *StorePostgres) GetByDeviceID(ctx context.Context, deviceID string) (Token, error) {
	var t Token
	err := s.pool.QueryRow(ctx, `
		SELECT device_id, account_id, platform, token
		FROM delivery_db.push_tokens
		WHERE device_id = $1
	`, deviceID).Scan(&t.DeviceID, &t.AccountID, &t.Platform, &t.Token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return t, ErrNotFound
		}
		return t, err
	}
	return t, nil
}

func (s *StorePostgres) Delete(ctx context.Context, deviceID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM delivery_db.push_tokens WHERE device_id = $1`, deviceID)
	return err
}
