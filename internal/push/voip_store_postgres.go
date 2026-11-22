package push

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VoipStorePostgres persists PushKit tokens in delivery_db.push_voip_tokens
// (migration 0020).
type VoipStorePostgres struct {
	pool *pgxpool.Pool
}

func NewVoipStorePostgres(pool *pgxpool.Pool) *VoipStorePostgres {
	return &VoipStorePostgres{pool: pool}
}

func (s *VoipStorePostgres) Upsert(ctx context.Context, t VoipToken) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO delivery_db.push_voip_tokens(device_id, account_id, token, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (device_id) DO UPDATE
		  SET account_id = EXCLUDED.account_id,
		      token = EXCLUDED.token,
		      updated_at = now()
	`, t.DeviceID, t.AccountID, t.Token)
	return err
}

func (s *VoipStorePostgres) GetByDeviceID(ctx context.Context, deviceID string) (VoipToken, error) {
	var t VoipToken
	err := s.pool.QueryRow(ctx, `
		SELECT device_id, account_id, token
		FROM delivery_db.push_voip_tokens
		WHERE device_id = $1
	`, deviceID).Scan(&t.DeviceID, &t.AccountID, &t.Token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return t, ErrNotFound
		}
		return t, err
	}
	return t, nil
}

func (s *VoipStorePostgres) Delete(ctx context.Context, deviceID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM delivery_db.push_voip_tokens WHERE device_id = $1`, deviceID)
	return err
}
