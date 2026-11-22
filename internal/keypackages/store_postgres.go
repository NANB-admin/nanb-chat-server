package keypackages

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StorePostgres uses the existing identity_db.key_packages table
// (migration 0005). Adds nothing schema-wise; PopOne relies on the
// 'consumed_at IS NULL' filter against the kp_claim_idx.
type StorePostgres struct {
	pool *pgxpool.Pool
}

func NewStorePostgres(pool *pgxpool.Pool) *StorePostgres {
	return &StorePostgres{pool: pool}
}

func (s *StorePostgres) PublishBatch(ctx context.Context, accountID, deviceID string, kps [][]byte) error {
	if len(kps) == 0 {
		return nil
	}
	const sql = `
		INSERT INTO identity_db.key_packages (kp_id, account_id, device_id, payload, expires_at)
		VALUES ($1, $2, $3, $4, now() + interval '30 days')
	`
	batch := &pgx.Batch{}
	for _, kp := range kps {
		batch.Queue(sql, uuid.New(), accountID, deviceID, kp)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range kps {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func (s *StorePostgres) DeleteUnconsumedByDevice(ctx context.Context, deviceID string) error {
	// consumed_at IS NULL only — a consumed row records an invitation that was
	// already built against this device and must never become poppable again.
	const sql = `
		DELETE FROM identity_db.key_packages
		WHERE device_id = $1 AND consumed_at IS NULL
	`
	_, err := s.pool.Exec(ctx, sql, deviceID)
	return err
}

// activeDeviceSQL restricts key_packages rows to devices that are still active
// (not revoked, not expired). Revocation also deletes a device's packages, but
// EXPIRY (web devices) does not, so fetches must exclude expired devices'
// packages explicitly or a sender would build a Welcome for a dead device. Same
// predicate as identity.deviceLive (kept inline: keypackages must not import
// identity).
const activeDeviceSQL = `device_id IN (
				SELECT device_id FROM identity_db.devices
				WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
			)`

func (s *StorePostgres) PopOne(ctx context.Context, accountID string) ([]byte, error) {
	const sql = `
		UPDATE identity_db.key_packages SET consumed_at = now()
		WHERE kp_id = (
			SELECT kp_id FROM identity_db.key_packages
			WHERE account_id = $1
			  AND consumed_at IS NULL
			  AND expires_at > now()
			  AND `+activeDeviceSQL+`
			ORDER BY expires_at ASC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING payload
	`
	var payload []byte
	err := s.pool.QueryRow(ctx, sql, accountID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEmpty
	}
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func (s *StorePostgres) PopOnePerDevice(ctx context.Context, accountID string) ([]DevicePackage, error) {
	// DISTINCT ON (device_id) picks the soonest-expiring unconsumed package for
	// each device in one statement, and the enclosing UPDATE marks exactly
	// those rows consumed atomically. (FOR UPDATE SKIP LOCKED can't combine
	// with DISTINCT, but per-device migration fetches are low-frequency and
	// devices publish packages in batches of 100, so contention is a non-issue.)
	const sql = `
		UPDATE identity_db.key_packages SET consumed_at = now()
		WHERE kp_id IN (
			SELECT DISTINCT ON (device_id) kp_id
			FROM identity_db.key_packages
			WHERE account_id = $1
			  AND consumed_at IS NULL
			  AND expires_at > now()
			  AND `+activeDeviceSQL+`
			ORDER BY device_id, expires_at ASC
		)
		RETURNING device_id::text, payload
	`
	rows, err := s.pool.Query(ctx, sql, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DevicePackage
	for rows.Next() {
		var dp DevicePackage
		if err := rows.Scan(&dp.DeviceID, &dp.Payload); err != nil {
			return nil, err
		}
		out = append(out, dp)
	}
	return out, rows.Err()
}

func (s *StorePostgres) PopForDevice(ctx context.Context, accountID, deviceID string, n int) ([][]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	// account_id AND device_id: a caller can only ever reach its own account's
	// devices, whatever device id it names.
	const sql = `
		UPDATE identity_db.key_packages SET consumed_at = now()
		WHERE kp_id IN (
			SELECT kp_id FROM identity_db.key_packages
			WHERE account_id = $1
			  AND device_id = $2
			  AND consumed_at IS NULL
			  AND expires_at > now()
			  AND ` + activeDeviceSQL + `
			ORDER BY expires_at ASC
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		RETURNING payload
	`
	rows, err := s.pool.Query(ctx, sql, accountID, deviceID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		out = append(out, payload)
	}
	return out, rows.Err()
}

func (s *StorePostgres) CountUnconsumed(ctx context.Context, accountID string) (int, error) {
	const sql = `
		SELECT COUNT(*) FROM identity_db.key_packages
		WHERE account_id = $1 AND consumed_at IS NULL AND expires_at > now()
	`
	var n int
	err := s.pool.QueryRow(ctx, sql, accountID).Scan(&n)
	return n, err
}

func (s *StorePostgres) CountUnconsumedByDevice(ctx context.Context, accountID, deviceID string) (int, error) {
	const sql = `
		SELECT COUNT(*) FROM identity_db.key_packages
		WHERE account_id = $1 AND device_id = $2
		  AND consumed_at IS NULL AND expires_at > now()
	`
	var n int
	err := s.pool.QueryRow(ctx, sql, accountID, deviceID).Scan(&n)
	return n, err
}
