package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nanb/nanb-server/internal/proto"
)

type StorePostgres struct {
	pool *pgxpool.Pool
}

func NewStorePostgres(pool *pgxpool.Pool) *StorePostgres {
	return &StorePostgres{pool: pool}
}

func (s *StorePostgres) CreateAccountWithDevice(ctx context.Context, args CreateAccountArgs) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO identity_db.accounts(account_id, username, identity_pub_key, x25519_pub_key, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, args.Account.AccountID, args.Account.Username, args.Account.IdentityPubKey, args.Account.X25519PubKey, args.Account.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			// Two unique constraints can fire here: the username UNIQUE and
			// the partial unique index on identity_pub_key (migration 0011).
			if strings.Contains(pgErr.ConstraintName, "identity_pub_key") {
				return ErrIdentityKeyExists
			}
			return ErrAlreadyExists
		}
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO identity_db.devices(device_id, account_id, device_pub_key, x25519_pub_key, display_name, linked_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, args.Device.DeviceID, args.Device.AccountID, args.Device.DevicePubKey, args.Device.X25519PubKey, args.Device.DisplayName, args.Device.LinkedAt)
	if err != nil {
		return err
	}

	for _, payload := range args.KeyPackages {
		_, err = tx.Exec(ctx, `
			INSERT INTO identity_db.key_packages(kp_id, account_id, device_id, payload, expires_at)
			VALUES ($1, $2, $3, $4, $5)
		`, uuid.NewString(), args.Account.AccountID, args.Device.DeviceID, payload, args.KPExpiresAt)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *StorePostgres) GetAccountByUsername(ctx context.Context, username string) (proto.Account, error) {
	var a proto.Account
	row := s.pool.QueryRow(ctx, `
		SELECT account_id, username, identity_pub_key, x25519_pub_key,
		       COALESCE(display_name,''), COALESCE(avatar_url,''), created_at
		FROM identity_db.accounts
		WHERE lower(username) = lower($1) AND deleted_at IS NULL
	`, username)
	if err := row.Scan(&a.AccountID, &a.Username, &a.IdentityPubKey, &a.X25519PubKey, &a.DisplayName, &a.AvatarURL, &a.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return a, ErrNotFound
		}
		return a, err
	}
	return a, nil
}

func (s *StorePostgres) GetAccountByID(ctx context.Context, accountID string) (proto.Account, error) {
	var a proto.Account
	row := s.pool.QueryRow(ctx, `
		SELECT account_id, username, identity_pub_key, x25519_pub_key,
		       COALESCE(display_name,''), COALESCE(avatar_url,''), created_at
		FROM identity_db.accounts
		WHERE account_id = $1 AND deleted_at IS NULL
	`, accountID)
	if err := row.Scan(&a.AccountID, &a.Username, &a.IdentityPubKey, &a.X25519PubKey, &a.DisplayName, &a.AvatarURL, &a.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return a, ErrNotFound
		}
		return a, err
	}
	return a, nil
}

func (s *StorePostgres) GetAccountByDeviceID(ctx context.Context, deviceID string) (proto.Account, error) {
	var a proto.Account
	row := s.pool.QueryRow(ctx, `
		SELECT a.account_id, a.username, a.identity_pub_key, a.x25519_pub_key,
		       COALESCE(a.display_name,''), COALESCE(a.avatar_url,''), a.created_at
		FROM identity_db.devices d
		JOIN identity_db.accounts a USING (account_id)
		WHERE d.device_id = $1 AND `+deviceLive("d.")+` AND a.deleted_at IS NULL
	`, deviceID)
	if err := row.Scan(&a.AccountID, &a.Username, &a.IdentityPubKey, &a.X25519PubKey, &a.DisplayName, &a.AvatarURL, &a.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return a, ErrNotFound
		}
		return a, err
	}
	return a, nil
}

func (s *StorePostgres) GetActiveDeviceByID(ctx context.Context, deviceID string) (proto.Device, error) {
	d, err := scanDevice(s.pool.QueryRow(ctx, `
		SELECT `+deviceColumns+`
		FROM identity_db.devices
		WHERE device_id = $1 AND `+deviceLive("")+`
	`, deviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

func (s *StorePostgres) ListActiveDevicesByAccountID(ctx context.Context, accountID string) ([]proto.Device, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+deviceColumns+`
		FROM identity_db.devices
		WHERE account_id = $1 AND `+deviceLive("")+`
		ORDER BY linked_at ASC, device_id ASC
	`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []proto.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// SetDeviceSupportsSealed marks a device as able to open sealed-sender
// envelopes (capability negotiation). Idempotent; no-op for an unknown device.
func (s *StorePostgres) SetDeviceSupportsSealed(ctx context.Context, deviceID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE identity_db.devices SET supports_sealed = true WHERE device_id = $1
	`, deviceID)
	return err
}

// UpdateDeviceX25519 replaces a device's published sealing public key. Only the
// device itself can reach this (the handler takes the id from the JWT), so it is
// a self-service re-publish, not an administrative override. Idempotent; a
// missing device is a no-op rather than an error, matching
// SetDeviceSupportsSealed.
func (s *StorePostgres) UpdateDeviceX25519(ctx context.Context, deviceID string, pub []byte) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE identity_db.devices SET x25519_pub_key = $2 WHERE device_id = $1
	`, deviceID, pub)
	return err
}

// SetAccountUAKCommitment publishes (or rotates) the account's unidentified-
// access-key commitment H(UAK). Returns ErrNotFound for a missing/deleted account.
func (s *StorePostgres) SetAccountUAKCommitment(ctx context.Context, accountID string, commitment []byte) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE identity_db.accounts SET uak_commitment = $2
		 WHERE account_id = $1 AND deleted_at IS NULL
	`, accountID, commitment)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetAccountUAKCommitmentByDevice resolves an active recipient device to its
// account id and that account's UAK commitment (nil/empty when the account has
// not enabled unidentified access). Backs the unauthenticated sealed-send
// authorization check. Returns ErrNotFound when the device/account is gone.
func (s *StorePostgres) GetAccountUAKCommitmentByDevice(ctx context.Context, deviceID string) (string, []byte, error) {
	var accountID string
	var commitment []byte
	row := s.pool.QueryRow(ctx, `
		SELECT a.account_id, a.uak_commitment
		FROM identity_db.devices d
		JOIN identity_db.accounts a USING (account_id)
		WHERE d.device_id = $1 AND `+deviceLive("d.")+` AND a.deleted_at IS NULL
	`, deviceID)
	if err := row.Scan(&accountID, &commitment); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, ErrNotFound
		}
		return "", nil, err
	}
	return accountID, commitment, nil
}

func (s *StorePostgres) GetActiveDeviceByAccountID(ctx context.Context, accountID string) (proto.Device, error) {
	d, err := scanDevice(s.pool.QueryRow(ctx, `
		SELECT `+deviceColumns+`
		FROM identity_db.devices
		WHERE account_id = $1 AND `+deviceLive("")+`
		ORDER BY linked_at ASC
		LIMIT 1
	`, accountID))
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// GetActiveDeviceByPubKey resolves an active device by its Ed25519 pub key.
// Backs the unauthenticated link-status poll a freshly-keyed device runs.
func (s *StorePostgres) GetActiveDeviceByPubKey(ctx context.Context, devicePubKey []byte) (proto.Device, error) {
	d, err := scanDevice(s.pool.QueryRow(ctx, `
		SELECT `+deviceColumns+`
		FROM identity_db.devices
		WHERE device_pub_key = $1 AND `+deviceLive("")+`
		ORDER BY linked_at ASC
		LIMIT 1
	`, devicePubKey))
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// LinkDevice inserts a new (already-authorized) device plus its key packages
// for an existing account, in one transaction. Backs POST /devices/link.
func (s *StorePostgres) LinkDevice(ctx context.Context, args LinkDeviceArgs) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// linked_by_device_id: NULL, not '', when there is no authorizer (uuid col).
	var linkedBy *string
	if args.Device.LinkedByDeviceID != "" {
		linkedBy = &args.Device.LinkedByDeviceID
	}
	kind := args.Device.Kind
	if kind == "" {
		kind = proto.DeviceKindPhone
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO identity_db.devices(device_id, account_id, device_pub_key, x25519_pub_key, display_name, linked_at,
		                                linked_by_device_id, kind, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, args.Device.DeviceID, args.Device.AccountID, args.Device.DevicePubKey, args.Device.X25519PubKey, args.Device.DisplayName, args.Device.LinkedAt,
		linkedBy, kind, args.Device.ExpiresAt)
	if err != nil {
		return err
	}

	for _, payload := range args.KeyPackages {
		_, err = tx.Exec(ctx, `
			INSERT INTO identity_db.key_packages(kp_id, account_id, device_id, payload, expires_at)
			VALUES ($1, $2, $3, $4, $5)
		`, uuid.NewString(), args.Device.AccountID, args.Device.DeviceID, payload, args.KPExpiresAt)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *StorePostgres) UpdateProfile(ctx context.Context, accountID string, displayName, avatarURL *string) error {
	// COALESCE keeps the existing value when the arg is NULL (field omitted);
	// a non-null empty string clears it.
	tag, err := s.pool.Exec(ctx, `
		UPDATE identity_db.accounts
		   SET display_name = COALESCE($2, display_name),
		       avatar_url   = COALESCE($3, avatar_url)
		 WHERE account_id = $1 AND deleted_at IS NULL
	`, accountID, displayName, avatarURL)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *StorePostgres) DeleteAccount(ctx context.Context, accountID string, now, holdUntil time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Read the username first (FOR UPDATE locks the row) — the tombstone
	// rename below destroys it, and the hold must be keyed by the original.
	var username string
	err = tx.QueryRow(ctx, `
		SELECT username FROM identity_db.accounts
		WHERE account_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`, accountID).Scan(&username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	// Tombstone the username ('deleted:' contains a colon so it can never
	// collide with a real username) — accounts.username is UNIQUE across
	// deleted rows too, so without the rename the name could never be
	// re-registered after the hold expires.
	_, err = tx.Exec(ctx, `
		UPDATE identity_db.accounts
		SET deleted_at = $2, username = 'deleted:' || account_id::text
		WHERE account_id = $1
	`, accountID, now)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		UPDATE identity_db.devices SET revoked_at = $2
		WHERE account_id = $1 AND revoked_at IS NULL
	`, accountID, now)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		DELETE FROM identity_db.key_packages WHERE account_id = $1
	`, accountID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO identity_db.username_holds(username, released_at)
		VALUES (lower($1), $2)
		ON CONFLICT (username) DO UPDATE SET released_at = EXCLUDED.released_at
	`, username, holdUntil)
	if err != nil {
		return err
	}

	// Cross-schema cleanup (same database, same transaction): push tokens
	// are dead weight once every device is revoked, and undelivered
	// envelopes addressed to the account will never be fetched again.
	_, err = tx.Exec(ctx, `
		DELETE FROM delivery_db.push_tokens WHERE account_id = $1
	`, accountID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		DELETE FROM delivery_db.message_envelopes WHERE recipient_account_id = $1
	`, accountID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *StorePostgres) RevokeDevice(ctx context.Context, accountID, deviceID string, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		UPDATE identity_db.devices SET revoked_at = $3
		WHERE device_id = $2 AND account_id = $1 AND revoked_at IS NULL
	`, accountID, deviceID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	// Its key packages are dead weight once the device is revoked — nobody
	// should invite a revoked device into a group.
	if _, err := tx.Exec(ctx, `
		DELETE FROM identity_db.key_packages WHERE device_id = $1
	`, deviceID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RevokeOtherDevicesByAccountID revokes every active device of the account
// except exceptDeviceID and deletes their (now-dead) key packages, in one
// transaction. Backs the recovery-phrase takeover.
func (s *StorePostgres) RevokeOtherDevicesByAccountID(ctx context.Context, accountID, exceptDeviceID string, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		UPDATE identity_db.devices SET revoked_at = $3
		WHERE account_id = $1 AND device_id <> $2 AND revoked_at IS NULL
		RETURNING device_id
	`, accountID, exceptDeviceID, now)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// Their key packages are dead weight once revoked — nobody should invite a
	// revoked device into a group.
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `DELETE FROM identity_db.key_packages WHERE device_id = $1`, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *StorePostgres) DeleteKeyPackagesByDevice(ctx context.Context, deviceID string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM identity_db.key_packages WHERE device_id = $1
	`, deviceID)
	return err
}

func (s *StorePostgres) IdentityPubKeyInUse(ctx context.Context, identityPubKey []byte) (bool, error) {
	var inUse bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM identity_db.accounts
			WHERE identity_pub_key = $1 AND deleted_at IS NULL
		)
	`, identityPubKey).Scan(&inUse)
	return inUse, err
}

func (s *StorePostgres) HasUsernameHold(ctx context.Context, username string, now time.Time) (bool, error) {
	var releasedAt time.Time
	row := s.pool.QueryRow(ctx, `
		SELECT released_at FROM identity_db.username_holds WHERE username = lower($1)
	`, username)
	if err := row.Scan(&releasedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return now.Before(releasedAt), nil
}

// challengeSweepBatch bounds how many expired challenges one StoreChallenge
// call deletes.
const challengeSweepBatch = 100

// StoreChallenge inserts one challenge. Each challenge has its own key (see
// identity/challenge_keys.go), so nothing ever overwrites a pending one — which
// also means abandoned challenges are not replaced, so each insert also sweeps
// a batch of expired rows to keep the table at roughly "challenges issued in
// the last lifetime". SKIP LOCKED: concurrent inserts never queue behind each
// other's sweep.
func (s *StorePostgres) StoreChallenge(ctx context.Context, key string, challenge []byte, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		WITH swept AS (
			DELETE FROM identity_db.session_challenges
			 WHERE challenge_key IN (
			   SELECT challenge_key FROM identity_db.session_challenges
			    WHERE expires_at < now()
			    LIMIT $4
			    FOR UPDATE SKIP LOCKED
			 )
		)
		INSERT INTO identity_db.session_challenges(challenge_key, challenge, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (challenge_key) DO UPDATE
		  SET challenge = EXCLUDED.challenge,
		      expires_at = EXCLUDED.expires_at
	`, key, challenge, expiresAt, challengeSweepBatch)
	return err
}

func (s *StorePostgres) ConsumeChallenge(ctx context.Context, key string, now time.Time) ([]byte, error) {
	var challenge []byte
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx, `
		DELETE FROM identity_db.session_challenges
		WHERE challenge_key = $1
		RETURNING challenge, expires_at
	`, key).Scan(&challenge, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if now.After(expiresAt) {
		return nil, ErrChallengeStale
	}
	return challenge, nil
}
