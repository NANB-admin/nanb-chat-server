package identity

import (
	"context"
	"time"

	"github.com/nanb/nanb-server/internal/proto"
)

// Store abstracts persistence for the identity package.
// Implementations:
//   - StoreInMemory for unit tests
//   - StorePostgres for production
type Store interface {
	CreateAccountWithDevice(ctx context.Context, args CreateAccountArgs) error

	GetAccountByUsername(ctx context.Context, username string) (proto.Account, error)
	// GetAccountByID resolves an account id to its (non-deleted) account.
	// Backs the self-synced-Welcome peer lookup: a linked device added to an
	// MLS group learns the conversation's peer only as an account id (from the
	// 1to1 conversation id) and needs the @handle + keys to render it.
	GetAccountByID(ctx context.Context, accountID string) (proto.Account, error)
	// GetAccountByDeviceID resolves an active device to its (non-deleted)
	// account. Used by receivers to identify the sender of an envelope —
	// envelopes carry only sender_device_id.
	GetAccountByDeviceID(ctx context.Context, deviceID string) (proto.Account, error)
	GetActiveDeviceByID(ctx context.Context, deviceID string) (proto.Device, error)
	// GetActiveDeviceByAccountID returns the (single in v1) active device for
	// an account. Used by the restore flow when the client doesn't know its
	// own device_id.
	GetActiveDeviceByAccountID(ctx context.Context, accountID string) (proto.Device, error)
	// GetActiveDeviceByPubKey resolves a device by its Ed25519 pub key. Backs
	// the unauthenticated link-status poll a freshly-keyed device runs to learn
	// its server-assigned device_id once the primary authorizes the link.
	GetActiveDeviceByPubKey(ctx context.Context, devicePubKey []byte) (proto.Device, error)
	// LinkDevice inserts a new (already-authorized) device + its key packages
	// for an existing account. Backs POST /devices/link.
	LinkDevice(ctx context.Context, args LinkDeviceArgs) error
	// RevokeDevice revokes a single active device owned by accountID (sets
	// revoked_at, drops its key packages). Returns ErrNotFound when the device
	// doesn't exist, isn't owned by accountID, or is already revoked. Backs
	// DELETE /devices/{device_id}.
	RevokeDevice(ctx context.Context, accountID, deviceID string, now time.Time) error
	// RevokeOtherDevicesByAccountID revokes every active device of the account
	// EXCEPT exceptDeviceID (sets revoked_at + drops their key packages). Backs
	// recovery-phrase restore's "this phone is now my account" takeover: the
	// freshly-minted device survives, all others are kicked. A no-op (nil) when
	// there are no others.
	RevokeOtherDevicesByAccountID(ctx context.Context, accountID, exceptDeviceID string, now time.Time) error
	// DeleteKeyPackagesByDevice removes every key package belonging to a device,
	// without touching the device row. Called on recovery-phrase restore: the
	// device keeps its id but its CoreCrypto store (and thus every published
	// key package's private key) was wiped, so the old packages are dead —
	// serving them makes peers build undecryptable Welcomes. Idempotent.
	DeleteKeyPackagesByDevice(ctx context.Context, deviceID string) error
	// ListActiveDevicesByAccountID returns every active device for an account,
	// ordered by linked_at ascending. Used by the "Linked devices" settings
	// screen to render the user's device fleet.
	ListActiveDevicesByAccountID(ctx context.Context, accountID string) ([]proto.Device, error)

	// SetDeviceSupportsSealed marks a device as able to open sealed-sender
	// envelopes (capability negotiation). Idempotent.
	SetDeviceSupportsSealed(ctx context.Context, deviceID string) error

	// UpdateDeviceX25519 replaces a device's published sealing public key.
	// Idempotent; no-op for an unknown device. The caller must already have
	// authenticated as that device — this is how a device whose local keypair was
	// regenerated re-publishes it, which is the only way peers can ever seal to
	// it again.
	UpdateDeviceX25519(ctx context.Context, deviceID string, pub []byte) error

	// SetAccountUAKCommitment publishes (or rotates) the account's unidentified-
	// access-key commitment H(UAK) — sealed-sender Phase 2. ErrNotFound when the
	// account is missing/deleted.
	SetAccountUAKCommitment(ctx context.Context, accountID string, commitment []byte) error
	// GetAccountUAKCommitmentByDevice resolves an active recipient device to its
	// account id + that account's UAK commitment (nil when unidentified access is
	// not enabled). Backs the unauthenticated sealed-send authz check.
	GetAccountUAKCommitmentByDevice(ctx context.Context, deviceID string) (accountID string, commitment []byte, err error)

	// UpdateProfile sets the account's display name and/or avatar URL. A nil
	// field is left unchanged. Returns ErrNotFound for a missing/deleted account.
	UpdateProfile(ctx context.Context, accountID string, displayName, avatarURL *string) error

	HasUsernameHold(ctx context.Context, username string, now time.Time) (bool, error)

	// IdentityPubKeyInUse reports whether a non-deleted account already
	// registered this identity public key. The key is derived from the
	// recovery phrase, so a duplicate means a duplicate phrase — signup
	// rejects it (restore would otherwise be ambiguous between accounts).
	IdentityPubKeyInUse(ctx context.Context, identityPubKey []byte) (bool, error)

	// DeleteAccount soft-deletes the account: marks the row deleted (and
	// tombstones the username so the UNIQUE constraint releases the name),
	// revokes every device, drops the account's key packages, and places a
	// hold on the username until holdUntil. Returns ErrNotFound when the
	// account doesn't exist or is already deleted.
	DeleteAccount(ctx context.Context, accountID string, now, holdUntil time.Time) error

	StoreChallenge(ctx context.Context, key string, challenge []byte, expiresAt time.Time) error
	ConsumeChallenge(ctx context.Context, key string, now time.Time) ([]byte, error)
}

type CreateAccountArgs struct {
	Account     proto.Account
	Device      proto.Device
	KeyPackages [][]byte
	KPExpiresAt time.Time
}

type LinkDeviceArgs struct {
	Device      proto.Device
	KeyPackages [][]byte
	KPExpiresAt time.Time
}
