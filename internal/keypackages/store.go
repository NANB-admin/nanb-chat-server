package keypackages

import (
	"context"
	"errors"
)

// ErrEmpty is returned by PopOne when an account has no unconsumed KeyPackages.
var ErrEmpty = errors.New("keypackages: account has no available key packages")

// DevicePackage pairs a consumed KeyPackage payload with the device it was
// published by. Returned by PopOnePerDevice so a multi-device MLS inviter can
// add every device of an account as its own group leaf.
type DevicePackage struct {
	DeviceID string
	Payload  []byte
}

// ErrAccountNotFound is returned by AccountLookup when the named user
// has no account record. Surfaced upward as ErrCodeAccountNotFound.
var ErrAccountNotFound = errors.New("keypackages: account not found")

// Store abstracts persistence for KeyPackages used during MLS group
// invitations (Welcome). Each KeyPackage is consumed exactly once: a peer
// fetches it via PopOne, encrypts a Welcome to it, and the KeyPackage is
// marked consumed atomically by the same pop.
//
// Concurrency: PopOne must return distinct rows under concurrent callers.
// In the Postgres impl this is enforced via FOR UPDATE SKIP LOCKED; in the
// in-memory impl via a mutex.
type Store interface {
	// PublishBatch stores N fresh KeyPackages for the named (account, device).
	PublishBatch(ctx context.Context, accountID, deviceID string, kps [][]byte) error

	// DeleteUnconsumedByDevice drops every UNCONSUMED KeyPackage belonging to
	// deviceID. Used by a Reset publish, when the device's local MLS store was
	// recreated and its published packages' private keys no longer exist.
	//
	// Deliberately leaves CONSUMED rows alone: they are the audit trail of
	// invitations already built, and re-popping one must stay impossible.
	DeleteUnconsumedByDevice(ctx context.Context, deviceID string) error

	// PopOne atomically marks one unconsumed KeyPackage as consumed and
	// returns its payload. Returns ErrEmpty if none available.
	PopOne(ctx context.Context, accountID string) ([]byte, error)

	// PopOnePerDevice atomically consumes one unconsumed KeyPackage for EACH
	// of the account's devices that has at least one available, returning them
	// keyed by device. Returns an empty slice (not ErrEmpty) when none exist —
	// the caller decides whether a partial/empty result is fatal.
	PopOnePerDevice(ctx context.Context, accountID string) ([]DevicePackage, error)

	// PopForDevice atomically consumes up to n unconsumed KeyPackages of ONE
	// device of accountID (soonest-expiring first). Returns fewer, or none,
	// when the device has fewer, is not active, or does not belong to
	// accountID; never ErrEmpty.
	PopForDevice(ctx context.Context, accountID, deviceID string, n int) ([][]byte, error)

	// CountUnconsumed returns the number of available KeyPackages for the
	// named account. Cheap (indexed).
	CountUnconsumed(ctx context.Context, accountID string) (int, error)

	// CountUnconsumedByDevice returns the number of available KeyPackages that
	// deviceID itself published. A package only opens on the device that minted
	// it, so this is the number a device must use to decide whether to refill:
	// the account-wide count lets a sibling's spares hide a device running dry.
	CountUnconsumedByDevice(ctx context.Context, accountID, deviceID string) (int, error)
}
