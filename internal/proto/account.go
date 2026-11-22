package proto

import "time"

type Account struct {
	AccountID      string
	Username       string
	IdentityPubKey []byte
	// X25519 pub key for ECDH-derived shared secrets. Set by clients that
	// support v1 baseline E2EE; nil for legacy accounts.
	X25519PubKey []byte
	DisplayName  string
	AvatarURL    string
	CreatedAt    time.Time
}

type Device struct {
	DeviceID     string
	AccountID    string
	DevicePubKey []byte
	// X25519PubKey is the device's own ECDH key for the per-device ratchet.
	// For the primary device this equals the account key (migration 0012
	// backfills it); linked devices each generate their own.
	X25519PubKey []byte
	DisplayName  string
	LinkedAt     time.Time
	// SupportsSealed: the device runs a build with the sealed-envelope receive
	// path, so senders may seal to it (sealed-sender capability negotiation).
	// Populated by ListActiveDevicesByAccountID; false elsewhere/by default.
	SupportsSealed bool
	// Kind is "phone" (default) or "web" (see DeviceKind*). Empty is treated as
	// phone by readers (legacy rows / un-populated structs).
	Kind string
	// LinkedByDeviceID is the device that authorized this device's link; empty
	// for primary / signup / legacy devices (NULL in the DB).
	LinkedByDeviceID string
	// ExpiresAt, when non-nil, is the instant the device stops being active
	// (web sessions). nil = never expires. Use ActiveAt to decide liveness.
	ExpiresAt *time.Time
}

type KeyPackage struct {
	KPID      string
	AccountID string
	DeviceID  string
	Payload   []byte
	ExpiresAt time.Time
}
