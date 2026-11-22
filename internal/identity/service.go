package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/nanb/nanb-server/internal/apierr"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/proto"
)

// Defaults for the configurable lifetimes — see ServiceDeps. Kept as
// exported constants so cmd/server can wire them as the upper bound when
// reading the corresponding env vars (operators can lower them but never
// raise them past the default).
const (
	DefaultChallengeLifetime  = 2 * time.Minute
	DefaultKeyPackageLifetime = 30 * 24 * time.Hour
	// DefaultWebDeviceLifetime is how long a web (browser) device stays active
	// after being linked, unless NANB_WEB_DEVICE_LIFETIME_DAYS says otherwise.
	DefaultWebDeviceLifetime = 30 * 24 * time.Hour

	// UsernameHoldDuration is the cool-down before a deleted account's
	// username can be re-registered (spec §account lifecycle: 30 days).
	UsernameHoldDuration = 30 * 24 * time.Hour

	// MaxKeyPackagesPerRequest / MaxKeyPackageBlobSize bound the key-package
	// batch a client may hand the account-create / device-link paths, matching
	// keypackages.Publish (MaxPerBatch / MaxBlobSize). Without these an
	// unauthenticated POST /accounts (or an authed link) could pin arbitrary
	// memory / DB rows: only a per-element non-empty check existed before.
	MaxKeyPackagesPerRequest = 200
	MaxKeyPackageBlobSize    = 8 * 1024
)

// validateKeyPackages enforces the batch-count and per-blob-size bounds on a
// key-package array shared by CreateAccount and LinkDevice. An empty array is
// allowed (those paths accept zero key packages); a too-large batch or an
// empty/oversized element is rejected as key_package_invalid.
func validateKeyPackages(kps [][]byte) error {
	if len(kps) > MaxKeyPackagesPerRequest {
		return proto.APIError{Code: proto.ErrCodeKeyPackageInvalid, Message: "too many key packages"}
	}
	for _, kp := range kps {
		if len(kp) == 0 {
			return proto.APIError{Code: proto.ErrCodeKeyPackageInvalid, Message: "empty key package"}
		}
		if len(kp) > MaxKeyPackageBlobSize {
			return proto.APIError{Code: proto.ErrCodeKeyPackageInvalid, Message: "key package too large"}
		}
	}
	return nil
}

// Clock returns "now". Inject in tests via a fixed implementation.
type Clock interface {
	Now() time.Time
}

// IDGenerator returns a fresh opaque identifier.
// Real impl uses uuid.NewString; tests use a deterministic sequence.
type IDGenerator interface {
	Next() string
}

type ServiceDeps struct {
	Store              Store
	Clock              Clock
	IDGen              IDGenerator
	JWTSignKey         ed25519.PrivateKey
	JWTLifetime        time.Duration
	ChallengeLifetime  time.Duration
	KeyPackageLifetime time.Duration
	// WebDeviceLifetime is how long a kind=web device stays active after it is
	// linked (expires_at = linked_at + this). Zero means DefaultWebDeviceLifetime.
	WebDeviceLifetime time.Duration
	// DevicesChanged is told which devices were already active when a new
	// device is linked. Optional — nil disables the live notification.
	DevicesChanged DevicesChangedNotifier
	// DevicesRevoked is told which devices a revoke, a phrase restore or an
	// account deletion just cut off, so their open connections are closed.
	// Optional — nil disables it.
	DevicesRevoked DevicesRevokedNotifier
}

// notifyRevoked tells DevicesRevoked (when set) which devices were just cut
// off. Detached: a slow socket close must not delay the caller's response.
func (s *Service) notifyRevoked(deviceIDs []string) {
	if s.deps.DevicesRevoked == nil || len(deviceIDs) == 0 {
		return
	}
	go s.deps.DevicesRevoked.NotifyDevicesRevoked(deviceIDs)
}

// activeDeviceIDs lists the account's active device ids, except [except].
// Best-effort: a lookup failure yields none (the revoke itself still stands;
// those devices are then only refused at their next handshake, as before).
func (s *Service) activeDeviceIDs(ctx context.Context, accountID, except string) []string {
	devs, err := s.deps.Store.ListActiveDevicesByAccountID(ctx, accountID)
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(devs))
	for _, d := range devs {
		if d.DeviceID != except {
			ids = append(ids, d.DeviceID)
		}
	}
	return ids
}

// effChallengeLifetime returns the configured value, falling back to the
// default when the dep is zero (for older constructions / tests that didn't
// set it).
func (s *Service) effChallengeLifetime() time.Duration {
	if s.deps.ChallengeLifetime > 0 {
		return s.deps.ChallengeLifetime
	}
	return DefaultChallengeLifetime
}

func (s *Service) effWebDeviceLifetime() time.Duration {
	if s.deps.WebDeviceLifetime > 0 {
		return s.deps.WebDeviceLifetime
	}
	return DefaultWebDeviceLifetime
}

func (s *Service) effKeyPackageLifetime() time.Duration {
	if s.deps.KeyPackageLifetime > 0 {
		return s.deps.KeyPackageLifetime
	}
	return DefaultKeyPackageLifetime
}

type Service struct {
	deps ServiceDeps
}

func NewService(deps ServiceDeps) *Service {
	return &Service{deps: deps}
}

func (s *Service) CreateAccount(ctx context.Context, req proto.CreateAccountRequest) (proto.CreateAccountResponse, error) {
	var resp proto.CreateAccountResponse

	if err := ValidateUsername(req.Username); err != nil {
		return resp, proto.APIError{Code: proto.ErrCodeUsernameInvalid, Message: err.Error()}
	}

	if err := VerifyUsernameClaim(req.Username, req.IdentityPubKey, req.SignedClaim); err != nil {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: err.Error()}
	}

	if len(req.DevicePubKey) != ed25519.PublicKeySize {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "device pub key length"}
	}
	// X25519 pub key is optional for backwards-compat (older clients) but if
	// provided must be the canonical 32-byte length.
	if len(req.X25519PubKey) != 0 && len(req.X25519PubKey) != 32 {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "x25519 pub key length"}
	}

	if err := validateKeyPackages(req.KeyPackages); err != nil {
		return resp, err
	}

	now := s.deps.Clock.Now()

	held, err := s.deps.Store.HasUsernameHold(ctx, req.Username, now)
	if err != nil {
		return resp, apierr.Internal(err)
	}
	if held {
		return resp, proto.APIError{Code: proto.ErrCodeUsernameOnHold, Message: "username on cool-down"}
	}

	// The identity key is derived from the recovery phrase, so two accounts
	// sharing a key means two users picked the same phrase — restore would
	// then be ambiguous and either user could take over the other's account.
	// Reject up front (the partial unique index in migration 0011 closes the
	// race between this check and the insert).
	inUse, err := s.deps.Store.IdentityPubKeyInUse(ctx, req.IdentityPubKey)
	if err != nil {
		return resp, apierr.Internal(err)
	}
	if inUse {
		return resp, proto.APIError{Code: proto.ErrCodeIdentityKeyTaken, Message: "identity key already registered"}
	}

	accountID := s.deps.IDGen.Next()
	deviceID := s.deps.IDGen.Next()

	args := CreateAccountArgs{
		Account: proto.Account{
			AccountID:      accountID,
			Username:       req.Username,
			IdentityPubKey: req.IdentityPubKey,
			X25519PubKey:   req.X25519PubKey,
			CreatedAt:      now,
		},
		Device: proto.Device{
			DeviceID:     deviceID,
			AccountID:    accountID,
			DevicePubKey: req.DevicePubKey,
			X25519PubKey: req.X25519PubKey,
			DisplayName:  req.DeviceDisplayName,
			LinkedAt:     now,
		},
		KeyPackages: req.KeyPackages,
		KPExpiresAt: now.Add(s.effKeyPackageLifetime()),
	}

	if err := s.deps.Store.CreateAccountWithDevice(ctx, args); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			return resp, proto.APIError{Code: proto.ErrCodeUsernameTaken, Message: "username already taken"}
		}
		if errors.Is(err, ErrIdentityKeyExists) {
			return resp, proto.APIError{Code: proto.ErrCodeIdentityKeyTaken, Message: "identity key already registered"}
		}
		return resp, apierr.Internal(err)
	}

	jwt := crypto.SignJWT(s.deps.JWTSignKey, crypto.JWTClaims{
		AccountID: accountID,
		DeviceID:  deviceID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.deps.JWTLifetime).Unix(),
	})

	return proto.CreateAccountResponse{
		AccountID: accountID,
		DeviceID:  deviceID,
		JWT:       jwt,
	}, nil
}

// DeleteAccount soft-deletes the calling account: marks the account row
// deleted, revokes its devices, drops its key packages and push tokens,
// and places a 30-day hold on the username before it can be re-registered.
// The caller's JWT keeps working until expiry, but every account-scoped
// lookup fails once the row is marked deleted.
func (s *Service) DeleteAccount(ctx context.Context, accountID string) error {
	devices := s.activeDeviceIDs(ctx, accountID, "")
	now := s.deps.Clock.Now()
	if err := s.deps.Store.DeleteAccount(ctx, accountID, now, now.Add(UsernameHoldDuration)); err != nil {
		if errors.Is(err, ErrNotFound) {
			return proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		}
		return apierr.Internal(err)
	}
	s.notifyRevoked(devices)
	return nil
}

// RevokeDevice revokes one of the calling account's OWN devices (other than
// the device making the request — revoking yourself is a foot-gun; the caller
// should delete the account instead). Frees a device slot and drops the
// device's key packages so nobody invites it into a group again.
func (s *Service) RevokeDevice(ctx context.Context, accountID, deviceID string) error {
	if err := s.deps.Store.RevokeDevice(ctx, accountID, deviceID, s.deps.Clock.Now()); err != nil {
		if errors.Is(err, ErrNotFound) {
			return proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "device not found"}
		}
		return apierr.Internal(err)
	}
	s.notifyRevoked([]string{deviceID})
	return nil
}

// MaxDisplayNameLen caps a profile display name (runes).
const MaxDisplayNameLen = 64

// MaxAvatarURLLen caps the avatar URL string.
const MaxAvatarURLLen = 2048

// UpdateProfile sets the calling account's display name and/or avatar URL.
// A nil field is left unchanged; an empty string clears it.
func (s *Service) UpdateProfile(ctx context.Context, accountID string, req proto.UpdateProfileRequest) error {
	if req.DisplayName != nil {
		dn := strings.TrimSpace(*req.DisplayName)
		if len([]rune(dn)) > MaxDisplayNameLen {
			return proto.APIError{Code: proto.ErrCodeBadRequest, Message: "display name too long"}
		}
		req.DisplayName = &dn
	}
	if req.AvatarURL != nil && len(*req.AvatarURL) > MaxAvatarURLLen {
		return proto.APIError{Code: proto.ErrCodeBadRequest, Message: "avatar url too long"}
	}
	if req.DisplayName == nil && req.AvatarURL == nil {
		return proto.APIError{Code: proto.ErrCodeBadRequest, Message: "nothing to update"}
	}
	if err := s.deps.Store.UpdateProfile(ctx, accountID, req.DisplayName, req.AvatarURL); err != nil {
		if errors.Is(err, ErrNotFound) {
			return proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		}
		return apierr.Internal(err)
	}
	return nil
}

// ListDevices returns every active device for the calling account.
func (s *Service) ListDevices(ctx context.Context, accountID string) ([]proto.Device, error) {
	devs, err := s.deps.Store.ListActiveDevicesByAccountID(ctx, accountID)
	if err != nil {
		return nil, apierr.Internal(err)
	}
	return devs, nil
}

// SetDeviceSupportsSealed marks the calling device as sealed-receive capable
// (sealed-sender capability negotiation). Idempotent.
func (s *Service) SetDeviceSupportsSealed(ctx context.Context, deviceID string) error {
	if err := s.deps.Store.SetDeviceSupportsSealed(ctx, deviceID); err != nil {
		return apierr.Internal(err)
	}
	return nil
}

// x25519PubKeyLen is the byte length of an X25519 public key.
const x25519PubKeyLen = 32

// RepublishDeviceX25519 replaces the calling device's published sealing key.
//
// A device's X25519 keypair is generated locally and published once, at
// registration. If the local copy is ever regenerated while the device id stays
// the same, the published key goes stale and the device becomes silently
// unreachable: peers keep sealing to the dead key, the device cannot open
// anything, and the receive path acks-and-drops what it cannot open, so the
// messages are destroyed and the SENDER still sees a successful delivery.
// Re-publishing on connect is the only way out, so this exists as a first-class
// write rather than requiring a full device re-registration.
//
// Not a privilege escalation: deviceID comes from the JWT, so a caller can only
// rewrite its OWN key, and a token that can do this can already read that
// device's envelopes.
func (s *Service) RepublishDeviceX25519(ctx context.Context, deviceID string, pub []byte) error {
	if len(pub) != x25519PubKeyLen {
		return proto.APIError{Code: proto.ErrCodeBadRequest, Message: "x25519_pub_key must be 32 bytes"}
	}
	if err := s.deps.Store.UpdateDeviceX25519(ctx, deviceID, pub); err != nil {
		return apierr.Internal(err)
	}
	return nil
}

// uakCommitmentLen is the byte length of a UAK commitment (a SHA-256 digest).
const uakCommitmentLen = sha256.Size // 32

// SetAccessKeyCommitment publishes (or rotates) the account's unidentified-
// access-key commitment H(UAK) — sealed-sender Phase 2. The commitment must be a
// 32-byte SHA-256 digest; the server stores it as-is and never sees the UAK here.
func (s *Service) SetAccessKeyCommitment(ctx context.Context, accountID string, commitment []byte) error {
	if len(commitment) != uakCommitmentLen {
		return proto.APIError{Code: proto.ErrCodeBadRequest, Message: "commitment must be a 32-byte SHA-256 digest"}
	}
	if err := s.deps.Store.SetAccountUAKCommitment(ctx, accountID, commitment); err != nil {
		if errors.Is(err, ErrNotFound) {
			return proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		}
		return apierr.Internal(err)
	}
	return nil
}

// VerifyAccessKey authorizes an unauthenticated sealed send to recipientDeviceID
// by checking the presented UAK against the recipient account's stored commitment
// (H(presented) == commitment, constant-time). It returns the recipient ACCOUNT
// id (server-authoritative, derived from the device) so the caller can address +
// rate-limit the deposit. ok is false — with a nil error — when the recipient has
// not enabled unidentified access or the key doesn't match; the caller then falls
// back to the authenticated path. A nil error + ok=false must NOT be treated as a
// server error. Implements delivery.AccessKeyVerifier.
func (s *Service) VerifyAccessKey(ctx context.Context, recipientDeviceID string, presentedKey []byte) (string, bool, error) {
	accountID, commitment, err := s.deps.Store.GetAccountUAKCommitmentByDevice(ctx, recipientDeviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", false, nil // unknown/revoked recipient → unauthorized, not an error
		}
		return "", false, err
	}
	if len(commitment) != uakCommitmentLen {
		return accountID, false, nil // recipient hasn't enabled unidentified access
	}
	sum := sha256.Sum256(presentedKey)
	if subtle.ConstantTimeCompare(sum[:], commitment) != 1 {
		return accountID, false, nil
	}
	return accountID, true, nil
}

// MaxDevicesPerAccount caps how many active devices an account may link. The
// client UI stops the user well before this; the server bound is a backstop.
const MaxDevicesPerAccount = 5

// LinkDevice registers a brand-new device on the account that owns authDeviceID
// (the already-authenticated caller). The link must be approved by the
// recovery-phrase holder: req.SignedLink is the account identity key's
// signature over the new device's Ed25519 pub key. The new device's own
// Ed25519 (session auth) + X25519 (ratchet) keys are generated on that device
// and are NOT derived from the recovery phrase.
func (s *Service) LinkDevice(ctx context.Context, authDeviceID string, req proto.LinkDeviceRequest) (proto.LinkDeviceResponse, error) {
	var resp proto.LinkDeviceResponse

	if len(req.DevicePubKey) != ed25519.PublicKeySize {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "device pub key length"}
	}
	if len(req.X25519PubKey) != 32 {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "x25519 pub key length"}
	}
	if len(req.SignedLink) != ed25519.SignatureSize {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "signed link length"}
	}
	if err := validateKeyPackages(req.KeyPackages); err != nil {
		return resp, err
	}
	kind := req.Kind
	if kind == "" {
		kind = proto.DeviceKindPhone
	}
	if !proto.ValidDeviceKind(kind) {
		return resp, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "kind must be \"phone\" or \"web\""}
	}

	// Resolve the authorizing account from the caller's device, then verify the
	// link signature against that account's immutable identity key.
	acc, err := s.deps.Store.GetAccountByDeviceID(ctx, authDeviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return resp, proto.APIError{Code: proto.ErrCodeDeviceNotFound, Message: "authorizing device not found"}
		}
		return resp, apierr.Internal(err)
	}
	if !verifyLinkSignature(acc.IdentityPubKey, req.DevicePubKey, req.SignedLink) {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "link authorization signature invalid"}
	}

	// Backstop device cap. A re-link of an already-registered pub key is a
	// no-op success (idempotent retries from a flaky network).
	existing, err := s.deps.Store.ListActiveDevicesByAccountID(ctx, acc.AccountID)
	if err != nil {
		return resp, apierr.Internal(err)
	}
	for _, d := range existing {
		if bytesEqual(d.DevicePubKey, req.DevicePubKey) {
			return proto.LinkDeviceResponse{
				DeviceID: d.DeviceID,
				LinkedAt: d.LinkedAt.UTC().Format(time.RFC3339),
			}, nil
		}
	}
	if len(existing) >= MaxDevicesPerAccount {
		return resp, proto.APIError{Code: proto.ErrCodeDeviceLimit, Message: "device limit reached"}
	}

	now := s.deps.Clock.Now()
	deviceID := s.deps.IDGen.Next()
	var expiresAt *time.Time
	if kind == proto.DeviceKindWeb {
		e := now.Add(s.effWebDeviceLifetime())
		expiresAt = &e
	}
	args := LinkDeviceArgs{
		Device: proto.Device{
			DeviceID:     deviceID,
			AccountID:    acc.AccountID,
			DevicePubKey: req.DevicePubKey,
			X25519PubKey: req.X25519PubKey,
			DisplayName:  req.DeviceDisplayName,
			LinkedAt:     now,
			// The authorizer is ALWAYS the authenticated caller, never a
			// client-supplied value.
			LinkedByDeviceID: authDeviceID,
			Kind:             kind,
			ExpiresAt:        expiresAt,
		},
		KeyPackages: req.KeyPackages,
		KPExpiresAt: now.Add(s.effKeyPackageLifetime()),
	}
	if err := s.deps.Store.LinkDevice(ctx, args); err != nil {
		return resp, apierr.Internal(err)
	}

	// Tell the account's OLD devices (the new one is not among `existing`) so
	// the designated adder can pull the newcomer into existing MLS 1:1 groups
	// right away. Detached: a wedged socket must not delay the link response.
	if s.deps.DevicesChanged != nil {
		oldIDs := make([]string, 0, len(existing))
		for _, d := range existing {
			oldIDs = append(oldIDs, d.DeviceID)
		}
		go s.deps.DevicesChanged.NotifyDevicesChanged(oldIDs)
	}

	return proto.LinkDeviceResponse{
		DeviceID: deviceID,
		LinkedAt: now.UTC().Format(time.RFC3339),
	}, nil
}

// PendingDevice backs the unauthenticated link-status poll a freshly-keyed
// device runs (keyed by its own Ed25519 pub key) to learn whether the primary
// has authorized it yet, and if so its server-assigned device_id + account.
func (s *Service) PendingDevice(ctx context.Context, devicePubKey []byte) (proto.PendingDeviceResponse, error) {
	if len(devicePubKey) != ed25519.PublicKeySize {
		return proto.PendingDeviceResponse{}, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "device pub key length"}
	}
	dev, err := s.deps.Store.GetActiveDeviceByPubKey(ctx, devicePubKey)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return proto.PendingDeviceResponse{Linked: false}, nil
		}
		return proto.PendingDeviceResponse{}, apierr.Internal(err)
	}
	acc, err := s.deps.Store.GetAccountByDeviceID(ctx, dev.DeviceID)
	if err != nil {
		// Device exists but account lookup failed — treat as not-yet-ready.
		return proto.PendingDeviceResponse{Linked: false}, nil
	}
	return proto.PendingDeviceResponse{
		Linked:    true,
		AccountID: acc.AccountID,
		DeviceID:  dev.DeviceID,
		Username:  acc.Username,
	}, nil
}

// LookupAccount returns the public account record for a username. Used by
// clients to start a new chat once they know the recipient's @handle.
// Returns ErrCodeUsernameInvalid for malformed usernames, ErrCodeAccountNotFound
// for unknown ones (so callers cannot enumerate by format).
func (s *Service) LookupAccount(ctx context.Context, username string) (proto.Account, error) {
	if err := ValidateUsername(username); err != nil {
		return proto.Account{}, proto.APIError{Code: proto.ErrCodeUsernameInvalid, Message: err.Error()}
	}
	acc, err := s.deps.Store.GetAccountByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return proto.Account{}, proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		}
		return proto.Account{}, apierr.Internal(err)
	}
	return acc, nil
}

// CheckUsername reports whether a username can be registered right now:
// well-formed, not taken by a live account, and not on a post-deletion hold.
// Unauthenticated — the signup screen calls it before any session exists so
// the user learns about a taken name before investing in a recovery phrase.
// Taken/held/invalid all come back as a normal availability result, not an
// error; only storage failures error.
func (s *Service) CheckUsername(ctx context.Context, username string) (proto.UsernameAvailability, error) {
	out := proto.UsernameAvailability{Username: username}

	if err := ValidateUsername(username); err != nil {
		out.Reason = "invalid"
		return out, nil
	}

	held, err := s.deps.Store.HasUsernameHold(ctx, username, s.deps.Clock.Now())
	if err != nil {
		return out, apierr.Internal(err)
	}
	if held {
		// Privacy: this endpoint is UNAUTHENTICATED, so a distinct "on_hold"
		// reason would let anyone probing arbitrary usernames learn that @x was
		// deleted within the last 30 days — a deletion-history oracle. Report
		// it indistinguishably from a live "taken" name. The deliberate create
		// path (a signed identity claim, not a cheap GET probe) still returns
		// the precise username_on_hold error so a genuine registrant gets the
		// "try again in 30 days" guidance.
		out.Reason = "taken"
		return out, nil
	}

	_, err = s.deps.Store.GetAccountByUsername(ctx, username)
	switch {
	case err == nil:
		out.Reason = "taken"
		return out, nil
	case errors.Is(err, ErrNotFound):
		out.Available = true
		return out, nil
	default:
		return out, apierr.Internal(err)
	}
}

// LookupAccountByDevice resolves a device id to its account. Lets a
// message receiver identify an unknown sender — envelopes carry only
// sender_device_id. Device ids are unguessable UUIDs a caller only learns
// by being sent an envelope, so this leaks nothing username lookup
// doesn't.
func (s *Service) LookupAccountByDevice(ctx context.Context, deviceID string) (proto.Account, error) {
	acc, err := s.deps.Store.GetAccountByDeviceID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return proto.Account{}, proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		}
		return proto.Account{}, apierr.Internal(err)
	}
	return acc, nil
}

// LookupAccountByID resolves an account id to its public account record.
// Backs the self-synced-Welcome peer lookup: a linked device joins an MLS
// group and knows its peer only as an account id (parsed from the 1to1
// conversation id), needing the @handle + keys to render the conversation.
// Account ids are unguessable UUIDs, so this leaks nothing username lookup
// doesn't.
func (s *Service) LookupAccountByID(ctx context.Context, accountID string) (proto.Account, error) {
	acc, err := s.deps.Store.GetAccountByID(ctx, accountID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return proto.Account{}, proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		}
		return proto.Account{}, apierr.Internal(err)
	}
	return acc, nil
}

// IssueRestoreChallenge issues a challenge keyed only by username (no
// device_id, since the restoring client does not know its own device id
// yet). Used by the recovery-phrase restore flow. Same lifetime as a regular
// session challenge.
func (s *Service) IssueRestoreChallenge(ctx context.Context, username string) ([]byte, int64, error) {
	if err := ValidateUsername(username); err != nil {
		return nil, 0, proto.APIError{Code: proto.ErrCodeUsernameInvalid, Message: err.Error()}
	}
	if _, err := s.deps.Store.GetAccountByUsername(ctx, username); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, 0, proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		}
		return nil, 0, apierr.Internal(err)
	}

	chal, err := crypto.NewChallenge()
	if err != nil {
		return nil, 0, apierr.Internal(err)
	}

	now := s.deps.Clock.Now()
	expiresAt := now.Add(s.effChallengeLifetime())
	// Keyed by the challenge itself: issuing one never displaces another
	// party's outstanding challenge (see challenge_keys.go).
	key := restoreChallengeKey(username, chal)

	if err := s.deps.Store.StoreChallenge(ctx, key, chal, expiresAt); err != nil {
		return nil, 0, apierr.Internal(err)
	}
	return chal, expiresAt.Unix(), nil
}

// CompleteRestoreSession completes the recovery-phrase restore flow. The
// client signs the issued challenge with the identity private key it just
// re-derived from the BIP-39 phrase. On success returns the (account_id,
// device_id, jwt) triple — the client previously didn't have account_id or
// device_id, so the restore endpoint surfaces them in v1's single-device
// model.
func (s *Service) CompleteRestoreSession(ctx context.Context, username string, identityPubKey, presented, signature, devicePubKey, x25519PubKey []byte, opts ...RestoreOption) (proto.RestoreSessionResponse, error) {
	var resp proto.RestoreSessionResponse
	var ro restoreOptions
	for _, o := range opts {
		o(&ro)
	}

	if err := ValidateUsername(username); err != nil {
		return resp, proto.APIError{Code: proto.ErrCodeUsernameInvalid, Message: err.Error()}
	}
	if len(identityPubKey) != ed25519.PublicKeySize {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "identity pub key length"}
	}
	if len(signature) != ed25519.SignatureSize {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "signature length"}
	}

	acc, err := s.deps.Store.GetAccountByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return resp, proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		}
		return resp, apierr.Internal(err)
	}
	if !bytesEqual(acc.IdentityPubKey, identityPubKey) {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "identity pub key mismatch"}
	}

	now := s.deps.Clock.Now()
	if !wellFormedChallenge(presented) {
		return resp, proto.APIError{Code: proto.ErrCodeChallengeNotFound, Message: "challenge not found"}
	}
	stored, err := s.deps.Store.ConsumeChallenge(ctx, restoreChallengeKey(username, presented), now)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			return resp, proto.APIError{Code: proto.ErrCodeChallengeNotFound, Message: "challenge not found"}
		case errors.Is(err, ErrChallengeStale):
			return resp, proto.APIError{Code: proto.ErrCodeChallengeExpired, Message: "challenge expired"}
		default:
			return resp, apierr.Internal(err)
		}
	}
	if !bytesEqual(stored, presented) {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "challenge mismatch"}
	}
	if !ed25519.Verify(ed25519.PublicKey(identityPubKey), presented, signature) {
		return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "bad signature"}
	}

	// New flow: the client sent a device key → MINT a fresh device for this
	// phone (so it shows up as a distinct linked device) and REVOKE the
	// account's other devices, so the restored phone becomes the sole device
	// ("this phone is now my account"). The old phone's next token refresh /
	// WebSocket reconnect then fails the active-device check and it signs out +
	// wipes. Possession of the phrase — proven by the verified signature above —
	// is the authorization; no co-signing primary device is needed.
	if len(devicePubKey) > 0 {
		if len(devicePubKey) != ed25519.PublicKeySize {
			return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "device pub key length"}
		}
		if len(x25519PubKey) != 32 {
			return resp, proto.APIError{Code: proto.ErrCodeBadSignature, Message: "x25519 pub key length"}
		}
		if ro.keepOtherDevices {
			// Nothing is revoked on this path, so the active-device cap applies
			// exactly as it does for a link (same ErrCodeDeviceLimit).
			if err := s.ensureDeviceCapacity(ctx, acc.AccountID); err != nil {
				return resp, err
			}
		}
		deviceID := s.deps.IDGen.Next()
		// Restore mints the device with NO key packages (RestoreSessionRequest
		// carries none — the client republishes a fresh batch right after via
		// keypackages.Publish, which is already count/size-bounded). So there is
		// no untrusted key-package array to bound on this path.
		if err := s.deps.Store.LinkDevice(ctx, LinkDeviceArgs{
			Device: proto.Device{
				DeviceID:     deviceID,
				AccountID:    acc.AccountID,
				DevicePubKey: devicePubKey,
				X25519PubKey: x25519PubKey,
				LinkedAt:     now,
			},
			KPExpiresAt: now.Add(s.effKeyPackageLifetime()),
		}); err != nil {
			return resp, apierr.Internal(err)
		}
		// KeepOtherDevices: the phrase holder asked to ADD this phone beside the
		// existing devices (they can then send it the chat history). Otherwise the
		// takeover semantics apply and every other device is revoked.
		if !ro.keepOtherDevices {
			revoked := s.activeDeviceIDs(ctx, acc.AccountID, deviceID)
			if err := s.deps.Store.RevokeOtherDevicesByAccountID(ctx, acc.AccountID, deviceID, now); err != nil {
				return resp, apierr.Internal(err)
			}
			s.notifyRevoked(revoked)
		}
		jwt := crypto.SignJWT(s.deps.JWTSignKey, crypto.JWTClaims{
			AccountID: acc.AccountID,
			DeviceID:  deviceID,
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(s.deps.JWTLifetime).Unix(),
		})
		return proto.RestoreSessionResponse{
			AccountID: acc.AccountID,
			DeviceID:  deviceID,
			JWT:       jwt,
		}, nil
	}

	// Legacy flow (older client without a device key): reuse the existing
	// device id (the original single-device restore behaviour).
	dev, err := s.deps.Store.GetActiveDeviceByAccountID(ctx, acc.AccountID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return resp, proto.APIError{Code: proto.ErrCodeDeviceNotFound, Message: "device not found"}
		}
		return resp, apierr.Internal(err)
	}

	// Restore re-derives the identity but the client's CoreCrypto store was
	// wiped, so every key package this device published holds a private key it
	// no longer has. Purge them here — otherwise peers keep fetching the dead
	// packages and building Welcomes the restored device can't decrypt. The
	// client republishes a fresh batch right after restore.
	if err := s.deps.Store.DeleteKeyPackagesByDevice(ctx, dev.DeviceID); err != nil {
		return resp, apierr.Internal(err)
	}

	jwt := crypto.SignJWT(s.deps.JWTSignKey, crypto.JWTClaims{
		AccountID: acc.AccountID,
		DeviceID:  dev.DeviceID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.deps.JWTLifetime).Unix(),
	})

	return proto.RestoreSessionResponse{
		AccountID: acc.AccountID,
		DeviceID:  dev.DeviceID,
		JWT:       jwt,
	}, nil
}

func (s *Service) IssueChallenge(ctx context.Context, username, deviceID string) ([]byte, int64, error) {
	acc, err := s.deps.Store.GetAccountByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, 0, proto.APIError{Code: proto.ErrCodeAccountNotFound, Message: "account not found"}
		}
		return nil, 0, apierr.Internal(err)
	}

	dev, err := s.deps.Store.GetActiveDeviceByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, 0, proto.APIError{Code: proto.ErrCodeDeviceNotFound, Message: "device not found"}
		}
		return nil, 0, apierr.Internal(err)
	}
	// Reject (username, deviceID) pairs where the device belongs to a
	// different account. Without this check, a caller could issue a
	// challenge keyed under someone else's username scope — harmless on its
	// own (CompleteSession still verifies against the device's pub key) but
	// a sharp edge worth blunting at the API boundary.
	if dev.AccountID != acc.AccountID {
		return nil, 0, proto.APIError{Code: proto.ErrCodeDeviceNotFound, Message: "device does not belong to account"}
	}

	chal, err := crypto.NewChallenge()
	if err != nil {
		return nil, 0, apierr.Internal(err)
	}

	now := s.deps.Clock.Now()
	expiresAt := now.Add(s.effChallengeLifetime())
	// Keyed by the challenge itself: issuing one never displaces another
	// party's outstanding challenge (see challenge_keys.go).
	key := sessionChallengeKey(username, dev.DeviceID, chal)

	if err := s.deps.Store.StoreChallenge(ctx, key, chal, expiresAt); err != nil {
		return nil, 0, apierr.Internal(err)
	}
	return chal, expiresAt.Unix(), nil
}

func (s *Service) CompleteSession(ctx context.Context, username, deviceID string, presented, signature []byte) (string, error) {
	dev, err := s.deps.Store.GetActiveDeviceByID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", proto.APIError{Code: proto.ErrCodeDeviceNotFound, Message: "device not found"}
		}
		return "", apierr.Internal(err)
	}

	now := s.deps.Clock.Now()
	if !wellFormedChallenge(presented) {
		return "", proto.APIError{Code: proto.ErrCodeChallengeNotFound, Message: "challenge not found"}
	}
	stored, err := s.deps.Store.ConsumeChallenge(ctx, sessionChallengeKey(username, dev.DeviceID, presented), now)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			return "", proto.APIError{Code: proto.ErrCodeChallengeNotFound, Message: "challenge not found"}
		case errors.Is(err, ErrChallengeStale):
			return "", proto.APIError{Code: proto.ErrCodeChallengeExpired, Message: "challenge expired"}
		default:
			return "", apierr.Internal(err)
		}
	}

	if !bytesEqual(stored, presented) {
		return "", proto.APIError{Code: proto.ErrCodeBadSignature, Message: "challenge mismatch"}
	}
	if len(dev.DevicePubKey) != ed25519.PublicKeySize ||
		len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(dev.DevicePubKey), presented, signature) {
		return "", proto.APIError{Code: proto.ErrCodeBadSignature, Message: "bad signature"}
	}

	jwt := crypto.SignJWT(s.deps.JWTSignKey, crypto.JWTClaims{
		AccountID: dev.AccountID,
		DeviceID:  dev.DeviceID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.deps.JWTLifetime).Unix(),
	})
	return jwt, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
