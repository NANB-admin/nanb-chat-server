package identity

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nanb/nanb-server/internal/proto"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrAlreadyExists  = errors.New("already exists")
	ErrChallengeStale = errors.New("challenge stale")
	// ErrIdentityKeyExists is returned by CreateAccountWithDevice when the
	// partial unique index on identity_pub_key (active accounts only)
	// rejects the insert — i.e. the service-level pre-check raced.
	ErrIdentityKeyExists = errors.New("identity key already exists")
)

// StoreInMemory is the unit-test storage implementation. Safe for concurrent use.
type StoreInMemory struct {
	mu sync.Mutex

	// Now is the clock used to decide device expiry (mirrors the DB's now() in
	// the Postgres store). nil means time.Now.
	Now func() time.Time

	accountsByID    map[string]proto.Account
	accountIDByUser map[string]string
	devicesByID     map[string]proto.Device
	usernameHolds   map[string]time.Time
	keyPackages     []proto.KeyPackage
	challenges      map[string]challengeEntry
	uakByAccount    map[string][]byte // account_id -> UAK commitment (Phase 2)
}

// active reports whether d is live right now (not expired). Revoked devices are
// deleted from devicesByID, so presence + ActiveAt == the Postgres deviceLive.
func (s *StoreInMemory) active(d proto.Device) bool {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	return d.ActiveAt(now())
}

type challengeEntry struct {
	value     []byte
	expiresAt time.Time
}

func NewStoreInMemory() *StoreInMemory {
	return &StoreInMemory{
		accountsByID:    map[string]proto.Account{},
		accountIDByUser: map[string]string{},
		devicesByID:     map[string]proto.Device{},
		usernameHolds:   map[string]time.Time{},
		challenges:      map[string]challengeEntry{},
		uakByAccount:    map[string][]byte{},
	}
}

func (s *StoreInMemory) CreateAccountWithDevice(_ context.Context, args CreateAccountArgs) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, taken := s.accountIDByUser[strings.ToLower(args.Account.Username)]; taken {
		return ErrAlreadyExists
	}
	// Mirror the Postgres partial unique index on identity_pub_key. Skip
	// empty keys — some store-level tests seed bare accounts without one
	// (the service path always has a claim-verified 32-byte key).
	if len(args.Account.IdentityPubKey) > 0 {
		for _, a := range s.accountsByID {
			if bytes.Equal(a.IdentityPubKey, args.Account.IdentityPubKey) {
				return ErrIdentityKeyExists
			}
		}
	}
	s.accountsByID[args.Account.AccountID] = args.Account
	s.accountIDByUser[strings.ToLower(args.Account.Username)] = args.Account.AccountID
	s.devicesByID[args.Device.DeviceID] = args.Device
	for i, p := range args.KeyPackages {
		s.keyPackages = append(s.keyPackages, proto.KeyPackage{
			KPID:      args.Device.DeviceID + "-" + strconv.Itoa(i),
			AccountID: args.Account.AccountID,
			DeviceID:  args.Device.DeviceID,
			Payload:   p,
			ExpiresAt: args.KPExpiresAt,
		})
	}
	return nil
}

func (s *StoreInMemory) GetAccountByUsername(_ context.Context, username string) (proto.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.accountIDByUser[strings.ToLower(username)]
	if !ok {
		return proto.Account{}, ErrNotFound
	}
	return s.accountsByID[id], nil
}

func (s *StoreInMemory) GetAccountByID(_ context.Context, accountID string) (proto.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.accountsByID[accountID]
	if !ok {
		return proto.Account{}, ErrNotFound
	}
	return a, nil
}

func (s *StoreInMemory) GetAccountByDeviceID(_ context.Context, deviceID string) (proto.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.devicesByID[deviceID]
	if !ok || !s.active(d) {
		return proto.Account{}, ErrNotFound
	}
	a, ok := s.accountsByID[d.AccountID]
	if !ok {
		return proto.Account{}, ErrNotFound
	}
	return a, nil
}

func (s *StoreInMemory) GetActiveDeviceByID(_ context.Context, deviceID string) (proto.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.devicesByID[deviceID]
	if !ok || !s.active(d) {
		return proto.Device{}, ErrNotFound
	}
	return d, nil
}

func (s *StoreInMemory) GetActiveDeviceByAccountID(_ context.Context, accountID string) (proto.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, d := range s.devicesByID {
		if d.AccountID == accountID && s.active(d) {
			return d, nil
		}
	}
	return proto.Device{}, ErrNotFound
}

func (s *StoreInMemory) ListActiveDevicesByAccountID(_ context.Context, accountID string) ([]proto.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []proto.Device
	for _, d := range s.devicesByID {
		if d.AccountID == accountID && s.active(d) {
			out = append(out, d)
		}
	}
	// Stable order: by LinkedAt ascending, then DeviceID for ties.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			a, b := out[j-1], out[j]
			if a.LinkedAt.After(b.LinkedAt) ||
				(a.LinkedAt.Equal(b.LinkedAt) && a.DeviceID > b.DeviceID) {
				out[j-1], out[j] = b, a
				continue
			}
			break
		}
	}
	return out, nil
}

func (s *StoreInMemory) SetDeviceSupportsSealed(_ context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devicesByID[deviceID]; ok {
		d.SupportsSealed = true
		s.devicesByID[deviceID] = d
	}
	return nil
}

func (s *StoreInMemory) UpdateDeviceX25519(_ context.Context, deviceID string, pub []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devicesByID[deviceID]; ok {
		d.X25519PubKey = pub
		s.devicesByID[deviceID] = d
	}
	return nil
}

func (s *StoreInMemory) SetAccountUAKCommitment(_ context.Context, accountID string, commitment []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accountsByID[accountID]; !ok {
		return ErrNotFound
	}
	cp := make([]byte, len(commitment))
	copy(cp, commitment)
	s.uakByAccount[accountID] = cp
	return nil
}

func (s *StoreInMemory) GetAccountUAKCommitmentByDevice(_ context.Context, deviceID string) (string, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devicesByID[deviceID] // present == not revoked (revoked rows are deleted)
	if !ok || !s.active(d) {
		return "", nil, ErrNotFound
	}
	if _, ok := s.accountsByID[d.AccountID]; !ok {
		return "", nil, ErrNotFound
	}
	return d.AccountID, s.uakByAccount[d.AccountID], nil
}

func (s *StoreInMemory) GetActiveDeviceByPubKey(_ context.Context, devicePubKey []byte) (proto.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var found *proto.Device
	for _, d := range s.devicesByID {
		if bytes.Equal(d.DevicePubKey, devicePubKey) && s.active(d) {
			// Pick the earliest-linked on the off chance of a collision.
			if found == nil || d.LinkedAt.Before(found.LinkedAt) {
				dd := d
				found = &dd
			}
		}
	}
	if found == nil {
		return proto.Device{}, ErrNotFound
	}
	return *found, nil
}

func (s *StoreInMemory) LinkDevice(_ context.Context, args LinkDeviceArgs) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.devicesByID[args.Device.DeviceID]; exists {
		return ErrAlreadyExists
	}
	s.devicesByID[args.Device.DeviceID] = args.Device
	for i, p := range args.KeyPackages {
		s.keyPackages = append(s.keyPackages, proto.KeyPackage{
			KPID:      args.Device.DeviceID + "-" + strconv.Itoa(i),
			AccountID: args.Device.AccountID,
			DeviceID:  args.Device.DeviceID,
			Payload:   p,
			ExpiresAt: args.KPExpiresAt,
		})
	}
	return nil
}

func (s *StoreInMemory) RevokeDevice(_ context.Context, accountID, deviceID string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devicesByID[deviceID]
	if !ok || d.AccountID != accountID {
		return ErrNotFound
	}
	delete(s.devicesByID, deviceID)
	kept := s.keyPackages[:0]
	for _, kp := range s.keyPackages {
		if kp.DeviceID != deviceID {
			kept = append(kept, kp)
		}
	}
	s.keyPackages = kept
	return nil
}

func (s *StoreInMemory) RevokeOtherDevicesByAccountID(_ context.Context, accountID, exceptDeviceID string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var revoked []string
	for id, d := range s.devicesByID {
		if d.AccountID == accountID && id != exceptDeviceID {
			revoked = append(revoked, id)
		}
	}
	for _, id := range revoked {
		delete(s.devicesByID, id)
	}
	kept := s.keyPackages[:0]
	for _, kp := range s.keyPackages {
		drop := false
		for _, id := range revoked {
			if kp.DeviceID == id {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, kp)
		}
	}
	s.keyPackages = kept
	return nil
}

func (s *StoreInMemory) DeleteKeyPackagesByDevice(_ context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.keyPackages[:0]
	for _, kp := range s.keyPackages {
		if kp.DeviceID != deviceID {
			kept = append(kept, kp)
		}
	}
	s.keyPackages = kept
	return nil
}

func (s *StoreInMemory) UpdateProfile(_ context.Context, accountID string, displayName, avatarURL *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc, ok := s.accountsByID[accountID]
	if !ok {
		return ErrNotFound
	}
	if displayName != nil {
		acc.DisplayName = *displayName
	}
	if avatarURL != nil {
		acc.AvatarURL = *avatarURL
	}
	s.accountsByID[accountID] = acc
	return nil
}

func (s *StoreInMemory) DeleteAccount(_ context.Context, accountID string, now, holdUntil time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc, ok := s.accountsByID[accountID]
	if !ok {
		return ErrNotFound
	}
	_ = now // the in-memory store drops the row instead of soft-deleting

	username := acc.Username
	delete(s.accountIDByUser, strings.ToLower(username))
	delete(s.accountsByID, accountID)

	for id, d := range s.devicesByID {
		if d.AccountID == accountID {
			delete(s.devicesByID, id)
		}
	}

	kept := s.keyPackages[:0]
	for _, kp := range s.keyPackages {
		if kp.AccountID != accountID {
			kept = append(kept, kp)
		}
	}
	s.keyPackages = kept

	s.usernameHolds[strings.ToLower(username)] = holdUntil
	return nil
}

func (s *StoreInMemory) IdentityPubKeyInUse(_ context.Context, identityPubKey []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, a := range s.accountsByID {
		if bytes.Equal(a.IdentityPubKey, identityPubKey) {
			return true, nil
		}
	}
	return false, nil
}

func (s *StoreInMemory) HasUsernameHold(_ context.Context, username string, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	releasedAt, held := s.usernameHolds[strings.ToLower(username)]
	if !held {
		return false, nil
	}
	return now.Before(releasedAt), nil
}

// AddUsernameHold seeds a hold record for tests.
func (s *StoreInMemory) AddUsernameHold(username string, releasedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usernameHolds[strings.ToLower(username)] = releasedAt
}

// AddDeviceForTest seeds an extra device row directly. Used by tests that
// exercise multi-device ordering without going through CreateAccountWithDevice.
func (s *StoreInMemory) AddDeviceForTest(d proto.Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devicesByID[d.DeviceID] = d
}

func (s *StoreInMemory) StoreChallenge(_ context.Context, key string, challenge []byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[key] = challengeEntry{value: append([]byte(nil), challenge...), expiresAt: expiresAt}
	return nil
}

func (s *StoreInMemory) ConsumeChallenge(_ context.Context, key string, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.challenges[key]
	if !ok {
		return nil, ErrNotFound
	}
	delete(s.challenges, key)
	if now.After(c.expiresAt) {
		return nil, ErrChallengeStale
	}
	return c.value, nil
}

// KeyPackagesFor returns a snapshot of stored KeyPackages for the given account, for inspection in tests.
func (s *StoreInMemory) KeyPackagesFor(accountID string) []proto.KeyPackage {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []proto.KeyPackage
	for _, kp := range s.keyPackages {
		if kp.AccountID == accountID {
			out = append(out, kp)
		}
	}
	return out
}
