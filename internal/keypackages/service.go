package keypackages

import (
	"context"
	"errors"

	"github.com/nanb/nanb-server/internal/apierr"
	"github.com/nanb/nanb-server/internal/proto"
)

// AccountLookup resolves a username to an account_id. Injected so the
// keypackages package doesn't have to import the identity package
// (circular import otherwise).
type AccountLookup interface {
	AccountIDByUsername(ctx context.Context, username string) (string, error)
}

type ServiceDeps struct {
	Store         Store
	AccountLookup AccountLookup

	// LowWaterMark: if fetching a KeyPackage drops the remaining count
	// below this value, the response signals ReplenishNeeded=true so
	// the depleted user's next foreground hit publishes more.
	LowWaterMark int

	// MaxPerBatch caps a single Publish call. Default 200.
	MaxPerBatch int

	// MaxBlobSize caps a single KeyPackage payload. Default 8 KiB.
	MaxBlobSize int

	// MaxStoredPerDevice caps how many unconsumed packages one device may have
	// on the server; a publish beyond it is trimmed to fit. 0 means
	// DefaultMaxStoredPerDevice.
	MaxStoredPerDevice int

	// ClaimQuota bounds how many of another account's packages one requester
	// may claim per window. Optional; nil = unbounded (tests).
	ClaimQuota ClaimQuota

	// Published hears every successful publish. Optional.
	Published PublishListener
}

// DefaultMaxStoredPerDevice: the client keeps a device's pool between 10 and
// ~60 (refills 50 under a low-water mark of 10) and publishes 100 on sign-up,
// link and restore, so 200 is twice anything a real client stores while still
// bounding what one device can park on the server.
const DefaultMaxStoredPerDevice = 200

func (s *Service) maxStoredPerDevice() int {
	if s.deps.MaxStoredPerDevice > 0 {
		return s.deps.MaxStoredPerDevice
	}
	return DefaultMaxStoredPerDevice
}

type Service struct {
	deps ServiceDeps
}

func NewService(deps ServiceDeps) *Service {
	return &Service{deps: deps}
}

func (s *Service) Publish(ctx context.Context, accountID, deviceID string, req proto.PublishKeyPackagesRequest) (proto.PublishKeyPackagesResponse, error) {
	if len(req.KeyPackages) == 0 {
		return proto.PublishKeyPackagesResponse{}, proto.APIError{
			Code: proto.ErrCodeKeyPackageInvalid, Message: "empty batch",
		}
	}
	if len(req.KeyPackages) > s.deps.MaxPerBatch {
		return proto.PublishKeyPackagesResponse{}, proto.APIError{
			Code: proto.ErrCodeKeyPackageInvalid, Message: "batch too large",
		}
	}
	for _, kp := range req.KeyPackages {
		if len(kp) == 0 {
			return proto.PublishKeyPackagesResponse{}, proto.APIError{
				Code: proto.ErrCodeKeyPackageInvalid, Message: "empty key package",
			}
		}
		if len(kp) > s.deps.MaxBlobSize {
			return proto.PublishKeyPackagesResponse{}, proto.APIError{
				Code: proto.ErrCodeKeyPackageInvalid, Message: "key package too large",
			}
		}
	}
	// A Reset batch REPLACES the device's pool. Purge before inserting so the
	// dead packages can't be popped in the window between the two, and so a
	// caller that resets never ends up with old+new mixed (PopOne is FIFO, so
	// the dead ones would be handed out first and every invitation built from
	// them would fail). Validated above, so nothing is dropped for a batch that
	// was going to be rejected anyway.
	stored := 0
	room := s.maxStoredPerDevice()
	if req.Reset {
		if err := s.deps.Store.DeleteUnconsumedByDevice(ctx, deviceID); err != nil {
			return proto.PublishKeyPackagesResponse{}, apierr.Internal(err)
		}
	} else {
		have, err := s.deps.Store.CountUnconsumedByDevice(ctx, accountID, deviceID)
		if err != nil {
			return proto.PublishKeyPackagesResponse{}, apierr.Internal(err)
		}
		room -= have
	}
	// Per-device cap: keep only what fits. Trimmed, not rejected, so a client
	// that over-publishes still succeeds (its pool is already full). The
	// response's StoredCount says how many were kept.
	batch := req.KeyPackages
	if room < len(batch) {
		if room < 0 {
			room = 0
		}
		batch = batch[:room]
	}
	if len(batch) > 0 {
		if err := s.deps.Store.PublishBatch(ctx, accountID, deviceID, batch); err != nil {
			return proto.PublishKeyPackagesResponse{}, apierr.Internal(err)
		}
		stored = len(batch)
		if s.deps.Published != nil {
			s.deps.Published.KeyPackagesPublished(accountID, deviceID)
		}
	}
	return proto.PublishKeyPackagesResponse{StoredCount: stored}, nil
}

// checkClaimQuota reports ErrClaimQuotaExceeded when requester may not claim
// any more of target's packages now. Claiming your OWN account's packages is
// never limited (older clients add their own new devices through the username
// routes).
func (s *Service) checkClaimQuota(requesterAccountID, targetAccountID string) error {
	if s.deps.ClaimQuota == nil || requesterAccountID == targetAccountID {
		return nil
	}
	if !s.deps.ClaimQuota.Allow(requesterAccountID, targetAccountID) {
		return ErrClaimQuotaExceeded
	}
	return nil
}

func (s *Service) chargeClaimQuota(requesterAccountID, targetAccountID string, n int) {
	if s.deps.ClaimQuota == nil || requesterAccountID == targetAccountID {
		return
	}
	s.deps.ClaimQuota.Charge(requesterAccountID, targetAccountID, n)
}

// FetchForUsername consumes one KeyPackage of the named account on behalf of
// requesterAccountID (subject to ClaimQuota).
func (s *Service) FetchForUsername(ctx context.Context, requesterAccountID, username string) (proto.FetchKeyPackageResponse, error) {
	accountID, err := s.deps.AccountLookup.AccountIDByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return proto.FetchKeyPackageResponse{}, proto.APIError{
				Code: proto.ErrCodeAccountNotFound, Message: "account not found",
			}
		}
		return proto.FetchKeyPackageResponse{}, apierr.Internal(err)
	}
	if err := s.checkClaimQuota(requesterAccountID, accountID); err != nil {
		return proto.FetchKeyPackageResponse{}, err
	}
	payload, err := s.deps.Store.PopOne(ctx, accountID)
	if err != nil {
		if errors.Is(err, ErrEmpty) {
			return proto.FetchKeyPackageResponse{}, proto.APIError{
				Code: proto.ErrCodeKeyPackageExhausted, Message: "no key packages available",
			}
		}
		return proto.FetchKeyPackageResponse{}, apierr.Internal(err)
	}
	s.chargeClaimQuota(requesterAccountID, accountID, 1)
	remaining, err := s.deps.Store.CountUnconsumed(ctx, accountID)
	if err != nil {
		// Pop already succeeded — we owe the caller the KeyPackage.
		// Drop the remaining-count diagnostic and continue.
		remaining = -1
	}
	return proto.FetchKeyPackageResponse{
		KeyPackage:       payload,
		RemainingForUser: remaining,
		ReplenishNeeded:  remaining >= 0 && remaining < s.deps.LowWaterMark,
	}, nil
}

// FetchAllDevicesForUsername consumes one KeyPackage per active device of the
// named account, so a multi-device MLS inviter can add every device of the peer
// as its own group leaf. Unlike FetchForUsername it does NOT error when a
// device (or the whole account) has no packages — absent devices are simply
// omitted; the caller adds whoever it can and the rest join on their next send.
// Claimed on behalf of requesterAccountID (subject to ClaimQuota).
func (s *Service) FetchAllDevicesForUsername(ctx context.Context, requesterAccountID, username string) (proto.FetchDeviceKeyPackagesResponse, error) {
	accountID, err := s.deps.AccountLookup.AccountIDByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return proto.FetchDeviceKeyPackagesResponse{}, proto.APIError{
				Code: proto.ErrCodeAccountNotFound, Message: "account not found",
			}
		}
		return proto.FetchDeviceKeyPackagesResponse{}, apierr.Internal(err)
	}
	if err := s.checkClaimQuota(requesterAccountID, accountID); err != nil {
		return proto.FetchDeviceKeyPackagesResponse{}, err
	}
	pkgs, err := s.deps.Store.PopOnePerDevice(ctx, accountID)
	if err != nil {
		return proto.FetchDeviceKeyPackagesResponse{}, apierr.Internal(err)
	}
	s.chargeClaimQuota(requesterAccountID, accountID, len(pkgs))
	out := make([]proto.DeviceKeyPackage, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, proto.DeviceKeyPackage{DeviceID: p.DeviceID, KeyPackage: p.Payload})
	}
	return proto.FetchDeviceKeyPackagesResponse{Devices: out}, nil
}

// MaxOwnDeviceClaim caps how many packages one ClaimForOwnDevice call takes.
const MaxOwnDeviceClaim = 64

// ClaimForOwnDevice consumes up to count KeyPackages of targetDeviceID, which
// must be ANOTHER device of the caller's own account. A device adding a newly
// linked sibling to every existing conversation needs one fresh package per
// conversation; taking them in one call (instead of one lookup per
// conversation, each also burning a package of every OTHER device) lets the
// whole hand-off finish in the few seconds the phone is usually left open.
// Restricted to the caller's own account, so it can't drain anyone else.
func (s *Service) ClaimForOwnDevice(ctx context.Context, accountID, callerDeviceID, targetDeviceID string, count int) (proto.FetchDeviceKeyPackagesResponse, error) {
	if targetDeviceID == "" || targetDeviceID == callerDeviceID {
		return proto.FetchDeviceKeyPackagesResponse{}, proto.APIError{
			Code: proto.ErrCodeBadRequest, Message: "target must be another of your devices",
		}
	}
	if count < 1 {
		count = 1
	}
	if count > MaxOwnDeviceClaim {
		count = MaxOwnDeviceClaim
	}
	pkgs, err := s.deps.Store.PopForDevice(ctx, accountID, targetDeviceID, count)
	if err != nil {
		return proto.FetchDeviceKeyPackagesResponse{}, apierr.Internal(err)
	}
	out := make([]proto.DeviceKeyPackage, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, proto.DeviceKeyPackage{DeviceID: targetDeviceID, KeyPackage: p})
	}
	return proto.FetchDeviceKeyPackagesResponse{Devices: out}, nil
}

// Count returns how many packages the calling DEVICE has left. Clients refill
// from this number, so it must not include packages from the account's other
// devices: those can't stand in for this device's, and one device with spares
// kept another from ever topping up.
func (s *Service) Count(ctx context.Context, accountID, deviceID string) (proto.KeyPackageCountResponse, error) {
	n, err := s.deps.Store.CountUnconsumedByDevice(ctx, accountID, deviceID)
	if err != nil {
		return proto.KeyPackageCountResponse{}, apierr.Internal(err)
	}
	return proto.KeyPackageCountResponse{Count: n}, nil
}
