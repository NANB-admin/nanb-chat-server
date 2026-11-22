package identity

import (
	"context"

	"github.com/nanb/nanb-server/internal/apierr"
	"github.com/nanb/nanb-server/internal/proto"
)

// ensureDeviceCapacity fails with the same ErrCodeDeviceLimit the link flow
// uses when the account already holds MaxDevicesPerAccount active devices. A
// restore that KEEPS the other devices adds a device without revoking any, so
// it must honour the cap exactly like a link; the default takeover restore
// revokes the rest and therefore never needs this check.
func (s *Service) ensureDeviceCapacity(ctx context.Context, accountID string) error {
	active, err := s.deps.Store.ListActiveDevicesByAccountID(ctx, accountID)
	if err != nil {
		return apierr.Internal(err)
	}
	if len(active) >= MaxDevicesPerAccount {
		return proto.APIError{Code: proto.ErrCodeDeviceLimit, Message: "device limit reached"}
	}
	return nil
}
