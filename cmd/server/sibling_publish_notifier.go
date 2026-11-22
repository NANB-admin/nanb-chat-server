package main

import (
	"context"
	"log"
	"time"

	"github.com/nanb/nanb-server/internal/proto"
)

// activeDeviceLister is the slice of the identity store this needs.
type activeDeviceLister interface {
	ListActiveDevicesByAccountID(ctx context.Context, accountID string) ([]proto.Device, error)
}

// devicesChangedSender is the delivery broadcaster's signature.
type devicesChangedSender interface {
	NotifyDevicesChanged(deviceIDs []string)
}

// siblingPublishNotifier tells a device's siblings that it just published
// KeyPackages, as the existing devices_changed signal. A device left out of a
// group because it had no packages can be added back the moment it has some,
// instead of whenever a sibling next reconnects. Detached and best-effort: a
// sibling that misses it still finds the gap on its own schedule.
type siblingPublishNotifier struct {
	devices activeDeviceLister
	changed devicesChangedSender
}

func (n siblingPublishNotifier) KeyPackagesPublished(accountID, deviceID string) {
	go n.notify(accountID, deviceID)
}

func (n siblingPublishNotifier) notify(accountID, deviceID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	devices, err := n.devices.ListActiveDevicesByAccountID(ctx, accountID)
	if err != nil {
		log.Printf("key packages: sibling notify for %s skipped: %v", deviceID, err)
		return
	}
	siblings := make([]string, 0, len(devices))
	for _, d := range devices {
		if d.DeviceID != deviceID {
			siblings = append(siblings, d.DeviceID)
		}
	}
	if len(siblings) > 0 {
		n.changed.NotifyDevicesChanged(siblings)
	}
}
