package delivery

import "github.com/nanb/nanb-server/internal/proto"

// DevicesChangedBroadcaster pushes the ephemeral devices_changed signal to the
// given devices over their live WebSockets. It satisfies
// identity.DevicesChangedNotifier. The frame carries no content and is never
// persisted: a device that is offline misses it and reconciles on connect.
type DevicesChangedBroadcaster struct {
	Hub HubAPI
}

func (b DevicesChangedBroadcaster) NotifyDevicesChanged(deviceIDs []string) {
	for _, id := range deviceIDs {
		b.Hub.Broadcast(id, proto.Envelope{
			Version:           "v1",
			Domain:            "nanb.link",
			EnvelopeType:      proto.EnvelopeTypeDevicesChanged,
			RecipientDeviceID: id,
		})
	}
}
