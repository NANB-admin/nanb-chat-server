package delivery

// LivenessForgetter drops a device's cached liveness (see NewCachedResolver).
type LivenessForgetter interface {
	Forget(deviceID string)
}

// DeviceDisconnector closes a device's live connection (see Hub.Disconnect).
type DeviceDisconnector interface {
	Disconnect(deviceID string) bool
}

// RevokedDeviceKicker satisfies identity.DevicesRevokedNotifier: it forgets
// each revoked device's cached liveness, so its sends and REST calls are
// refused at once instead of after the cache TTL, then closes its open
// WebSocket. Liveness is optional (nil skips it).
type RevokedDeviceKicker struct {
	Hub      DeviceDisconnector
	Liveness LivenessForgetter
}

func (k *RevokedDeviceKicker) NotifyDevicesRevoked(deviceIDs []string) {
	for _, id := range deviceIDs {
		if k.Liveness != nil {
			k.Liveness.Forget(id)
		}
		k.Hub.Disconnect(id)
	}
}
