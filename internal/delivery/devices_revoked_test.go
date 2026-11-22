package delivery_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/delivery"
)

type recordingDisconnector struct{ ids []string }

func (r *recordingDisconnector) Disconnect(id string) bool {
	r.ids = append(r.ids, id)
	return true
}

type recordingForgetter struct{ ids []string }

func (r *recordingForgetter) Forget(id string) { r.ids = append(r.ids, id) }

func TestRevokedDeviceKicker_DisconnectsEachDevice(t *testing.T) {
	hub := &recordingDisconnector{}
	k := &delivery.RevokedDeviceKicker{Hub: hub}

	k.NotifyDevicesRevoked([]string{"dev-1", "dev-2"})

	assert.Equal(t, []string{"dev-1", "dev-2"}, hub.ids)
}

func TestRevokedDeviceKicker_ForgetsCachedLiveness(t *testing.T) {
	cache := &recordingForgetter{}
	k := &delivery.RevokedDeviceKicker{Hub: &recordingDisconnector{}, Liveness: cache}

	k.NotifyDevicesRevoked([]string{"dev-1"})

	assert.Equal(t, []string{"dev-1"}, cache.ids)
}
