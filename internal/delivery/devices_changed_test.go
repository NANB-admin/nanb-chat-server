package delivery_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/delivery"
	"github.com/nanb/nanb-server/internal/proto"
)

type recordingHub struct {
	sent map[string]proto.Envelope
}

func (h *recordingHub) Broadcast(deviceID string, env proto.Envelope) bool {
	h.sent[deviceID] = env
	return true
}

func TestDevicesChangedBroadcaster_SendsEphemeralFrameToEachDevice(t *testing.T) {
	hub := &recordingHub{sent: map[string]proto.Envelope{}}
	b := delivery.DevicesChangedBroadcaster{Hub: hub}

	b.NotifyDevicesChanged([]string{"dev-a", "dev-b"})

	assert.Len(t, hub.sent, 2)
	for _, id := range []string{"dev-a", "dev-b"} {
		env := hub.sent[id]
		assert.Equal(t, proto.EnvelopeTypeDevicesChanged, env.EnvelopeType)
		assert.Equal(t, id, env.RecipientDeviceID)
		assert.Empty(t, env.EnvelopeID, "ephemeral frame must not carry an ackable envelope id")
	}
}
