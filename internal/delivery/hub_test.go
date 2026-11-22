package delivery_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/delivery"
	"github.com/nanb/nanb-server/internal/proto"
)

type fakeConn struct {
	mu        sync.Mutex
	received  []proto.Envelope
	writeFail bool
}

func (f *fakeConn) WriteEnvelope(env proto.Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeFail {
		return errors.New("write failed")
	}
	f.received = append(f.received, env)
	return nil
}

func (f *fakeConn) snapshot() []proto.Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]proto.Envelope, len(f.received))
	copy(cp, f.received)
	return cp
}

func makeEnv(id, recipientDevice string) proto.Envelope {
	return proto.Envelope{
		EnvelopeID:        id,
		RecipientDeviceID: recipientDevice,
		ServerTS:          time.Now(),
	}
}

func TestHub_BroadcastDeliversToRegisteredDevice(t *testing.T) {
	h := delivery.NewHub()
	conn := &fakeConn{}

	h.Register("dev-1", conn)
	defer h.Unregister("dev-1", conn)

	h.Broadcast("dev-1", makeEnv("env-1", "dev-1"))

	got := conn.snapshot()
	assert.Len(t, got, 1)
	assert.Equal(t, "env-1", got[0].EnvelopeID)
}

func TestHub_BroadcastSkipsUnregisteredDevice(t *testing.T) {
	h := delivery.NewHub()

	h.Broadcast("dev-other", makeEnv("env-1", "dev-other"))
	// No assertion needed — must not panic.
}

func TestHub_UnregisterStopsDelivery(t *testing.T) {
	h := delivery.NewHub()
	conn := &fakeConn{}

	h.Register("dev-1", conn)
	h.Unregister("dev-1", conn)

	h.Broadcast("dev-1", makeEnv("env-1", "dev-1"))
	assert.Empty(t, conn.snapshot())
}

func TestHub_UnregisterIgnoresMismatchedConn(t *testing.T) {
	h := delivery.NewHub()
	conn1 := &fakeConn{}
	conn2 := &fakeConn{}

	h.Register("dev-1", conn1)
	h.Unregister("dev-1", conn2) // wrong conn — should not affect conn1

	h.Broadcast("dev-1", makeEnv("env-1", "dev-1"))
	assert.Len(t, conn1.snapshot(), 1)
}

func TestHub_BroadcastWriteFailureReturnsFalse(t *testing.T) {
	h := delivery.NewHub()
	conn := &fakeConn{writeFail: true}

	h.Register("dev-1", conn)
	defer h.Unregister("dev-1", conn)

	delivered := h.Broadcast("dev-1", makeEnv("env-1", "dev-1"))
	assert.False(t, delivered)
}

func TestHub_BroadcastReturnsTrueOnSuccess(t *testing.T) {
	h := delivery.NewHub()
	conn := &fakeConn{}

	h.Register("dev-1", conn)
	defer h.Unregister("dev-1", conn)

	delivered := h.Broadcast("dev-1", makeEnv("env-1", "dev-1"))
	assert.True(t, delivered)
}

func TestHub_BroadcastReturnsFalseWhenNotRegistered(t *testing.T) {
	h := delivery.NewHub()

	delivered := h.Broadcast("dev-other", makeEnv("env-1", "dev-other"))
	assert.False(t, delivered)
}

type closableConn struct {
	fakeConn
	closed int
}

func (c *closableConn) Close() error {
	c.closed++
	return nil
}

func TestHub_Disconnect_ClosesTheConnection(t *testing.T) {
	h := delivery.NewHub()
	c := &closableConn{}
	h.Register("dev-1", c)

	assert.True(t, h.Disconnect("dev-1"))
	assert.Equal(t, 1, c.closed)
}

func TestHub_Disconnect_StopsDeliveryToTheDevice(t *testing.T) {
	h := delivery.NewHub()
	h.Register("dev-1", &closableConn{})

	h.Disconnect("dev-1")

	assert.False(t, h.Broadcast("dev-1", makeEnv("e1", "dev-1")))
}

func TestHub_Disconnect_UnknownDeviceIsANoop(t *testing.T) {
	assert.False(t, delivery.NewHub().Disconnect("dev-1"))
}
