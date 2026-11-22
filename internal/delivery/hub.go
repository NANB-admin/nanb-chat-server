package delivery

import (
	"sync"

	"github.com/nanb/nanb-server/internal/proto"
)

// Conn is the abstraction over a single client connection so tests can inject
// fakes without real WebSockets. Production wires *WSConn (defined in handlers.go).
type Conn interface {
	WriteEnvelope(env proto.Envelope) error
}

// Hub keeps an in-memory map device_id → Conn. Safe for concurrent use.
type Hub struct {
	mu    sync.Mutex
	conns map[string]Conn
}

func NewHub() *Hub {
	return &Hub{conns: map[string]Conn{}}
}

// Register associates a device with a connection, replacing any prior conn for the same device.
func (h *Hub) Register(deviceID string, conn Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conns[deviceID] = conn
}

// Unregister removes the connection for a device only if it matches conn.
// Avoids races where a stale Unregister erases a fresh registration.
func (h *Hub) Unregister(deviceID string, conn Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur, ok := h.conns[deviceID]; ok && cur == conn {
		delete(h.conns, deviceID)
	}
}

// Disconnect closes and forgets [deviceID]'s live connection, if it has one,
// and reports whether it did. Used when the device is revoked: the handshake
// refuses a revoked device, but a socket opened before the revoke stayed up.
func (h *Hub) Disconnect(deviceID string) bool {
	h.mu.Lock()
	conn, ok := h.conns[deviceID]
	if ok {
		delete(h.conns, deviceID)
	}
	h.mu.Unlock()
	if !ok {
		return false
	}
	if c, closable := conn.(interface{ Close() error }); closable {
		_ = c.Close()
	}
	return true
}

// Broadcast delivers an envelope to the device's current connection if registered.
// Returns true if the envelope was successfully written; false if not registered
// or write failed (caller can decide to fall back to push notification).
func (h *Hub) Broadcast(deviceID string, env proto.Envelope) bool {
	h.mu.Lock()
	conn, ok := h.conns[deviceID]
	h.mu.Unlock()
	if !ok {
		return false
	}
	if err := conn.WriteEnvelope(env); err != nil {
		return false
	}
	return true
}
