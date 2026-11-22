package proto

import "time"

// Envelope is the universal wire payload. The server only reads metadata fields;
// Ciphertext is opaque MLS-encrypted bytes that the server cannot decrypt.
type Envelope struct {
	EnvelopeID         string    `json:"envelope_id"`
	Version            string    `json:"version"`
	Domain             string    `json:"domain"`
	EnvelopeType       string    `json:"envelope_type"`
	ConversationID     string    `json:"conversation_id"`
	SenderDeviceID     string    `json:"sender_device_id"`
	RecipientAccountID string    `json:"recipient_account_id"`
	RecipientDeviceID  string    `json:"recipient_device_id"`
	Ciphertext         []byte    `json:"ciphertext"`
	ServerTS           time.Time `json:"server_ts"`
}

// EnvelopeType values used by clients. Server treats these as opaque tags.
const (
	EnvelopeTypeMLSApplication    = "mls_application"     // MLS Application (message)
	EnvelopeTypeMLSHandshake      = "mls_handshake"       // MLS Handshake (commits, proposals)
	EnvelopeTypeMLSWelcome        = "mls_welcome"         // MLS Welcome (group invitation)
	EnvelopeTypeKeyPackagePublish = "key_package_publish" // Key package for device registration
	EnvelopeTypeMediaEnvelope     = "media_envelope"      // Media attachment wrapper
	EnvelopeTypeTextLegacy        = "text_legacy"         // pre-MLS ratchet ciphertext
	// EnvelopeTypeTyping is an EPHEMERAL signal relayed over the WebSocket and
	// never persisted (no envelope_id, not stored/catchup-able). Ciphertext is
	// a single byte: 1 = typing, 0 = stopped.
	EnvelopeTypeTyping = "typing"
	// EnvelopeTypeDeliveryStatus is an EPHEMERAL, SERVER-ORIGINATED signal sent
	// to a message's ORIGINAL SENDER device when one of the recipient's devices
	// confirms a wakeup push physically landed (a transport-level "delivered",
	// ahead of the recipient opening the app). Never persisted/catchup-able.
	// Ciphertext is the UTF-8 envelope id that was delivered, so the sender can
	// match it to its outgoing message. Carries NO encrypted content — the
	// server has no keys.
	EnvelopeTypeDeliveryStatus = "delivery_status"
	// EnvelopeTypeDevicesChanged is an EPHEMERAL, SERVER-ORIGINATED signal sent
	// to an account's already-connected devices when a new device is linked, so
	// the old device responsible for adding it to existing MLS 1:1 groups can do
	// so now instead of at its next reconnect. No content, no envelope id, never
	// persisted/catchup-able — a device that misses it reconciles on connect.
	EnvelopeTypeDevicesChanged = "devices_changed"
	// EnvelopeTypeSealed is a sealed-sender (Phase 1) outer wrapper. The payload
	// is an opaque per-recipient blob; the real type/conversation/sender live
	// inside it, encrypted to the recipient device. The server stores it with
	// EMPTY conversation_id + sender_device_id (it never learns them), routing
	// only by recipient device. See docs/sealed-sender-design.md.
	EnvelopeTypeSealed = "sealed"
)

// SealedSentinelUUID is stored in the UUID columns (conversation_id,
// sender_device_id) of a sealed envelope instead of the real values: the server
// must not learn them, but those columns are `uuid NOT NULL`, so an empty string
// is rejected (invalid uuid). The all-zero UUID is a valid, CONSTANT value — the
// same for every sealed envelope — so it carries no conversation/sender info and
// can't link a pair. (Sealed FIFO eviction is per-device, not per-conversation,
// so the constant conversation_id is never grouped on.)
const SealedSentinelUUID = "00000000-0000-0000-0000-000000000000"
