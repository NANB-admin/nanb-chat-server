package proto

import "time"

type SubmitMessageRequest struct {
	ConversationID     string   `json:"conversation_id"`
	EnvelopeType       string   `json:"envelope_type"`
	RecipientAccountID string   `json:"recipient_account_id"`
	RecipientDeviceID  string   `json:"recipient_device_id,omitempty"`  // singular path
	RecipientDeviceIDs []string `json:"recipient_device_ids,omitempty"` // plural path (MLS broadcast)
	Ciphertext         []byte   `json:"ciphertext"`

	// TTLSeconds optionally shortens the envelope's retention below the
	// server default (the sender's delete-messages-after preference). The
	// server only honors it DOWNWARD — 0/omitted means the server default.
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`

	// PushKind is a NON-encrypted hint that shapes the offline wakeup push.
	// Content stays E2EE; this only tells the server which push style to send.
	// Empty for a normal message (offline-only "new message" wakeup).
	//   - "call"   — a closed device rings (full-screen) instead of a banner,
	//                and the wakeup fires even when the hub reports delivered.
	//   - "call_cancel" — a "stop ringing" call signal (answered on another
	//                device / caller gave up); wakes a closed device so it can
	//                dismiss its ring, shows nothing, and expires with the ring.
	//   - "silent" — a control/protocol-only envelope (receipt, reaction, pin,
	//                MLS Welcome, access-key share); never fires an offline
	//                wakeup, so it can't buzz the peer with a phantom banner.
	PushKind string `json:"push_kind,omitempty"`

	// AccessKey is the recipient's unidentified-access key (UAK), presented on
	// the UNAUTHENTICATED sealed-send path (POST /messages/sealed) INSTEAD of a
	// JWT. The server verifies H(AccessKey) against the recipient account's
	// stored commitment to authorize the deposit without learning the sender.
	// Only meaningful for sealed sends on the unauth path; ignored elsewhere.
	AccessKey []byte `json:"access_key,omitempty"`
}

// SetAccessKeyRequest publishes (or rotates) the caller's unidentified-access-key
// commitment — H(UAK), a 32-byte SHA-256 digest. The server stores only this
// commitment, never the UAK. Auth-gated (the caller sets its own account's value).
type SetAccessKeyRequest struct {
	Commitment []byte `json:"commitment"`
}

type SubmitMessageResponse struct {
	// EnvelopeID is the id of the (single) inserted envelope when the request
	// used the singular RecipientDeviceID. Empty when the plural path was used.
	EnvelopeID string `json:"envelope_id,omitempty"`

	// EnvelopeIDs lists the ids of every inserted envelope when the plural
	// path was used. Empty when the singular path was used.
	EnvelopeIDs []string `json:"envelope_ids,omitempty"`

	ServerTS time.Time `json:"server_ts"`
}

type CatchupRequest struct {
	SinceServerTS time.Time `json:"since_server_ts,omitempty"`
	Limit         int       `json:"limit,omitempty"`
}

type CatchupResponse struct {
	Envelopes []Envelope `json:"envelopes"`
}

type AckRequest struct {
	EnvelopeIDs []string `json:"envelope_ids"`
}

type AckResponse struct {
	AckedCount int `json:"acked_count"`
}

// ConfirmReceivedRequest is posted by a recipient device's background push
// handler to confirm a wakeup push for the envelope physically landed — a
// transport-level "delivered" that does NOT decrypt or ack the envelope.
type ConfirmReceivedRequest struct {
	EnvelopeID string `json:"envelope_id"`
}

// ConfirmReceivedResponse reports whether this confirmation triggered a
// delivery-status relay to the sender. Relayed is true only on the FIRST
// confirmation for an envelope AND when the sender had a live connection;
// false covers duplicates (a redelivered push), envelopes not addressed to
// the caller, and an offline sender — all benign no-ops.
type ConfirmReceivedResponse struct {
	Relayed bool `json:"relayed"`
}
