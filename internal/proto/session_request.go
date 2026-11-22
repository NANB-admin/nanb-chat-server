package proto

type ChallengeRequest struct {
	Username string `json:"username"`
	DeviceID string `json:"device_id"`
}

type ChallengeResponse struct {
	Challenge []byte `json:"challenge"`
	ExpiresAt int64  `json:"expires_at"`
}

type SessionRequest struct {
	Username  string `json:"username"`
	DeviceID  string `json:"device_id"`
	Challenge []byte `json:"challenge"`
	Signature []byte `json:"signature"`
}

type SessionResponse struct {
	JWT string `json:"jwt"`
}

// RestoreChallengeRequest is sent by a client that has the recovery phrase
// (and therefore a re-derived identity keypair) but does not know its
// device_id. The challenge it gets back is keyed by username only.
type RestoreChallengeRequest struct {
	Username string `json:"username"`
}

// RestoreSessionRequest completes the restore flow. The signature is over
// the issued challenge bytes, made with the client's identity private key.
type RestoreSessionRequest struct {
	Username       string `json:"username"`
	IdentityPubKey []byte `json:"identity_pub_key"`
	Challenge      []byte `json:"challenge"`
	Signature      []byte `json:"signature"`
	// DevicePubKey + X25519PubKey: when present, restore MINTS a fresh device
	// for the restoring phone (so it appears as a distinct linked device) and
	// REVOKES the account's other devices — "this phone is now my account".
	// Absent (older clients) → legacy behaviour: reuse the existing device id.
	DevicePubKey []byte `json:"device_pub_key,omitempty"`
	X25519PubKey []byte `json:"x25519_pub_key,omitempty"`
	// KeepOtherDevices: mint the new device but do NOT revoke the account's
	// others — "add this phone alongside my existing devices" (so a still-signed-in
	// device can hand over chat history). Default false keeps the takeover
	// semantics a lost/stolen phone needs. Ignored without DevicePubKey.
	KeepOtherDevices bool `json:"keep_other_devices,omitempty"`
}

// RestoreSessionResponse hands the client back its account_id + device_id
// (which it does not have on a freshly-installed device) along with a JWT.
type RestoreSessionResponse struct {
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
	JWT       string `json:"jwt"`
}
