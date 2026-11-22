package proto

type CreateAccountRequest struct {
	Username          string   `json:"username"`
	IdentityPubKey    []byte   `json:"identity_pub_key"`
	X25519PubKey      []byte   `json:"x25519_pub_key,omitempty"`
	DevicePubKey      []byte   `json:"device_pub_key"`
	DeviceDisplayName string   `json:"device_display_name,omitempty"`
	SignedClaim       []byte   `json:"signed_claim"`
	KeyPackages       [][]byte `json:"key_packages"`
}

type CreateAccountResponse struct {
	AccountID string `json:"account_id"`
	DeviceID  string `json:"device_id"`
	JWT       string `json:"jwt"`
}

type DeleteAccountResponse struct {
	OK bool `json:"ok"`
}

// UpdateProfileRequest is the body of PATCH /accounts/me. Fields are pointers
// so the caller can update display_name and avatar_url independently — a nil
// field is left unchanged, an empty string clears it.
type UpdateProfileRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
}

// LinkDeviceRequest authorizes a brand-new device onto the caller's account.
// The caller is an already-authenticated device (JWT); it proves the link was
// approved by the recovery-phrase holder via SignedLink — the account identity
// key's signature over the new device's Ed25519 pub key. The new device
// generates its own Ed25519 (for session auth) and X25519 (for the ratchet)
// keypairs; neither is derived from the recovery phrase.
type LinkDeviceRequest struct {
	DevicePubKey      []byte   `json:"device_pub_key"`
	X25519PubKey      []byte   `json:"x25519_pub_key"`
	DeviceDisplayName string   `json:"device_display_name,omitempty"`
	SignedLink        []byte   `json:"signed_link"`
	KeyPackages       [][]byte `json:"key_packages"`
	// Kind is optional: "phone" (default) or "web". Web devices expire.
	Kind string `json:"kind,omitempty"`
}

type LinkDeviceResponse struct {
	DeviceID string `json:"device_id"`
	LinkedAt string `json:"linked_at"`
}

// PendingDeviceResponse is returned by the unauthenticated link-status poll a
// freshly-keyed device runs (keyed by its own high-entropy pub key) to learn
// its server-assigned device_id + account once the primary has authorized it.
// Linked=false until the link lands.
type PendingDeviceResponse struct {
	Linked    bool   `json:"linked"`
	AccountID string `json:"account_id,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`
	Username  string `json:"username,omitempty"`
}

// UsernameAvailability is the response of GET /usernames/{username}.
// Taken/held/invalid names are a 200 with Available=false (not an error) so
// the signup screen can render inline feedback before the user invests in a
// recovery phrase. Reason is one of "invalid", "taken", "on_hold".
type UsernameAvailability struct {
	Username  string `json:"username"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}
