package proto

// SetDeviceCapabilitiesRequest is the (optional) body of
// POST /devices/me/capabilities. Auth-gated: a device only ever describes
// ITSELF, since the target is taken from the JWT's device claim, never the body.
//
// The body is optional so older clients, which POST an empty request purely to
// advertise sealed-receive support, keep working unchanged.
type SetDeviceCapabilitiesRequest struct {
	// X25519PubKey is the device's CURRENT sealing public key. Peers encrypt the
	// sealed-sender outer layer to it, so a device whose local keypair no longer
	// matches the copy published here is unreachable: every peer keeps sealing to
	// the dead key, the device cannot open a single envelope, and — because the
	// receive path acks what it cannot open — the messages are destroyed rather
	// than retried. Nothing in the protocol surfaces that to the sender, who sees
	// a normal delivery.
	//
	// Re-publishing it on every connect makes the condition self-healing: the
	// device is the authority on its own key, and this is the only write path for
	// it after registration. Omitted/empty leaves the stored key untouched.
	X25519PubKey []byte `json:"x25519_pub_key,omitempty"`
}
