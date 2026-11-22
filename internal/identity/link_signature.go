package identity

import (
	"crypto/ed25519"
	"log"
)

// linkSignatureDomain is the context prefix of a domain-separated device-link
// signature. The identity key signs several things (session / restore
// challenges, username claims); without a context string a signature produced
// for one purpose is, byte-for-byte, a valid signature for another whenever the
// signed bytes coincide. The v1 link form (the raw 32-byte device pub key,
// what every deployed client sends) has no context.
const linkSignatureDomain = "nanb-device-link-v1:"

// LinkSignaturePayload is the canonical message a link approver signs:
// linkSignatureDomain followed by the new device's Ed25519 public key.
func LinkSignaturePayload(devicePubKey []byte) []byte {
	out := make([]byte, 0, len(linkSignatureDomain)+len(devicePubKey))
	out = append(out, linkSignatureDomain...)
	out = append(out, devicePubKey...)
	return out
}

// verifyLinkSignature reports whether signature authorises devicePubKey under
// identityPubKey. It accepts the domain-separated form (preferred) and, during
// the client transition, the legacy raw-pub-key form; a legacy acceptance is
// logged so the owner can see when no client sends it any more and can then
// delete the fallback below.
func verifyLinkSignature(identityPubKey, devicePubKey, signature []byte) bool {
	if len(identityPubKey) != ed25519.PublicKeySize {
		return false
	}
	pub := ed25519.PublicKey(identityPubKey)
	if ed25519.Verify(pub, LinkSignaturePayload(devicePubKey), signature) {
		return true
	}
	if ed25519.Verify(pub, devicePubKey, signature) {
		log.Printf("identity: device link accepted with LEGACY (un-prefixed) signature; client should sign %q||devicePubKey", linkSignatureDomain)
		return true
	}
	return false
}
