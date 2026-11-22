package identity

import (
	"crypto/ed25519"
	"errors"
)

var ErrBadClaimSignature = errors.New("bad claim signature")

// UsernameClaimPayload is the canonical byte sequence the registrant signs to
// prove ownership of the identity keypair while claiming a username.
func UsernameClaimPayload(username string, identityPubKey []byte) []byte {
	out := make([]byte, 0, len(username)+1+len(identityPubKey)+len("nanb-username-claim-v1:"))
	out = append(out, []byte("nanb-username-claim-v1:")...)
	out = append(out, []byte(username)...)
	out = append(out, '|')
	out = append(out, identityPubKey...)
	return out
}

func VerifyUsernameClaim(username string, identityPubKey, signature []byte) error {
	if len(identityPubKey) != ed25519.PublicKeySize {
		return ErrBadClaimSignature
	}
	if len(signature) != ed25519.SignatureSize {
		return ErrBadClaimSignature
	}
	payload := UsernameClaimPayload(username, identityPubKey)
	if !ed25519.Verify(ed25519.PublicKey(identityPubKey), payload, signature) {
		return ErrBadClaimSignature
	}
	return nil
}
