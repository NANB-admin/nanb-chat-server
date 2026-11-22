package identity

import (
	"encoding/hex"

	"github.com/nanb/nanb-server/internal/crypto"
)

// Challenge storage keys.
//
// Every issued challenge is stored under its OWN key — scope plus the
// challenge bytes themselves — so any number can be outstanding for one
// account at once, each single-use and expiring on its own. Keying by scope
// alone (one slot per account/device) let anybody who knew a username lock its
// owner out of login and phrase-restore: each challenge request overwrote the
// pending one, and even a bogus completion consumed (deleted) it before the
// signature was checked. Now a challenge can only be consumed by someone who
// presents its exact bytes, i.e. the party it was issued to.

// sessionChallengeKey is the key of a login challenge for (username, device).
func sessionChallengeKey(username, deviceID string, challenge []byte) string {
	return username + "|" + deviceID + "|" + hex.EncodeToString(challenge)
}

// restoreChallengeKey is the key of a phrase-restore challenge for username.
func restoreChallengeKey(username string, challenge []byte) string {
	return "restore|" + username + "|" + hex.EncodeToString(challenge)
}

// wellFormedChallenge reports whether presented could be a challenge this
// server issued; anything else can't match a stored key and is not looked up.
func wellFormedChallenge(presented []byte) bool {
	return len(presented) == crypto.ChallengeLen
}
