package turn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// usernameLabel domain-separates the username-derivation key from the coturn
// shared secret itself (the same secret also keys the credential HMAC).
const usernameLabel = "nanb-turn-username-v1"

// expiryStepDivisor splits the TTL into steps: every credential minted inside
// one step gets the SAME expiry (rounded up to the step), hence the same
// username, so coturn's per-username user-quota groups all of one account's
// allocations in that step instead of seeing a fresh username per request.
// Validity ends up in [TTL, TTL+TTL/divisor), never shorter than the TTL.
const expiryStepDivisor = 6

// minExpiryStep keeps tiny test/dev TTLs from degenerating to a zero step.
const minExpiryStep = time.Second

// expiryFor returns the credential expiry for a request at now: now+ttl rounded
// UP to the next step boundary.
func expiryFor(now time.Time, ttl time.Duration) time.Time {
	step := ttl / expiryStepDivisor
	if step < minExpiryStep {
		step = minExpiryStep
	}
	stepSecs := int64(step / time.Second)
	target := now.Add(ttl).Unix()
	rounded := ((target + stepSecs - 1) / stepSecs) * stepSecs
	return time.Unix(rounded, 0)
}

// opaqueID derives the stable, non-reversible per-account identifier that goes
// into the TURN username after the expiry. It is an HMAC of the account id and
// the expiry under a key derived from the server secret, so:
//   - the real account id never appears in coturn's logs or on the wire;
//   - the same account maps to the same id for every credential sharing an
//     expiry (quota grouping), and to an unlinkable new id when the expiry
//     advances;
//   - nobody without the secret can compute or enumerate another account's id.
func opaqueID(secret, accountID string, expiry time.Time) string {
	keyMac := hmac.New(sha256.New, []byte(secret))
	keyMac.Write([]byte(usernameLabel))
	key := keyMac.Sum(nil)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(accountID))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.FormatInt(expiry.Unix(), 10)))
	return hex.EncodeToString(mac.Sum(nil))[:24]
}
