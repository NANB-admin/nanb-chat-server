package delivery

import (
	"time"

	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/httputil"
	"github.com/nanb/nanb-server/internal/ratelimit"
)

// Budgets for FAILED unidentified-access attempts on POST /messages/sealed.
// Successful sealed sends are never counted or throttled (the owner's
// no-send-limits rule); only wrong/stale access keys are.
//
//   - per (client, recipient device): how many failures one source may rack up
//     against one device before its attempts to THAT device are refused
//     without a lookup. A legitimate client only fails with a stale key, and
//     falls back to the authenticated path on the 403 anyway.
//   - per clearnet client: caps one source spraying failures across many
//     devices (each a DB lookup). Not applied to onion traffic, which is all
//     one key: a Tor attacker exhausting it would push EVERY Tor user off the
//     sealed path. Onion floods are bounded per target device only.
const (
	uakFailPerTargetBurst = 20
	uakFailPerTargetEvery = 3 * time.Second
	uakFailPerClientBurst = 120
	uakFailPerClientRate  = 2 // per second
	uakFailMaxTargets     = 50000
	uakFailMaxClients     = 20000
)

// AccessKeyFailureLimiter throttles repeated FAILED access-key attempts. It is
// consulted before verification (so a source that keeps failing stops costing
// lookups) and charged only after a verification fails.
type AccessKeyFailureLimiter struct {
	perTarget *ratelimit.Keyed
	perClient *ratelimit.Keyed
}

// NewAccessKeyFailureLimiter builds the limiter. now is injectable for tests;
// nil means time.Now.
func NewAccessKeyFailureLimiter(now func() time.Time) *AccessKeyFailureLimiter {
	return &AccessKeyFailureLimiter{
		perTarget: ratelimit.NewKeyed(ratelimit.KeyedConfig{
			Rate:    rate.Every(uakFailPerTargetEvery),
			Burst:   uakFailPerTargetBurst,
			MaxKeys: uakFailMaxTargets,
		}, now),
		perClient: ratelimit.NewKeyed(ratelimit.KeyedConfig{
			Rate:    rate.Limit(uakFailPerClientRate),
			Burst:   uakFailPerClientBurst,
			MaxKeys: uakFailMaxClients,
		}, now),
	}
}

// Blocked reports whether clientKey has failed too often recently (against
// recipientDeviceID, or — clearnet only — overall) to be allowed another try.
func (l *AccessKeyFailureLimiter) Blocked(clientKey, recipientDeviceID string) bool {
	if !l.perTarget.HasTokens(targetKey(clientKey, recipientDeviceID), 1) {
		return true
	}
	return clientKey != httputil.OnionClientKey && !l.perClient.HasTokens(clientKey, 1)
}

// RecordFailure charges one failed attempt by clientKey against recipientDeviceID.
func (l *AccessKeyFailureLimiter) RecordFailure(clientKey, recipientDeviceID string) {
	l.perTarget.Charge(targetKey(clientKey, recipientDeviceID), 1)
	if clientKey != httputil.OnionClientKey {
		l.perClient.Charge(clientKey, 1)
	}
}

func targetKey(clientKey, recipientDeviceID string) string {
	return clientKey + "|" + recipientDeviceID
}
