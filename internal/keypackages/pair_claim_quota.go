package keypackages

import (
	"time"

	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/ratelimit"
)

// Default per-(requester, target) claim budget: 60 packages, refilling one a
// minute. Real use is bursty and small — starting a chat with a contact takes
// one package per contact device, so a burst of 60 covers adding a 3-device
// contact to 20 new chats at once — while a drainer gets at most ~60 an hour
// per attacking account, which the target's replenisher (refills 50 whenever
// it drops under 10) easily outpaces.
const (
	DefaultClaimQuotaBurst = 60
	DefaultClaimQuotaEvery = time.Minute
	// defaultClaimQuotaMaxPairs bounds the tracked (requester, target) pairs.
	defaultClaimQuotaMaxPairs = 100000
)

// PairClaimQuota is the production ClaimQuota: a token bucket per
// (requester, target) pair.
type PairClaimQuota struct {
	buckets *ratelimit.Keyed
}

// NewPairClaimQuota builds a quota of burst packages per pair, refilling one
// every `every`. now is injectable for tests; nil means time.Now.
func NewPairClaimQuota(burst int, every time.Duration, now func() time.Time) *PairClaimQuota {
	return &PairClaimQuota{buckets: ratelimit.NewKeyed(ratelimit.KeyedConfig{
		Rate:    rate.Every(every),
		Burst:   burst,
		MaxKeys: defaultClaimQuotaMaxPairs,
	}, now)}
}

// Allow implements ClaimQuota.
func (q *PairClaimQuota) Allow(requesterAccountID, targetAccountID string) bool {
	return q.buckets.HasTokens(pairKey(requesterAccountID, targetAccountID), 1)
}

// Charge implements ClaimQuota.
func (q *PairClaimQuota) Charge(requesterAccountID, targetAccountID string, n int) {
	q.buckets.Charge(pairKey(requesterAccountID, targetAccountID), n)
}

func pairKey(requesterAccountID, targetAccountID string) string {
	return requesterAccountID + "|" + targetAccountID
}
