package turn

import (
	"time"

	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/ratelimit"
)

// Credential minting is bounded per account. coturn's user-quota only caps
// allocations per USERNAME, so an account that could mint unlimited credentials
// would sidestep it; with step-stable usernames (see expiryFor) the quota binds,
// and this limit stops a client hammering the endpoint to churn credentials.
// 30/minute is far above any real use (a call fetches once, clients cache for
// hours) — a burst of 30 then 0.5/s.
const (
	mintBurst       = 30
	mintRefillEvery = 2 * time.Second
	mintMaxAccounts = 100_000
)

func newMintLimiter(now func() time.Time) *ratelimit.Keyed {
	return ratelimit.NewKeyed(ratelimit.KeyedConfig{
		Rate:    rate.Every(mintRefillEvery),
		Burst:   mintBurst,
		MaxKeys: mintMaxAccounts,
	}, now)
}
