package httputil

import "golang.org/x/time/rate"

// ClientRateLimitConfig sizes a ClientRateLimiter.
//
//   - PerClient*: each clearnet client key's own bucket (the primary limit).
//   - Onion*: the single bucket all onion traffic shares (Tor clients are
//     indistinguishable), kept apart so clearnet abuse can't starve it.
//   - Ceiling*: a generous process-wide safety ceiling over ALL clearnet keys
//     together, only there to cap total load from a widely distributed flood.
//   - MaxClients: how many per-client buckets are tracked at once.
type ClientRateLimitConfig struct {
	PerClientRate  rate.Limit
	PerClientBurst int
	OnionRate      rate.Limit
	OnionBurst     int
	CeilingRate    rate.Limit
	CeilingBurst   int
	MaxClients     int
}
