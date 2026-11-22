package ratelimit

import "golang.org/x/time/rate"

// KeyedConfig sizes a Keyed limiter: every key gets its own token bucket of
// Burst tokens refilling at Rate, and at most MaxKeys buckets are tracked at
// once (see Keyed for what happens at the cap).
type KeyedConfig struct {
	Rate    rate.Limit
	Burst   int
	MaxKeys int
}
