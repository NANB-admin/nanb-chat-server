package main

import (
	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/httputil"
)

// Budgets for the UNAUTHENTICATED identity-write endpoints (POST /accounts,
// /sessions/challenge, /sessions/restore/challenge), which share one limiter.
//
// These used to be ONE process-global bucket (20/s) for the whole fleet, so a
// single script could hold it empty and lock everybody out of sign-up and
// login. Now every client key (client IP, see httputil.ClientIPResolver) has
// its own bucket; Tor users share a separate onion bucket (the server can't
// tell them apart, but clearnet abuse can't touch it); and a far larger global
// ceiling only caps total load from a widely distributed flood.
//
// Per client: a login is one challenge, a sign-up one account create, so 30 in
// a burst and one every 2s sustained is generous even behind a shared NAT.
func identityWriteLimits() httputil.ClientRateLimitConfig {
	return httputil.ClientRateLimitConfig{
		PerClientRate:  rate.Limit(0.5),
		PerClientBurst: 30,
		OnionRate:      rate.Limit(10),
		OnionBurst:     60,
		CeilingRate:    rate.Limit(200),
		CeilingBurst:   400,
		MaxClients:     100000,
	}
}

// Budgets for GET /usernames/{username} (pre-signup availability checks —
// possibly one per keystroke), same shape as identityWriteLimits: per client so
// one enumerator can't starve real sign-ups, with an onion bucket of its own.
func usernameLookupLimits() httputil.ClientRateLimitConfig {
	return httputil.ClientRateLimitConfig{
		PerClientRate:  rate.Limit(5),
		PerClientBurst: 40,
		OnionRate:      rate.Limit(30),
		OnionBurst:     120,
		CeilingRate:    rate.Limit(500),
		CeilingBurst:   1000,
		MaxClients:     100000,
	}
}
