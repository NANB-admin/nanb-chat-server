package keypackages

import "errors"

// ClaimQuota bounds how many of a TARGET account's single-use key packages one
// REQUESTER account may claim per time window, so one account can't drain a
// victim's pool (there is no reusable last-resort package to fall back on, so
// an empty pool means nobody can add the victim's devices to a new group).
// Claims of the caller's OWN packages never go through it.
type ClaimQuota interface {
	// Allow reports whether requester may claim at least one more package of
	// target right now. It spends nothing.
	Allow(requesterAccountID, targetAccountID string) bool
	// Charge records that requester claimed n packages of target.
	Charge(requesterAccountID, targetAccountID string, n int)
}

// ErrClaimQuotaExceeded is returned by the fetch methods when the requester
// has used up its ClaimQuota for the target. The handlers answer 429.
var ErrClaimQuotaExceeded = errors.New("keypackages: claim quota for this account exceeded")
