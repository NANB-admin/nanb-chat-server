package ratelimit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/ratelimit"
)

// manualClock is a test clock that only moves when told to.
type manualClock struct{ t time.Time }

func (c *manualClock) now() time.Time          { return c.t }
func (c *manualClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *manualClock {
	return &manualClock{t: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
}

func newKeyed(clock *manualClock, burst, maxKeys int) *ratelimit.Keyed {
	return ratelimit.NewKeyed(ratelimit.KeyedConfig{
		Rate:    rate.Every(time.Minute),
		Burst:   burst,
		MaxKeys: maxKeys,
	}, clock.now)
}

func TestKeyed_Allow_AdmitsUpToTheBurst(t *testing.T) {
	k := newKeyed(newClock(), 3, 10)
	admitted := 0
	for i := 0; i < 5; i++ {
		if k.Allow("a") {
			admitted++
		}
	}
	assert.Equal(t, 3, admitted)
}

func TestKeyed_Allow_OneKeyExhaustedLeavesAnotherUntouched(t *testing.T) {
	k := newKeyed(newClock(), 2, 10)
	k.Allow("attacker")
	k.Allow("attacker")
	k.Allow("attacker")

	assert.True(t, k.Allow("victim"))
}

func TestKeyed_Allow_RefillsOverTime(t *testing.T) {
	clock := newClock()
	k := newKeyed(clock, 1, 10)
	k.Allow("a")

	clock.advance(time.Minute)

	assert.True(t, k.Allow("a"))
}

func TestKeyed_HasTokens_DoesNotSpend(t *testing.T) {
	k := newKeyed(newClock(), 1, 10)
	k.HasTokens("a", 1)
	k.HasTokens("a", 1)

	assert.True(t, k.Allow("a"))
}

func TestKeyed_HasTokens_UnknownKeyHasAFullBucket(t *testing.T) {
	k := newKeyed(newClock(), 5, 10)

	assert.True(t, k.HasTokens("never-seen", 5))
}

func TestKeyed_Charge_PutsTheKeyInDebt(t *testing.T) {
	clock := newClock()
	k := newKeyed(clock, 3, 10)
	k.Charge("a", 3)
	k.Charge("a", 3)

	clock.advance(2 * time.Minute) // refills 2 of the 3 tokens owed

	assert.False(t, k.HasTokens("a", 1))
}

func TestKeyed_Charge_NonPositiveIsANoOp(t *testing.T) {
	k := newKeyed(newClock(), 1, 10)
	k.Charge("a", 0)

	assert.True(t, k.Allow("a"))
}

func TestKeyed_AtCap_ReclaimsRefilledBuckets(t *testing.T) {
	clock := newClock()
	k := newKeyed(clock, 1, 1)
	k.Allow("old") // tracked, now empty
	clock.advance(time.Hour)

	k.Allow("new") // map full: "old" has refilled, so it is reclaimed

	assert.True(t, k.Allow("old"), "a reclaimed key starts again from a full bucket")
}

func TestKeyed_AtCap_NewKeysShareTheOverflowBucket(t *testing.T) {
	k := newKeyed(newClock(), 1, 1)
	k.Allow("tracked") // fills the map with a throttled bucket

	k.Allow("new-1") // spends the single overflow token

	assert.False(t, k.Allow("new-2"))
}

func TestKeyed_AtCap_TrackedKeysKeepTheirOwnBudget(t *testing.T) {
	k := newKeyed(newClock(), 2, 1)
	k.Allow("tracked")
	k.Allow("new-1")
	k.Allow("new-2") // overflow drained

	assert.True(t, k.Allow("tracked"))
}
