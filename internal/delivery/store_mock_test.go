package delivery_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/delivery"
	"github.com/nanb/nanb-server/internal/proto"
)

func envFor(id, recipientDevice, recipientAcct, conv string, ts time.Time) proto.Envelope {
	return proto.Envelope{
		EnvelopeID:         id,
		RecipientDeviceID:  recipientDevice,
		RecipientAccountID: recipientAcct,
		ConversationID:     conv,
		ServerTS:           ts,
	}
}

func TestStoreInMemory_CatchupForDevice_FiltersWrongDevice(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	expires := time.Now().Add(24 * time.Hour) // relative: the mock's expiry filter uses wall-clock now

	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-1", "dev-A", "acc-1", "c1", now), expires))
	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-2", "dev-B", "acc-1", "c1", now), expires))

	envs, err := store.CatchupForDevice(ctx, "dev-A", time.Time{}, 0)
	require.NoError(t, err)
	assert.Len(t, envs, 1)
	assert.Equal(t, "env-1", envs[0].EnvelopeID)
}

func TestStoreInMemory_CatchupForDevice_FiltersBySince(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-1", "dev-A", "acc-1", "c1", t0), time.Now().Add(24*time.Hour)))
	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-2", "dev-A", "acc-1", "c1", t0.Add(time.Hour)), time.Now().Add(24*time.Hour)))

	envs, err := store.CatchupForDevice(ctx, "dev-A", t0.Add(30*time.Minute), 0)
	require.NoError(t, err)
	assert.Len(t, envs, 1)
	assert.Equal(t, "env-2", envs[0].EnvelopeID)
}

func TestStoreInMemory_CatchupForDevice_SkipsAcked(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-1", "dev-A", "acc-1", "c1", t0), time.Now().Add(24*time.Hour)))
	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-2", "dev-A", "acc-1", "c1", t0), time.Now().Add(24*time.Hour)))

	_, err := store.AckEnvelopes(ctx, "dev-A", []string{"env-1"}, t0)
	require.NoError(t, err)

	envs, err := store.CatchupForDevice(ctx, "dev-A", time.Time{}, 0)
	require.NoError(t, err)
	assert.Len(t, envs, 1)
	assert.Equal(t, "env-2", envs[0].EnvelopeID)
}

func TestStoreInMemory_AckEnvelopes_IgnoresWrongDevice(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-1", "dev-A", "acc-1", "c1", t0), time.Now().Add(24*time.Hour)))

	count, err := store.AckEnvelopes(ctx, "dev-B", []string{"env-1"}, t0)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestStoreInMemory_AckEnvelopes_IgnoresAlreadyAcked(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-1", "dev-A", "acc-1", "c1", t0), time.Now().Add(24*time.Hour)))

	first, err := store.AckEnvelopes(ctx, "dev-A", []string{"env-1"}, t0)
	require.NoError(t, err)
	assert.Equal(t, 1, first)

	second, err := store.AckEnvelopes(ctx, "dev-A", []string{"env-1"}, t0)
	require.NoError(t, err)
	assert.Equal(t, 0, second)
}

func TestStoreInMemory_EvictOldestForConversation_NoExcessReturnsZero(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-1", "dev-A", "acc-1", "c1", t0), time.Now().Add(24*time.Hour)))
	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-2", "dev-A", "acc-1", "c1", t0.Add(time.Minute)), time.Now().Add(24*time.Hour)))

	deleted, err := store.EvictOldestForConversation(ctx, "acc-1", "c1", 5)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted)
}

func TestStoreInMemory_EvictOldestForConversation_SkipsAcked(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-1", "dev-A", "acc-1", "c1", t0), time.Now().Add(24*time.Hour)))
	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-2", "dev-A", "acc-1", "c1", t0.Add(time.Minute)), time.Now().Add(24*time.Hour)))
	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-3", "dev-A", "acc-1", "c1", t0.Add(2*time.Minute)), time.Now().Add(24*time.Hour)))

	// env-1 already acked → only env-2, env-3 remain in the unacked window.
	_, err := store.AckEnvelopes(ctx, "dev-A", []string{"env-1"}, t0)
	require.NoError(t, err)

	// keep=1 means we want the 1 newest unacked. env-3 stays, env-2 is evicted.
	deleted, err := store.EvictOldestForConversation(ctx, "acc-1", "c1", 1)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)
}

// FIFO trim must keep the NEWEST `keep` envelopes and evict the older ones.
// This locks in the survivorship contract — the count-only assertions
// elsewhere don't catch the inversion bug where the impl keeps the oldest.
func TestStoreInMemory_EvictOldestForConversation_KeepsNewest(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	for i, ts := range []time.Time{
		t0,
		t0.Add(time.Minute),
		t0.Add(2 * time.Minute),
		t0.Add(3 * time.Minute),
		t0.Add(4 * time.Minute),
	} {
		id := fmt.Sprintf("env-%d", i+1)
		require.NoError(t, store.InsertEnvelope(ctx, envFor(id, "dev-A", "acc-1", "c1", ts), time.Now().Add(24*time.Hour)))
	}

	deleted, err := store.EvictOldestForConversation(ctx, "acc-1", "c1", 2)
	require.NoError(t, err)
	assert.Equal(t, 3, deleted)

	// Survivors: the two NEWEST unacked envelopes.
	survivors, err := store.CatchupForDevice(ctx, "dev-A", time.Time{}, 100)
	require.NoError(t, err)
	require.Len(t, survivors, 2)
	ids := []string{survivors[0].EnvelopeID, survivors[1].EnvelopeID}
	assert.Contains(t, ids, "env-4")
	assert.Contains(t, ids, "env-5")
	assert.NotContains(t, ids, "env-1", "oldest must be evicted")
	assert.NotContains(t, ids, "env-2", "oldest must be evicted")
	assert.NotContains(t, ids, "env-3", "oldest must be evicted")
}

func TestStoreInMemory_EvictOldestForConversation_NonPositiveKeepIsNoOp(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-1", "dev-A", "acc-1", "c1", t0), time.Now().Add(24*time.Hour)))

	for _, keep := range []int{0, -1, -100} {
		deleted, err := store.EvictOldestForConversation(ctx, "acc-1", "c1", keep)
		require.NoError(t, err)
		assert.Equal(t, 0, deleted, "keep=%d must be a no-op", keep)
	}
}

func TestStoreInMemory_MarkReceived_FirstTransitionThenDuplicate(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	store.SeedEnvelope(proto.Envelope{
		EnvelopeID:        "env-1",
		SenderDeviceID:    "sender-dev-1",
		ConversationID:    "c1",
		RecipientDeviceID: "dev-A",
	})

	sender, conv, first, err := store.MarkReceived(ctx, "env-1", "dev-A", time.Time{})
	require.NoError(t, err)
	assert.True(t, first)
	assert.Equal(t, "sender-dev-1", sender)
	assert.Equal(t, "c1", conv)

	_, _, second, err := store.MarkReceived(ctx, "env-1", "dev-A", time.Time{})
	require.NoError(t, err)
	assert.False(t, second, "a second confirmation is not a first transition")
}

func TestStoreInMemory_MarkReceived_WrongRecipientIsNoOp(t *testing.T) {
	store := delivery.NewStoreInMemory()
	store.SeedEnvelope(proto.Envelope{
		EnvelopeID:        "env-1",
		SenderDeviceID:    "sender-dev-1",
		ConversationID:    "c1",
		RecipientDeviceID: "dev-A",
	})

	_, _, first, err := store.MarkReceived(context.Background(), "env-1", "dev-B", time.Time{})
	require.NoError(t, err)
	assert.False(t, first)
}

func TestStoreInMemory_MarkReceived_MissingEnvelopeIsNoOp(t *testing.T) {
	store := delivery.NewStoreInMemory()
	_, _, first, err := store.MarkReceived(context.Background(), "nope", "dev-A", time.Time{})
	require.NoError(t, err)
	assert.False(t, first)
}

func TestStoreInMemory_CountForConversation_IgnoresAcked(t *testing.T) {
	store := delivery.NewStoreInMemory()
	ctx := context.Background()
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-1", "dev-A", "acc-1", "c1", t0), time.Now().Add(24*time.Hour)))
	require.NoError(t, store.InsertEnvelope(ctx, envFor("env-2", "dev-A", "acc-1", "c1", t0), time.Now().Add(24*time.Hour)))

	_, err := store.AckEnvelopes(ctx, "dev-A", []string{"env-1"}, t0)
	require.NoError(t, err)

	count, err := store.CountForConversation(ctx, "acc-1", "c1")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}
