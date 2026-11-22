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

// kindPusher records the push kind of every wakeup it is asked to send.
type kindPusher struct{ kinds []string }

func (k *kindPusher) DispatchWakeup(_ context.Context, _, _, _, pushKind string, _ []byte) error {
	k.kinds = append(k.kinds, pushKind)
	return nil
}

type autoIDs struct{ n int }

func (a *autoIDs) Next() string {
	a.n++
	return fmt.Sprintf("env-%d", a.n)
}

func newGatedService(pusher delivery.Pusher, gate *delivery.CallPushGate) *delivery.Service {
	return delivery.NewService(delivery.ServiceDeps{
		Store:             delivery.NewStoreInMemory(),
		Clock:             fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)},
		IDGen:             &autoIDs{},
		Hub:               delivery.NewHub(),
		Pusher:            pusher,
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
		CallPushGate:      gate,
	})
}

func callRequest(recipientDevice, pushKind string) proto.SubmitMessageRequest {
	req := validRequest()
	req.RecipientDeviceID = recipientDevice
	req.RecipientAccountID = "acct-" + recipientDevice
	req.PushKind = pushKind
	return req
}

func sendN(t *testing.T, svc *delivery.Service, sender string, n int, recipientDevice, kind string) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := svc.SubmitMessage(context.Background(), sender, callRequest(recipientDevice, kind))
		require.NoError(t, err, "a throttled ring must never fail the send")
	}
}

func countKind(kinds []string, want string) int {
	n := 0
	for _, k := range kinds {
		if k == want {
			n++
		}
	}
	return n
}

func TestSubmitMessage_CallPushesToOneRecipientAreThrottledToANormalWakeup(t *testing.T) {
	pusher := &kindPusher{}
	svc := newGatedService(pusher, delivery.NewCallPushGate(nil))

	sendN(t, svc, "caller-1", 40, "victim-dev", "call")

	assert.Less(t, countKind(pusher.kinds, "call"), 40, "some rings must be throttled")
	assert.Greater(t, countKind(pusher.kinds, "call"), 0, "the first rings still go out")
}

func TestSubmitMessage_ThrottledCallStillWakesTheDeviceAsOrdinaryMessage(t *testing.T) {
	pusher := &kindPusher{}
	svc := newGatedService(pusher, delivery.NewCallPushGate(nil))

	sendN(t, svc, "caller-1", 40, "victim-dev", "call")

	assert.Len(t, pusher.kinds, 40, "every send still produces a wakeup")
	assert.Greater(t, countKind(pusher.kinds, ""), 0, "throttled rings are downgraded to kind \"\"")
}

func TestSubmitMessage_ThrottledCallEnvelopeIsStillStored(t *testing.T) {
	svc := newGatedService(&kindPusher{}, delivery.NewCallPushGate(nil))

	_, err := svc.SubmitMessage(context.Background(), "caller-1", callRequest("victim-dev", "call"))

	assert.NoError(t, err)
}

func TestSubmitMessage_NormalMessagePushesAreNeverThrottled(t *testing.T) {
	pusher := &kindPusher{}
	svc := newGatedService(pusher, delivery.NewCallPushGate(nil))

	sendN(t, svc, "caller-1", 200, "victim-dev", "")

	assert.Len(t, pusher.kinds, 200)
}

func TestSubmitMessage_CallThrottleForOnePairDoesNotAffectAnotherRecipient(t *testing.T) {
	pusher := &kindPusher{}
	svc := newGatedService(pusher, delivery.NewCallPushGate(nil))
	sendN(t, svc, "caller-1", 40, "victim-dev", "call")
	before := countKind(pusher.kinds, "call")

	sendN(t, svc, "caller-1", 1, "friend-dev", "call")

	assert.Equal(t, before+1, countKind(pusher.kinds, "call"))
}

func TestSubmitMessage_CallsWithoutAGateAreNeverThrottled(t *testing.T) {
	pusher := &kindPusher{}
	svc := newGatedService(pusher, nil)

	sendN(t, svc, "caller-1", 100, "victim-dev", "call")

	assert.Equal(t, 100, countKind(pusher.kinds, "call"))
}

func TestCallPushGate_UnauthenticatedSealedCallsAreLimitedPerRecipientAccount(t *testing.T) {
	gate := delivery.NewCallPushGate(nil)

	allowed := 0
	for i := 0; i < 50; i++ {
		if gate.Allow(proto.SealedSentinelUUID, "victim-acct") {
			allowed++
		}
	}

	assert.Less(t, allowed, 50)
	assert.True(t, gate.Allow(proto.SealedSentinelUUID, "other-acct"), "another recipient keeps its own budget")
}

func TestCallPushGate_BudgetRefillsOverTime(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	gate := delivery.NewCallPushGate(clock.Now)
	for i := 0; i < 50; i++ {
		gate.Allow("caller-1", "victim-acct")
	}
	clock.Advance(time.Minute)

	assert.True(t, gate.Allow("caller-1", "victim-acct"))
}

func TestCallPushGate_OneSenderCannotRingManyStrangersInBulk(t *testing.T) {
	gate := delivery.NewCallPushGate(nil)

	allowed := 0
	for i := 0; i < 200; i++ {
		if gate.Allow("caller-1", fmt.Sprintf("stranger-%d", i)) {
			allowed++
		}
	}

	assert.LessOrEqual(t, allowed, 61, "per-sender budget bounds a bulk ring")
	assert.Greater(t, allowed, 0)
}
