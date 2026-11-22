package push_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/push"
)

// scriptedClient fails its first `failures` sends, then succeeds.
type scriptedClient struct {
	failures int
	err      error
	sends    []map[string]string
}

func (c *scriptedClient) SendWakeup(_ context.Context, _ push.Token, payload map[string]string) error {
	if c.failures > 0 {
		c.failures--
		return c.err
	}
	c.sends = append(c.sends, payload)
	return nil
}

const (
	testDeviceID   = "11111111-1111-1111-1111-111111111111"
	testEnvelopeID = "22222222-2222-2222-2222-222222222222"
)

// newRetryFixture wires a service + outbox + worker sharing one client/store,
// with the device already registered.
func newRetryFixture(t *testing.T, client push.PushClient) (
	*push.Service, *push.OutboxInMemory, *push.RetryWorker, *push.StoreInMemory,
) {
	t.Helper()
	store := push.NewStoreInMemory()
	require.NoError(t, store.Upsert(context.Background(), push.Token{
		DeviceID:  testDeviceID,
		AccountID: "acc-1",
		Platform:  "fcm",
		Token:     "tok-1",
	}))
	outbox := push.NewOutboxInMemory()
	svc := push.NewService(push.ServiceDeps{Store: store, Client: client, Outbox: outbox})
	worker := push.NewRetryWorker(outbox, store, client)
	return svc, outbox, worker, store
}

func dispatch(t *testing.T, svc *push.Service) error {
	t.Helper()
	return svc.DispatchWakeup(
		context.Background(), testDeviceID, testEnvelopeID, "conv-1", "", nil)
}

func TestDispatchQueuesRetryOnTransientFailure(t *testing.T) {
	client := &scriptedClient{failures: 1, err: errors.New("fcm unavailable")}
	svc, outbox, _, _ := newRetryFixture(t, client)

	require.Error(t, dispatch(t, svc))

	assert.Equal(t, 1, outbox.Len())
}

func TestDispatchDoesNotQueueOnSuccess(t *testing.T) {
	client := &scriptedClient{}
	svc, outbox, _, _ := newRetryFixture(t, client)

	require.NoError(t, dispatch(t, svc))

	assert.Equal(t, 0, outbox.Len())
}

func TestDispatchPrunesDeadToken(t *testing.T) {
	client := &scriptedClient{failures: 1, err: push.ErrTokenInvalid}
	svc, _, _, store := newRetryFixture(t, client)

	require.Error(t, dispatch(t, svc))

	_, err := store.GetByDeviceID(context.Background(), testDeviceID)
	assert.ErrorIs(t, err, push.ErrNotFound)
}

func TestDispatchDoesNotQueueDeadToken(t *testing.T) {
	client := &scriptedClient{failures: 1, err: push.ErrTokenInvalid}
	svc, outbox, _, _ := newRetryFixture(t, client)

	require.Error(t, dispatch(t, svc))

	assert.Equal(t, 0, outbox.Len())
}

func TestRetryWorkerResendsAQueuedPush(t *testing.T) {
	client := &scriptedClient{failures: 1, err: errors.New("fcm unavailable")}
	svc, outbox, worker, _ := newRetryFixture(t, client)
	require.Error(t, dispatch(t, svc))
	// Make the queued item due.
	items, err := outbox.DueItems(context.Background(), time.Now().Add(time.Hour), 10)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.NoError(t, outbox.Reschedule(context.Background(), items[0].ID, 1, time.Now().Add(-time.Second)))

	sent, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 1, sent)
}

func TestRetryWorkerClearsTheQueueOnSuccess(t *testing.T) {
	client := &scriptedClient{failures: 1, err: errors.New("fcm unavailable")}
	svc, outbox, worker, _ := newRetryFixture(t, client)
	require.Error(t, dispatch(t, svc))
	items, _ := outbox.DueItems(context.Background(), time.Now().Add(time.Hour), 10)
	require.NoError(t, outbox.Reschedule(context.Background(), items[0].ID, 1, time.Now().Add(-time.Second)))

	_, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 0, outbox.Len())
}

func TestRetryWorkerResendsTheSamePayload(t *testing.T) {
	client := &scriptedClient{failures: 1, err: errors.New("fcm unavailable")}
	store := push.NewStoreInMemory()
	require.NoError(t, store.Upsert(context.Background(), push.Token{
		DeviceID: testDeviceID, AccountID: "acc-1", Platform: "fcm", Token: "tok-1",
	}))
	outbox := push.NewOutboxInMemory()
	svc := push.NewService(push.ServiceDeps{Store: store, Client: client, Outbox: outbox})
	worker := push.NewRetryWorker(outbox, store, client)
	require.Error(t, svc.DispatchWakeup(
		context.Background(), testDeviceID, testEnvelopeID, "conv-1", "call", nil))
	items, _ := outbox.DueItems(context.Background(), time.Now().Add(time.Hour), 10)
	require.NoError(t, outbox.Reschedule(context.Background(), items[0].ID, 1, time.Now().Add(-time.Second)))

	_, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	require.Len(t, client.sends, 1)
	assert.Equal(t, map[string]string{
		"envelope_id":     testEnvelopeID,
		"conversation_id": "conv-1",
		"push_kind":       "call",
	}, client.sends[0])
}

func TestRetryWorkerLeavesAnItemQueuedWhenTheRetryAlsoFails(t *testing.T) {
	client := &scriptedClient{failures: 2, err: errors.New("fcm unavailable")}
	svc, outbox, worker, _ := newRetryFixture(t, client)
	require.Error(t, dispatch(t, svc))
	items, _ := outbox.DueItems(context.Background(), time.Now().Add(time.Hour), 10)
	require.NoError(t, outbox.Reschedule(context.Background(), items[0].ID, 1, time.Now().Add(-time.Second)))

	sent, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 0, sent)
	assert.Equal(t, 1, outbox.Len())
}

func TestRetryWorkerGivesUpOnAPushThatNeverLands(t *testing.T) {
	// A client that fails every time: the item must age out of the queue rather
	// than being retried forever.
	client := &scriptedClient{failures: 99, err: errors.New("fcm unavailable")}
	svc, outbox, worker, _ := newRetryFixture(t, client)
	require.Error(t, dispatch(t, svc))

	// Each pass makes the pending item due immediately, so the loop advances one
	// attempt per iteration; it is bounded well above the retry schedule so a
	// regression that never gives up fails the assertion instead of hanging.
	for i := 0; i < 20 && outbox.Len() > 0; i++ {
		due, err := outbox.DueItems(context.Background(), time.Now().Add(time.Hour), 10)
		require.NoError(t, err)
		require.NoError(t, outbox.Reschedule(
			context.Background(), due[0].ID, due[0].Attempts, time.Now().Add(-time.Second)))
		_, err = worker.RunOnce(context.Background())
		require.NoError(t, err)
	}

	assert.Equal(t, 0, outbox.Len())
}

func TestRetryWorkerPrunesATokenTheProviderRejects(t *testing.T) {
	client := &scriptedClient{failures: 1, err: errors.New("fcm unavailable")}
	svc, outbox, _, store := newRetryFixture(t, client)
	require.Error(t, dispatch(t, svc))
	items, _ := outbox.DueItems(context.Background(), time.Now().Add(time.Hour), 10)
	require.NoError(t, outbox.Reschedule(context.Background(), items[0].ID, 1, time.Now().Add(-time.Second)))
	deadClient := &scriptedClient{failures: 1, err: push.ErrTokenInvalid}
	worker := push.NewRetryWorker(outbox, store, deadClient)

	_, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	_, getErr := store.GetByDeviceID(context.Background(), testDeviceID)
	assert.ErrorIs(t, getErr, push.ErrNotFound)
}

func TestRetryWorkerDropsTheQueueForAnUnregisteredDevice(t *testing.T) {
	client := &scriptedClient{failures: 1, err: errors.New("fcm unavailable")}
	svc, outbox, worker, store := newRetryFixture(t, client)
	require.Error(t, dispatch(t, svc))
	items, _ := outbox.DueItems(context.Background(), time.Now().Add(time.Hour), 10)
	require.NoError(t, outbox.Reschedule(context.Background(), items[0].ID, 1, time.Now().Add(-time.Second)))
	require.NoError(t, store.Delete(context.Background(), testDeviceID))

	_, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 0, outbox.Len())
}

func TestRetryWorkerSweepsItemsPastTheAgeBackstop(t *testing.T) {
	store := push.NewStoreInMemory()
	outbox := push.NewOutboxInMemory()
	worker := push.NewRetryWorker(outbox, store, &scriptedClient{})
	require.NoError(t, outbox.Enqueue(context.Background(), push.OutboxItem{
		DeviceID:      testDeviceID,
		EnvelopeID:    testEnvelopeID,
		Attempts:      1,
		NextAttemptAt: time.Now().Add(24 * time.Hour),
		CreatedAt:     time.Now().Add(-25 * time.Hour),
	}))

	_, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 0, outbox.Len())
}

// consumedChecker reports a fixed answer for every envelope.
type consumedChecker struct {
	consumed bool
	err      error
}

func (c consumedChecker) IsEnvelopeConsumed(_ context.Context, _, _ string) (bool, error) {
	return c.consumed, c.err
}

func TestRetryWorkerSkipsAPushTheRecipientAlreadyPulled(t *testing.T) {
	client := &scriptedClient{}
	store := push.NewStoreInMemory()
	require.NoError(t, store.Upsert(context.Background(), push.Token{
		DeviceID: testDeviceID, AccountID: "acc-1", Platform: "fcm", Token: "tok-1",
	}))
	outbox := push.NewOutboxInMemory()
	require.NoError(t, outbox.Enqueue(context.Background(), push.OutboxItem{
		DeviceID: testDeviceID, EnvelopeID: testEnvelopeID, Attempts: 1,
		NextAttemptAt: time.Now().Add(-time.Second), CreatedAt: time.Now(),
	}))
	worker := push.NewRetryWorker(outbox, store, client).
		WithConsumedChecker(consumedChecker{consumed: true})

	_, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Empty(t, client.sends, "must not buzz about an already-read message")
}

func TestRetryWorkerDropsAConsumedPushFromTheQueue(t *testing.T) {
	store := push.NewStoreInMemory()
	require.NoError(t, store.Upsert(context.Background(), push.Token{
		DeviceID: testDeviceID, AccountID: "acc-1", Platform: "fcm", Token: "tok-1",
	}))
	outbox := push.NewOutboxInMemory()
	require.NoError(t, outbox.Enqueue(context.Background(), push.OutboxItem{
		DeviceID: testDeviceID, EnvelopeID: testEnvelopeID, Attempts: 1,
		NextAttemptAt: time.Now().Add(-time.Second), CreatedAt: time.Now(),
	}))
	worker := push.NewRetryWorker(outbox, store, &scriptedClient{}).
		WithConsumedChecker(consumedChecker{consumed: true})

	_, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 0, outbox.Len())
}

func TestRetryWorkerStillSendsWhenTheConsumedCheckFails(t *testing.T) {
	// An unreadable store must degrade to a duplicate wakeup (which the client
	// collapses), never to silence.
	client := &scriptedClient{}
	store := push.NewStoreInMemory()
	require.NoError(t, store.Upsert(context.Background(), push.Token{
		DeviceID: testDeviceID, AccountID: "acc-1", Platform: "fcm", Token: "tok-1",
	}))
	outbox := push.NewOutboxInMemory()
	require.NoError(t, outbox.Enqueue(context.Background(), push.OutboxItem{
		DeviceID: testDeviceID, EnvelopeID: testEnvelopeID, Attempts: 1,
		NextAttemptAt: time.Now().Add(-time.Second), CreatedAt: time.Now(),
	}))
	worker := push.NewRetryWorker(outbox, store, client).
		WithConsumedChecker(consumedChecker{err: errors.New("db down")})

	sent, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 1, sent)
}

func TestOutboxKeepsOnePendingRetryPerEnvelope(t *testing.T) {
	client := &scriptedClient{failures: 2, err: errors.New("fcm unavailable")}
	svc, outbox, _, _ := newRetryFixture(t, client)

	require.Error(t, dispatch(t, svc))
	require.Error(t, dispatch(t, svc))

	assert.Equal(t, 1, outbox.Len())
}

func TestDispatchQueuesRetryWhenTheTokenLookupFails(t *testing.T) {
	// A DB blip on the token lookup says nothing about the device; dropping the
	// push there was a notification silently lost.
	store := &errStore{Store: push.NewStoreInMemory(), failGet: errors.New("db down")}
	outbox := push.NewOutboxInMemory()
	svc := push.NewService(push.ServiceDeps{Store: store, Client: &scriptedClient{}, Outbox: outbox})

	require.Error(t, dispatch(t, svc))

	assert.Equal(t, 1, outbox.Len())
}

func TestRetryWorkerKeepsTheQueueWhenTheTokenLookupFails(t *testing.T) {
	store := &errStore{Store: push.NewStoreInMemory(), failGet: errors.New("db down")}
	outbox := push.NewOutboxInMemory()
	require.NoError(t, outbox.Enqueue(context.Background(), push.OutboxItem{
		DeviceID: testDeviceID, EnvelopeID: testEnvelopeID, Attempts: 1,
		NextAttemptAt: time.Now().Add(-time.Second), CreatedAt: time.Now(),
	}))
	worker := push.NewRetryWorker(outbox, store, &scriptedClient{})

	_, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 1, outbox.Len())
}

func TestRetryWorkerDropsACallRingPastTheRingWindow(t *testing.T) {
	// The backoff runs to ~21 minutes; a ring for a call that ended long ago
	// must not buzz "Incoming call".
	client := &scriptedClient{}
	store := push.NewStoreInMemory()
	require.NoError(t, store.Upsert(context.Background(), push.Token{
		DeviceID: testDeviceID, AccountID: "acc-1", Platform: "fcm", Token: "tok-1",
	}))
	outbox := push.NewOutboxInMemory()
	require.NoError(t, outbox.Enqueue(context.Background(), push.OutboxItem{
		DeviceID: testDeviceID, EnvelopeID: testEnvelopeID, PushKind: "call",
		Attempts: 2, NextAttemptAt: time.Now().Add(-time.Second),
		CreatedAt: time.Now().Add(-2 * time.Minute),
	}))
	worker := push.NewRetryWorker(outbox, store, client)

	_, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Empty(t, client.sends)
}

func TestRetryWorkerStillRetriesACallRingInsideTheRingWindow(t *testing.T) {
	client := &scriptedClient{}
	store := push.NewStoreInMemory()
	require.NoError(t, store.Upsert(context.Background(), push.Token{
		DeviceID: testDeviceID, AccountID: "acc-1", Platform: "fcm", Token: "tok-1",
	}))
	outbox := push.NewOutboxInMemory()
	require.NoError(t, outbox.Enqueue(context.Background(), push.OutboxItem{
		DeviceID: testDeviceID, EnvelopeID: testEnvelopeID, PushKind: "call",
		Attempts: 1, NextAttemptAt: time.Now().Add(-time.Second),
		CreatedAt: time.Now().Add(-15 * time.Second),
	}))
	worker := push.NewRetryWorker(outbox, store, client)

	sent, err := worker.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 1, sent)
}
