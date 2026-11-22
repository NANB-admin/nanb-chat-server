package push

import (
	"context"
	"errors"
	"log"
	"time"
)

// Retry schedule. Attempt n waits retryBackoff[n-1] after the previous try, so a
// push gets ~15s, 1m, 5m, 15m — four retries spread over ~21 minutes, which
// covers a provider blip and a device that is briefly unreachable without
// buzzing anyone about a message that has long since been read.
var retryBackoff = []time.Duration{
	15 * time.Second,
	time.Minute,
	5 * time.Minute,
	15 * time.Minute,
}

// maxPushAttempts counts the original inline send plus one per backoff step.
var maxPushAttempts = 1 + len(retryBackoff)

const (
	// retryBatchSize bounds one sweep so a backlog drains steadily instead of
	// hammering the provider in a single burst.
	retryBatchSize = 200

	// retryMaxAge is the age backstop: a push nobody could deliver in this long
	// is dropped whatever its attempt count. Well past the last backoff step, so
	// it only catches rows the schedule alone would leave behind.
	retryMaxAge = time.Hour
)

// EnvelopeConsumedChecker reports whether an envelope no longer needs a wakeup
// because its recipient has already pulled it (or it has been swept). Satisfied
// by delivery.Service.
//
// A retry can fire up to ~21 minutes after the original send, by which time the
// user may well have opened the app and read the message over the socket.
// Without this check the queue would buzz them about it anyway.
type EnvelopeConsumedChecker interface {
	IsEnvelopeConsumed(ctx context.Context, envelopeID, recipientDeviceID string) (bool, error)
}

// RetryWorker re-sends wakeup pushes whose first attempt failed.
//
// Without it a single transient FCM/APNs error meant the recipient never got a
// notification for that message and nothing anywhere would try again — the
// reliability half of "notifications are iffy" (the other half, pushes being
// suppressed whenever the WS hub claimed `delivered`, was fixed in 5183f91).
//
// It is deliberately NOT on the sender's request path: a submit fires one
// attempt inline (so a call still rings immediately) and hands the failure here.
type RetryWorker struct {
	outbox   Outbox
	store    Store
	client   PushClient
	consumed EnvelopeConsumedChecker
	now      func() time.Time
}

func NewRetryWorker(outbox Outbox, store Store, client PushClient) *RetryWorker {
	return &RetryWorker{outbox: outbox, store: store, client: client, now: time.Now}
}

// WithConsumedChecker wires the "has the recipient already got this message?"
// gate. Optional: without it every queued push is retried on schedule, which is
// correct but can buzz about an already-read message.
func (w *RetryWorker) WithConsumedChecker(c EnvelopeConsumedChecker) *RetryWorker {
	w.consumed = c
	return w
}

// RunOnce drains one batch of due retries and sweeps aged-out rows. Returns how
// many pushes landed on this sweep. One item failing never blocks the rest.
func (w *RetryWorker) RunOnce(ctx context.Context) (int, error) {
	now := w.now()
	if _, err := w.outbox.DeleteOlderThan(ctx, now.Add(-retryMaxAge)); err != nil {
		log.Printf("push retry: age sweep: %v", err)
	}
	items, err := w.outbox.DueItems(ctx, now, retryBatchSize)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, item := range items {
		if w.attempt(ctx, item, now) {
			sent++
		}
	}
	return sent, nil
}

// attempt makes one retry for [item] and applies the outcome to the queue.
// Returns whether the push landed.
func (w *RetryWorker) attempt(ctx context.Context, item OutboxItem, now time.Time) bool {
	// Don't buzz about a message the recipient already pulled. An error here is
	// deliberately ignored (treated as "still pending") so an unreadable store
	// degrades to a duplicate wakeup, not to silence.
	if w.consumed != nil {
		if done, err := w.consumed.IsEnvelopeConsumed(ctx, item.EnvelopeID, item.DeviceID); err == nil && done {
			if delErr := w.outbox.Delete(ctx, item.ID); delErr != nil {
				log.Printf("push retry: delete consumed item %d: %v", item.ID, delErr)
			}
			return false
		}
	}

	// A call ring is only worth delivering while the caller is still ringing.
	// The backoff schedule runs to ~21 minutes, so without this a ring whose
	// first send failed buzzed "Incoming call" at 1m, 5m and 15m for a call that
	// had long since ended.
	if item.PushKind == "call" && now.Sub(item.CreatedAt) > callWakeupTTL {
		if delErr := w.outbox.Delete(ctx, item.ID); delErr != nil {
			log.Printf("push retry: delete stale call ring %d: %v", item.ID, delErr)
		}
		return false
	}

	t, err := w.store.GetByDeviceID(ctx, item.DeviceID)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			// A transient token-store failure (DB blip, pool exhausted) says
			// nothing about the device. Dropping its queue here turned one bad
			// query into lost notifications; leave the item for the next sweep
			// (the age backstop still bounds it).
			log.Printf("push retry: token lookup for device %s: %v", item.DeviceID, err)
			return false
		}
		// No token any more (unregistered, or pruned as dead): there is nothing
		// left to retry at, so drop the whole queue for the device.
		if dropErr := w.outbox.DeleteForDevice(ctx, item.DeviceID); dropErr != nil {
			log.Printf("push retry: drop queue for device %s: %v", item.DeviceID, dropErr)
		}
		return false
	}

	sendErr := w.client.SendWakeup(ctx, t, buildWakeupPayload(item))
	if sendErr == nil {
		if delErr := w.outbox.Delete(ctx, item.ID); delErr != nil {
			log.Printf("push retry: delete delivered item %d: %v", item.ID, delErr)
		}
		return true
	}

	if IsDeadTokenError(sendErr) {
		// The token is proven dead — prune it and drain the device's queue
		// rather than burning the remaining attempts on it.
		if delErr := w.store.Delete(ctx, item.DeviceID); delErr != nil {
			log.Printf("push retry: prune dead token for device %s: %v", item.DeviceID, delErr)
		}
		if dropErr := w.outbox.DeleteForDevice(ctx, item.DeviceID); dropErr != nil {
			log.Printf("push retry: drain queue for dead device %s: %v", item.DeviceID, dropErr)
		}
		return false
	}

	attempts := item.Attempts + 1
	if IsPermanentSendError(sendErr) || attempts >= maxPushAttempts {
		log.Printf("push retry: giving up on device %s after %d attempts: %v", item.DeviceID, attempts, sendErr)
		if delErr := w.outbox.Delete(ctx, item.ID); delErr != nil {
			log.Printf("push retry: delete exhausted item %d: %v", item.ID, delErr)
		}
		return false
	}
	if err := w.outbox.Reschedule(ctx, item.ID, attempts, now.Add(backoffFor(attempts))); err != nil {
		log.Printf("push retry: reschedule item %d: %v", item.ID, err)
	}
	return false
}

// backoffFor returns the wait before the retry that follows [attempts] failed
// tries, clamped to the last step of the schedule.
func backoffFor(attempts int) time.Duration {
	idx := attempts - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(retryBackoff) {
		idx = len(retryBackoff) - 1
	}
	return retryBackoff[idx]
}

// buildWakeupPayload rebuilds the provider data map for a queued push. It must
// stay in step with Service.DispatchWakeup — a retry has to be the same push,
// not a differently-shaped one.
func buildWakeupPayload(item OutboxItem) map[string]string {
	payload := map[string]string{
		"envelope_id":     item.EnvelopeID,
		"conversation_id": item.ConversationID,
	}
	if item.PushKind != "" {
		payload["push_kind"] = item.PushKind
	}
	if b64 := encodeSealedPayload(item.SealedPayload); b64 != "" {
		payload["sealed_payload"] = b64
	}
	return payload
}

// Run is production glue: a ticker loop over RunOnce.
func (w *RetryWorker) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if sent, err := w.RunOnce(ctx); err != nil {
				log.Printf("push retry: sweep failed: %v", err)
			} else if sent > 0 {
				log.Printf("push retry: delivered %d queued wakeups", sent)
			}
		}
	}
}
