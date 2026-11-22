package push

import (
	"context"
	"sort"
	"sync"
	"time"
)

// OutboxInMemory is an [Outbox] for tests and for a deployment running without
// Postgres. Retries survive only the process, which is the correct degradation:
// the queue exists to ride out a provider blip, not a server restart.
type OutboxInMemory struct {
	mu     sync.Mutex
	nextID int64
	items  map[int64]OutboxItem
}

func NewOutboxInMemory() *OutboxInMemory {
	return &OutboxInMemory{items: map[int64]OutboxItem{}}
}

func (o *OutboxInMemory) Enqueue(_ context.Context, item OutboxItem) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	// Mirror the Postgres unique index on (device_id, envelope_id): refresh the
	// pending row instead of queueing a second buzz for the same message.
	for id, existing := range o.items {
		if existing.DeviceID == item.DeviceID && existing.EnvelopeID == item.EnvelopeID {
			existing.ConversationID = item.ConversationID
			existing.PushKind = item.PushKind
			existing.SealedPayload = item.SealedPayload
			existing.NextAttemptAt = item.NextAttemptAt
			o.items[id] = existing
			return nil
		}
	}
	o.nextID++
	item.ID = o.nextID
	if item.CreatedAt.IsZero() {
		item.CreatedAt = item.NextAttemptAt
	}
	o.items[item.ID] = item
	return nil
}

func (o *OutboxInMemory) DueItems(_ context.Context, now time.Time, limit int) ([]OutboxItem, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var due []OutboxItem
	for _, it := range o.items {
		if !it.NextAttemptAt.After(now) {
			due = append(due, it)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if due[i].NextAttemptAt.Equal(due[j].NextAttemptAt) {
			return due[i].ID < due[j].ID
		}
		return due[i].NextAttemptAt.Before(due[j].NextAttemptAt)
	})
	if limit > 0 && len(due) > limit {
		due = due[:limit]
	}
	return due, nil
}

func (o *OutboxInMemory) Reschedule(_ context.Context, id int64, attempts int, next time.Time) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	it, ok := o.items[id]
	if !ok {
		return nil
	}
	it.Attempts = attempts
	it.NextAttemptAt = next
	o.items[id] = it
	return nil
}

func (o *OutboxInMemory) Delete(_ context.Context, id int64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.items, id)
	return nil
}

func (o *OutboxInMemory) DeleteForDevice(_ context.Context, deviceID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for id, it := range o.items {
		if it.DeviceID == deviceID {
			delete(o.items, id)
		}
	}
	return nil
}

func (o *OutboxInMemory) DeleteOlderThan(_ context.Context, cutoff time.Time) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	removed := 0
	for id, it := range o.items {
		if !it.CreatedAt.After(cutoff) {
			delete(o.items, id)
			removed++
		}
	}
	return removed, nil
}

// Len reports how many items are queued. Test helper.
func (o *OutboxInMemory) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.items)
}
