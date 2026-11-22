package delivery

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/nanb/nanb-server/internal/proto"
)

// StoreInMemory is the unit-test storage implementation. Safe for concurrent use.
type StoreInMemory struct {
	mu        sync.Mutex
	envelopes []envelopeRow
	// now drives the expiry filter. Defaults to wall-clock, but a test that
	// inserts with a Service using a FIXED clock must point this at the SAME
	// clock — otherwise envelopes inserted with a fixed-past expiry look
	// already-expired against wall-clock and silently vanish from catchup
	// (a time-bomb that fires once real time passes insert_time + retention).
	now func() time.Time
}

type envelopeRow struct {
	env       proto.Envelope
	expiresAt time.Time
	acked     bool
	received  bool
}

// expired mirrors the Postgres `expires_at > now()` query-time filter.
// A zero expiresAt (rows from SeedEnvelope) never expires, so existing
// test fixtures keep working.
func (r *envelopeRow) expired(now time.Time) bool {
	return !r.expiresAt.IsZero() && !r.expiresAt.After(now)
}

func NewStoreInMemory() *StoreInMemory {
	return &StoreInMemory{now: time.Now}
}

// NewStoreInMemoryWithClock builds an in-memory store whose expiry filter
// reads [now] instead of the wall clock — use it whenever the inserts come
// from a Service constructed with a fixed test clock.
func NewStoreInMemoryWithClock(now func() time.Time) *StoreInMemory {
	return &StoreInMemory{now: now}
}

// clockNow returns the store's clock, defaulting to wall-clock for stores
// built via a zero value or older constructors.
func (s *StoreInMemory) clockNow() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

func (s *StoreInMemory) InsertEnvelope(_ context.Context, env proto.Envelope, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.envelopes = append(s.envelopes, envelopeRow{env: env, expiresAt: expiresAt})
	return nil
}

func (s *StoreInMemory) CatchupForDevice(_ context.Context, deviceID string, since time.Time, limit int) ([]proto.Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clockNow()
	var out []proto.Envelope
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.acked {
			continue
		}
		if row.expired(now) {
			continue
		}
		if row.env.RecipientDeviceID != deviceID {
			continue
		}
		if !since.IsZero() && row.env.ServerTS.Before(since) {
			continue
		}
		out = append(out, row.env)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerTS.Before(out[j].ServerTS) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *StoreInMemory) EnvelopeConsumed(_ context.Context, envelopeID, recipientDeviceID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.env.EnvelopeID == envelopeID && row.env.RecipientDeviceID == recipientDeviceID {
			return row.acked, nil
		}
	}
	// No such row: retention swept it, or it never existed. Either way there is
	// nothing left to notify about.
	return true, nil
}

func (s *StoreInMemory) AckEnvelopes(_ context.Context, deviceID string, envelopeIDs []string, _ time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	wanted := map[string]struct{}{}
	for _, id := range envelopeIDs {
		wanted[id] = struct{}{}
	}
	// Mirrors Postgres: an acked envelope is deleted outright.
	count := 0
	kept := s.envelopes[:0]
	for i := range s.envelopes {
		row := s.envelopes[i]
		_, want := wanted[row.env.EnvelopeID]
		if !row.acked && want && row.env.RecipientDeviceID == deviceID {
			count++
			continue
		}
		kept = append(kept, row)
	}
	s.envelopes = kept
	return count, nil
}

func (s *StoreInMemory) MarkReceived(_ context.Context, envelopeID, recipientDeviceID string, _ time.Time) (string, string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.env.EnvelopeID == envelopeID && row.env.RecipientDeviceID == recipientDeviceID {
			if row.received {
				return "", "", false, nil
			}
			row.received = true
			return row.env.SenderDeviceID, row.env.ConversationID, true, nil
		}
	}
	return "", "", false, nil
}

func (s *StoreInMemory) EvictOldestForConversation(_ context.Context, recipientAccountID, conversationID string, keep int) (int, error) {
	if keep <= 0 {
		// Mirror the Postgres guard — refuse to evict everything when
		// misconfigured. Service-layer config clamps >= 1.
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	type idxTS struct {
		idx int
		ts  time.Time
	}
	var matches []idxTS
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.acked {
			continue
		}
		if row.env.RecipientAccountID == recipientAccountID && row.env.ConversationID == conversationID {
			matches = append(matches, idxTS{i, row.env.ServerTS})
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].ts.Before(matches[j].ts) })

	excess := len(matches) - keep
	if excess <= 0 {
		return 0, nil
	}
	deleted := 0
	for k := 0; k < excess; k++ {
		s.envelopes[matches[k].idx].acked = true
		deleted++
	}
	return deleted, nil
}

func (s *StoreInMemory) CountForConversation(_ context.Context, recipientAccountID, conversationID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.acked {
			continue
		}
		if row.env.RecipientAccountID == recipientAccountID && row.env.ConversationID == conversationID {
			count++
		}
	}
	return count, nil
}

func (s *StoreInMemory) CountForDeviceConversation(_ context.Context, recipientDeviceID, conversationID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clockNow()
	count := 0
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.acked || row.expired(now) {
			continue
		}
		if row.env.RecipientDeviceID == recipientDeviceID && row.env.ConversationID == conversationID {
			count++
		}
	}
	return count, nil
}

func (s *StoreInMemory) EvictOldestForDeviceConversation(_ context.Context, recipientDeviceID, conversationID string, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	type idxTS struct {
		idx int
		ts  time.Time
	}
	var matches []idxTS
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.acked {
			continue
		}
		if row.env.RecipientDeviceID == recipientDeviceID && row.env.ConversationID == conversationID {
			matches = append(matches, idxTS{i, row.env.ServerTS})
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].ts.Before(matches[j].ts) })

	excess := len(matches) - keep
	if excess <= 0 {
		return 0, nil
	}
	deleted := 0
	for k := 0; k < excess; k++ {
		s.envelopes[matches[k].idx].acked = true
		deleted++
	}
	return deleted, nil
}

// EvictOldestForDevice / CountForDevice: sealed-sender per-device analogues.
func (s *StoreInMemory) EvictOldestForDevice(_ context.Context, recipientDeviceID string, keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	type idxTS struct {
		idx int
		ts  time.Time
	}
	var matches []idxTS
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.acked {
			continue
		}
		if row.env.RecipientDeviceID == recipientDeviceID {
			matches = append(matches, idxTS{i, row.env.ServerTS})
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].ts.Before(matches[j].ts) })

	excess := len(matches) - keep
	if excess <= 0 {
		return 0, nil
	}
	deleted := 0
	for k := 0; k < excess; k++ {
		s.envelopes[matches[k].idx].acked = true
		deleted++
	}
	return deleted, nil
}

func (s *StoreInMemory) CountForDevice(_ context.Context, recipientDeviceID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clockNow()
	count := 0
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.acked || row.expired(now) {
			continue
		}
		if row.env.RecipientDeviceID == recipientDeviceID {
			count++
		}
	}
	return count, nil
}

// SeedEnvelope inserts a pre-built envelope into the mock store. Test-only helper.
func (s *StoreInMemory) SeedEnvelope(e proto.Envelope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.envelopes = append(s.envelopes, envelopeRow{env: e})
}

// GetEnvelopeByID returns the envelope by id ONLY if addressed to the
// supplied recipient device. ErrNotFound for any mismatch or missing.
func (s *StoreInMemory) GetEnvelopeByID(_ context.Context, envID, devID string) (proto.Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.env.EnvelopeID == envID && row.env.RecipientDeviceID == devID {
			if row.expired(s.clockNow()) {
				return proto.Envelope{}, ErrNotFound
			}
			return row.env, nil
		}
	}
	return proto.Envelope{}, ErrNotFound
}

// DeleteExpiredEnvelopes mirrors the Postgres retention sweep: rows with a
// non-zero expires_at at or before now, or already acked, are removed, up to
// limit.
func (s *StoreInMemory) DeleteExpiredEnvelopes(_ context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.envelopes[:0]
	deleted := 0
	for i := range s.envelopes {
		row := s.envelopes[i]
		expired := !row.expiresAt.IsZero() && !row.expiresAt.After(now)
		if deleted < limit && (expired || row.acked) {
			deleted++
			continue
		}
		kept = append(kept, row)
	}
	s.envelopes = kept
	return deleted, nil
}

// ExpiryOf returns the stored expires_at for an envelope. Test-only helper.
func (s *StoreInMemory) ExpiryOf(envelopeID string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.envelopes {
		if s.envelopes[i].env.EnvelopeID == envelopeID {
			return s.envelopes[i].expiresAt, true
		}
	}
	return time.Time{}, false
}

// SnapshotForRecipient returns a copy of envelopes for a device, for inspection in tests.
func (s *StoreInMemory) SnapshotForRecipient(deviceID string) []proto.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []proto.Envelope
	for i := range s.envelopes {
		row := &s.envelopes[i]
		if row.acked {
			continue
		}
		if row.env.RecipientDeviceID == deviceID {
			out = append(out, row.env)
		}
	}
	return out
}
