package media

import (
	"context"
	"sync"
	"time"

	"github.com/nanb/nanb-server/internal/proto"
)

type StoreInMemory struct {
	mu      sync.Mutex
	records map[string]proto.MediaRecord
}

func NewStoreInMemory() *StoreInMemory {
	return &StoreInMemory{records: map[string]proto.MediaRecord{}}
}

func (s *StoreInMemory) Insert(_ context.Context, m proto.MediaRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[m.MediaID] = m
	return nil
}

func (s *StoreInMemory) GetByID(_ context.Context, mediaID string) (proto.MediaRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.records[mediaID]
	if !ok {
		return proto.MediaRecord{}, ErrNotFound
	}
	if m.DeletedAt != nil {
		return proto.MediaRecord{}, ErrNotFound
	}
	return m, nil
}

func (s *StoreInMemory) MarkDeleted(_ context.Context, mediaID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.records[mediaID]
	if !ok {
		return ErrNotFound
	}
	t := now
	m.DeletedAt = &t
	s.records[mediaID] = m
	return nil
}

func (s *StoreInMemory) ListExpired(_ context.Context, now time.Time, limit int) ([]proto.MediaRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []proto.MediaRecord
	for _, m := range s.records {
		if m.DeletedAt != nil {
			continue
		}
		if !m.ExpiresAt.After(now) {
			out = append(out, m)
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}
