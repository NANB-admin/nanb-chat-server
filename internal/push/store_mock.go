package push

import (
	"context"
	"sync"
)

type StoreInMemory struct {
	mu     sync.Mutex
	tokens map[string]Token
}

func NewStoreInMemory() *StoreInMemory { return &StoreInMemory{tokens: map[string]Token{}} }

func (s *StoreInMemory) Upsert(_ context.Context, t Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Mirror StorePostgres: a token belongs to one device only.
	for id, existing := range s.tokens {
		if id != t.DeviceID && existing.Token == t.Token {
			delete(s.tokens, id)
		}
	}
	s.tokens[t.DeviceID] = t
	return nil
}

func (s *StoreInMemory) GetByDeviceID(_ context.Context, deviceID string) (Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[deviceID]
	if !ok {
		return Token{}, ErrNotFound
	}
	return t, nil
}

func (s *StoreInMemory) Delete(_ context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, deviceID)
	return nil
}
