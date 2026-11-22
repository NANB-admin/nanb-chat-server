package push

import (
	"context"
	"sync"
)

// VoipStoreInMemory is the test/dev counterpart of [VoipStorePostgres].
type VoipStoreInMemory struct {
	mu     sync.Mutex
	tokens map[string]VoipToken
}

func NewVoipStoreInMemory() *VoipStoreInMemory {
	return &VoipStoreInMemory{tokens: map[string]VoipToken{}}
}

func (s *VoipStoreInMemory) Upsert(_ context.Context, t VoipToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.DeviceID] = t
	return nil
}

func (s *VoipStoreInMemory) GetByDeviceID(_ context.Context, deviceID string) (VoipToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[deviceID]
	if !ok {
		return VoipToken{}, ErrNotFound
	}
	return t, nil
}

func (s *VoipStoreInMemory) Delete(_ context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, deviceID)
	return nil
}
