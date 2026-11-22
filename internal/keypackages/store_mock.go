package keypackages

import (
	"context"
	"sync"
)

// StoreInMemory is an in-memory implementation of Store for unit tests + local
// dev. PopOne is protected by a mutex to match the Postgres impl's atomic
// pop semantics.
type StoreInMemory struct {
	mu sync.Mutex
	// byAccount[accountID] is a FIFO-ordered list of unconsumed KeyPackages
	// (oldest at index 0), each tagged with its publishing device so
	// PopOnePerDevice can return one per device.
	byAccount map[string][]memKp
}

type memKp struct {
	deviceID string
	payload  []byte
}

// NewStoreInMemory returns an empty StoreInMemory ready for use. Concurrent
// access across the Store interface is safe.
func NewStoreInMemory() *StoreInMemory {
	return &StoreInMemory{byAccount: make(map[string][]memKp)}
}

func (s *StoreInMemory) PublishBatch(_ context.Context, accountID, deviceID string, kps [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, kp := range kps {
		// copy to defend against caller mutation
		buf := make([]byte, len(kp))
		copy(buf, kp)
		s.byAccount[accountID] = append(s.byAccount[accountID], memKp{deviceID: deviceID, payload: buf})
	}
	return nil
}

func (s *StoreInMemory) DeleteUnconsumedByDevice(_ context.Context, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// byAccount holds ONLY unconsumed packages (a pop removes the entry), so
	// filtering the queue is exactly "delete the unconsumed rows".
	for accountID, q := range s.byAccount {
		kept := q[:0]
		for _, kp := range q {
			if kp.deviceID != deviceID {
				kept = append(kept, kp)
			}
		}
		s.byAccount[accountID] = kept
	}
	return nil
}

func (s *StoreInMemory) PopOne(_ context.Context, accountID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.byAccount[accountID]
	if len(q) == 0 {
		return nil, ErrEmpty
	}
	head := q[0]
	s.byAccount[accountID] = q[1:]
	return head.payload, nil
}

func (s *StoreInMemory) PopOnePerDevice(_ context.Context, accountID string) ([]DevicePackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.byAccount[accountID]
	var out []DevicePackage
	seen := make(map[string]bool)
	remaining := q[:0:0] // fresh slice; preserve FIFO order of leftovers
	for _, kp := range q {
		if !seen[kp.deviceID] {
			seen[kp.deviceID] = true
			out = append(out, DevicePackage{DeviceID: kp.deviceID, Payload: kp.payload})
			continue // consumed
		}
		remaining = append(remaining, kp)
	}
	s.byAccount[accountID] = remaining
	return out, nil
}

func (s *StoreInMemory) PopForDevice(_ context.Context, accountID, deviceID string, n int) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.byAccount[accountID]
	var out [][]byte
	remaining := q[:0:0] // fresh slice; preserve FIFO order of leftovers
	for _, kp := range q {
		if kp.deviceID == deviceID && len(out) < n {
			out = append(out, kp.payload)
			continue // consumed
		}
		remaining = append(remaining, kp)
	}
	s.byAccount[accountID] = remaining
	return out, nil
}

func (s *StoreInMemory) CountUnconsumed(_ context.Context, accountID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byAccount[accountID]), nil
}

func (s *StoreInMemory) CountUnconsumedByDevice(_ context.Context, accountID, deviceID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, kp := range s.byAccount[accountID] {
		if kp.deviceID == deviceID {
			n++
		}
	}
	return n, nil
}
