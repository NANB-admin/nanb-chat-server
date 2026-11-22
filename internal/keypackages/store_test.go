package keypackages_test

import (
	"context"
	"sync"
	"testing"

	"github.com/nanb/nanb-server/internal/keypackages"
)

func TestStoreInMemory_PublishBatch_StoresAll(t *testing.T) {
	s := keypackages.NewStoreInMemory()
	ctx := context.Background()
	err := s.PublishBatch(ctx, "acct-1", "dev-1", [][]byte{[]byte("kp1"), []byte("kp2")})
	if err != nil {
		t.Fatalf("PublishBatch: %v", err)
	}
	n, err := s.CountUnconsumed(ctx, "acct-1")
	if err != nil {
		t.Fatalf("CountUnconsumed: %v", err)
	}
	if n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}
}

func TestStoreInMemory_CountUnconsumedByDevice_ExcludesSiblingDevices(t *testing.T) {
	s := keypackages.NewStoreInMemory()
	ctx := context.Background()
	_ = s.PublishBatch(ctx, "acct-1", "dev-1", [][]byte{[]byte("kp1")})
	_ = s.PublishBatch(ctx, "acct-1", "dev-2", [][]byte{[]byte("kp2"), []byte("kp3")})
	n, err := s.CountUnconsumedByDevice(ctx, "acct-1", "dev-1")
	if err != nil {
		t.Fatalf("CountUnconsumedByDevice: %v", err)
	}
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
}

func TestStoreInMemory_PopOne_ReturnsOldestFirst(t *testing.T) {
	s := keypackages.NewStoreInMemory()
	ctx := context.Background()
	_ = s.PublishBatch(ctx, "acct-1", "dev-1", [][]byte{[]byte("first")})
	_ = s.PublishBatch(ctx, "acct-1", "dev-1", [][]byte{[]byte("second")})
	got, err := s.PopOne(ctx, "acct-1")
	if err != nil {
		t.Fatalf("PopOne: %v", err)
	}
	if string(got) != "first" {
		t.Fatalf("popped %q, want %q", got, "first")
	}
}

func TestStoreInMemory_PopOne_EmptyReturnsErrEmpty(t *testing.T) {
	s := keypackages.NewStoreInMemory()
	_, err := s.PopOne(context.Background(), "acct-1")
	if err != keypackages.ErrEmpty {
		t.Fatalf("err = %v, want ErrEmpty", err)
	}
}

func TestStoreInMemory_PopOne_ConcurrentReturnsDistinct(t *testing.T) {
	s := keypackages.NewStoreInMemory()
	ctx := context.Background()
	pkgs := make([][]byte, 100)
	for i := range pkgs {
		pkgs[i] = []byte{byte(i)}
	}
	_ = s.PublishBatch(ctx, "acct-1", "dev-1", pkgs)

	const N = 100
	results := make([][]byte, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			got, err := s.PopOne(ctx, "acct-1")
			if err != nil {
				t.Errorf("PopOne[%d]: %v", idx, err)
				return
			}
			results[idx] = got
		}(i)
	}
	wg.Wait()

	seen := make(map[byte]bool)
	for _, r := range results {
		if r == nil {
			t.Fatal("got nil result")
		}
		if seen[r[0]] {
			t.Fatalf("duplicate %d", r[0])
		}
		seen[r[0]] = true
	}
}

func TestStoreInMemory_CountUnconsumed_DecreasesAfterPop(t *testing.T) {
	s := keypackages.NewStoreInMemory()
	ctx := context.Background()
	_ = s.PublishBatch(ctx, "acct-1", "dev-1", [][]byte{[]byte("a"), []byte("b"), []byte("c")})
	_, _ = s.PopOne(ctx, "acct-1")
	n, _ := s.CountUnconsumed(ctx, "acct-1")
	if n != 2 {
		t.Fatalf("count = %d, want 2", n)
	}
}
