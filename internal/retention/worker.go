package retention

import (
	"context"
	"log"
	"time"
)

// Cleaner deletes one batch of expired records, returning how many went.
// media.Service and delivery.Service both implement it.
type Cleaner interface {
	DeleteExpired(ctx context.Context, batchSize int) (int, error)
}

// MediaCleaner is kept as an alias for the original single-cleaner name.
type MediaCleaner = Cleaner

type namedCleaner struct {
	name string
	c    Cleaner
}

// MaxBatchesPerRun bounds how many back-to-back batches one cleaner may
// delete in a single RunOnce. A full batch means more is probably waiting, so
// the worker keeps going (a backlog drains within a few ticks instead of one
// batch per tick); the bound keeps a single tick from running unbounded.
const MaxBatchesPerRun = 20

type Worker struct {
	cleaners []namedCleaner
	batch    int
}

// NewWorker keeps its original (media-first) signature; additional record
// types register via AddCleaner.
func NewWorker(c Cleaner, batchSize int) *Worker {
	return &Worker{
		cleaners: []namedCleaner{{name: "media", c: c}},
		batch:    batchSize,
	}
}

// AddCleaner registers another expired-record sweeper (e.g. envelopes)
// that runs on the same tick + batch size.
func (w *Worker) AddCleaner(name string, c Cleaner) {
	w.cleaners = append(w.cleaners, namedCleaner{name: name, c: c})
}

// RunOnce sweeps every registered cleaner, repeating a cleaner's batch while
// it keeps coming back full (up to MaxBatchesPerRun). One cleaner failing
// doesn't block the others; the first error is returned after all have run.
func (w *Worker) RunOnce(ctx context.Context) (int, error) {
	total := 0
	var firstErr error
	for _, nc := range w.cleaners {
		deleted, err := w.drain(ctx, nc.c)
		if err != nil {
			log.Printf("retention: %s cleanup error: %v", nc.name, err)
			if firstErr == nil {
				firstErr = err
			}
		}
		if deleted > 0 {
			log.Printf("retention: deleted %d expired %s records", deleted, nc.name)
		}
		total += deleted
	}
	return total, firstErr
}

// drain runs batches of one cleaner until a batch comes back short (nothing
// more to delete, or some rows failed and will be retried next tick), the
// context ends, or MaxBatchesPerRun is reached.
func (w *Worker) drain(ctx context.Context, c Cleaner) (int, error) {
	total := 0
	for i := 0; i < MaxBatchesPerRun; i++ {
		if ctx.Err() != nil {
			return total, nil
		}
		deleted, err := c.DeleteExpired(ctx, w.batch)
		total += deleted
		if err != nil {
			return total, err
		}
		if deleted < w.batch {
			return total, nil
		}
	}
	return total, nil
}

// Run is production glue: ticker loop. Excluded from unit tests; just calls RunOnce.
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := w.RunOnce(ctx); err != nil {
				continue
			}
		}
	}
}
