package retention_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/retention"
)

type fakeMedia struct {
	deleted   int
	deleteErr error
	calls     int
	lastBatch int
}

func (f *fakeMedia) DeleteExpired(_ context.Context, batch int) (int, error) {
	f.calls++
	f.lastBatch = batch
	if f.deleteErr != nil {
		return 0, f.deleteErr
	}
	return f.deleted, nil
}

func TestWorker_RunOnce_DelegatesToService(t *testing.T) {
	fm := &fakeMedia{deleted: 5}
	w := retention.NewWorker(fm, 100)

	deleted, err := w.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 5, deleted)
	assert.Equal(t, 1, fm.calls)
	assert.Equal(t, 100, fm.lastBatch)
}

func TestWorker_RunOnce_PropagatesError(t *testing.T) {
	fm := &fakeMedia{deleteErr: errors.New("boom")}
	w := retention.NewWorker(fm, 100)

	_, err := w.RunOnce(context.Background())
	assert.Error(t, err)
}

func TestWorker_AddCleaner_SweepsAllRegisteredCleaners(t *testing.T) {
	media := &fakeMedia{deleted: 3}
	envelopes := &fakeMedia{deleted: 7}
	w := retention.NewWorker(media, 50)
	w.AddCleaner("envelope", envelopes)

	deleted, err := w.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 10, deleted)
	assert.Equal(t, 1, media.calls)
	assert.Equal(t, 1, envelopes.calls)
	assert.Equal(t, 50, envelopes.lastBatch)
}

func TestWorker_OneCleanerFailing_DoesNotBlockOthers(t *testing.T) {
	media := &fakeMedia{deleteErr: errors.New("s3 down")}
	envelopes := &fakeMedia{deleted: 4}
	w := retention.NewWorker(media, 50)
	w.AddCleaner("envelope", envelopes)

	deleted, err := w.RunOnce(context.Background())
	assert.Error(t, err, "first error is surfaced")
	assert.Equal(t, 4, deleted, "the healthy cleaner still ran")
	assert.Equal(t, 1, envelopes.calls)
}

// scriptedCleaner returns the given per-call deletion counts in order, then 0.
type scriptedCleaner struct {
	results []int
	calls   int
}

func (c *scriptedCleaner) DeleteExpired(_ context.Context, _ int) (int, error) {
	c.calls++
	if c.calls > len(c.results) {
		return 0, nil
	}
	return c.results[c.calls-1], nil
}

func TestWorker_RunOnce_KeepsDeletingWhileBatchesComeBackFull(t *testing.T) {
	c := &scriptedCleaner{results: []int{10, 10, 4}}
	w := retention.NewWorker(c, 10)

	deleted, err := w.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 24, deleted)
}

func TestWorker_RunOnce_StopsAfterAShortBatch(t *testing.T) {
	c := &scriptedCleaner{results: []int{10, 4, 10}}
	w := retention.NewWorker(c, 10)

	_, err := w.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 2, c.calls)
}

func TestWorker_RunOnce_CapsBatchesPerRun(t *testing.T) {
	full := make([]int, retention.MaxBatchesPerRun+5)
	for i := range full {
		full[i] = 10
	}
	c := &scriptedCleaner{results: full}
	w := retention.NewWorker(c, 10)

	_, err := w.RunOnce(context.Background())

	require.NoError(t, err)
	assert.Equal(t, retention.MaxBatchesPerRun, c.calls)
}
