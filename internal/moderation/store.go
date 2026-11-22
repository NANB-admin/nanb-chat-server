package moderation

import "context"

// Store persists user reports to the moderation queue.
type Store interface {
	InsertReport(ctx context.Context, r Report) error
}
