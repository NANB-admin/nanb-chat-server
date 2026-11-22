package media

import (
	"context"
	"errors"
	"time"

	"github.com/nanb/nanb-server/internal/proto"
)

var (
	ErrNotFound = errors.New("media not found")
)

type Store interface {
	Insert(ctx context.Context, m proto.MediaRecord) error
	GetByID(ctx context.Context, mediaID string) (proto.MediaRecord, error)
	MarkDeleted(ctx context.Context, mediaID string, now time.Time) error
	ListExpired(ctx context.Context, now time.Time, limit int) ([]proto.MediaRecord, error)
}
