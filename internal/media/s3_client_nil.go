package media

import (
	"context"
	"errors"
	"io"
	"time"
)

// NilClient errors on every operation. Used when S3 is not configured.
// Lets the server boot for development without AWS credentials.
type NilClient struct{}

var ErrS3NotConfigured = errors.New("s3 not configured")

func (NilClient) PresignPut(_ context.Context, _ string, _ int64, _ time.Duration) (string, error) {
	return "", ErrS3NotConfigured
}

func (NilClient) PresignGet(_ context.Context, _ string, _ time.Duration) (string, error) {
	return "", ErrS3NotConfigured
}

func (NilClient) DeleteObject(_ context.Context, _ string) error { return ErrS3NotConfigured }

func (NilClient) PutObject(_ context.Context, _ string, _ io.Reader, _ int64, _ string) error {
	return ErrS3NotConfigured
}

func (NilClient) GetObject(_ context.Context, _ string) (*ObjectStream, error) {
	return nil, ErrS3NotConfigured
}
