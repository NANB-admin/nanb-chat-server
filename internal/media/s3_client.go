package media

import (
	"context"
	"io"
	"time"
)

// S3Client is the abstraction over object storage. Tests inject a fake.
type S3Client interface {
	// PresignPut returns a URL that accepts ONE PUT of exactly sizeBytes bytes
	// (the size is signed into the URL as Content-Length, so a client can't
	// upload more than it declared at init).
	PresignPut(ctx context.Context, objectKey string, sizeBytes int64, expires time.Duration) (string, error)
	PresignGet(ctx context.Context, objectKey string, expires time.Duration) (string, error)
	DeleteObject(ctx context.Context, objectKey string) error
	// GetObject streams the object's bytes server-side. Used by the onion
	// media-stream path so media stays on the no-exit Tor route instead of
	// egressing to a CDN/S3 presigned host through a Tor exit node. The caller
	// MUST Close the returned Body.
	GetObject(ctx context.Context, objectKey string) (*ObjectStream, error)
	// PutObject stores exactly size bytes read from body under objectKey. Used
	// by the server-side upload path (web clients, which cannot PUT to a
	// presigned S3 URL from the browser).
	PutObject(ctx context.Context, objectKey string, body io.Reader, size int64, contentType string) error
}

// ObjectStream is a streamable object read from storage. The caller copies
// Body to the client and is responsible for closing it.
type ObjectStream struct {
	ContentType   string
	ContentLength int64 // -1 when unknown
	Body          io.ReadCloser
}
