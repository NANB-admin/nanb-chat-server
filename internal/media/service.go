package media

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"time"

	"github.com/nanb/nanb-server/internal/apierr"
	"github.com/nanb/nanb-server/internal/proto"
)

type Clock interface {
	Now() time.Time
}

type IDGenerator interface {
	Next() string
}

type ServiceDeps struct {
	Store            Store
	S3               S3Client
	Clock            Clock
	IDGen            IDGenerator
	MaxSizeBytes     int64
	DefaultRetention time.Duration
	PresignTTL       time.Duration
	// CDN is optional. When set, GetDownload returns a CloudFront signed URL
	// (edge-cached) instead of an S3 presigned GET. Nil = disabled.
	CDN CDNSigner
}

type Service struct {
	deps ServiceDeps
}

func NewService(deps ServiceDeps) *Service {
	return &Service{deps: deps}
}

// MaxAuthorizedAccounts caps the download allow-list a single upload may declare,
// so a client can't pin an unbounded array. Generous relative to real
// conversation/group sizes (the server group cap is far smaller).
const MaxAuthorizedAccounts = 256

// authorizedToFetch reports whether callerAccountID may download rec. An empty
// allow-list means legacy/open access (older clients that didn't declare an
// audience — see the documented gap on GetDownload); the uploader is always
// allowed regardless of the list.
func authorizedToFetch(rec proto.MediaRecord, callerAccountID string) bool {
	if len(rec.AuthorizedAccountIDs) == 0 {
		return true
	}
	if callerAccountID != "" && callerAccountID == rec.UploaderAccountID {
		return true
	}
	for _, id := range rec.AuthorizedAccountIDs {
		if id == callerAccountID {
			return true
		}
	}
	return false
}

func (s *Service) InitUpload(ctx context.Context, accountID, deviceID string, req proto.InitMediaUploadRequest) (proto.InitMediaUploadResponse, error) {
	var resp proto.InitMediaUploadResponse

	if len(req.SHA256) != sha256.Size {
		return resp, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "sha256 must be 32 bytes"}
	}
	if req.SizeBytes <= 0 {
		return resp, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "size_bytes must be > 0"}
	}
	if req.SizeBytes > s.deps.MaxSizeBytes {
		return resp, proto.APIError{Code: proto.ErrCodePayloadTooLarge, Message: "size exceeds max"}
	}
	if req.MimeType == "" {
		return resp, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "mime_type required"}
	}
	if len(req.AuthorizedAccountIDs) > MaxAuthorizedAccounts {
		return resp, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "too many authorized accounts"}
	}

	now := s.deps.Clock.Now()
	mediaID := s.deps.IDGen.Next()
	objectKey := "media/" + mediaID

	// Record the download allow-list only when the client declared one. The
	// uploader is folded in so it can always fetch its own object; enforcement
	// lives in GetDownload/StreamDownload. Absent (older clients) → nil → the
	// object stays open to any authenticated caller (the documented gap).
	var authorized []string
	if len(req.AuthorizedAccountIDs) > 0 {
		authorized = make([]string, 0, len(req.AuthorizedAccountIDs)+1)
		authorized = append(authorized, accountID)
		for _, id := range req.AuthorizedAccountIDs {
			if id != "" && id != accountID {
				authorized = append(authorized, id)
			}
		}
	}

	ttl := s.deps.DefaultRetention
	if req.TTLSeconds > 0 {
		want := time.Duration(req.TTLSeconds) * time.Second
		if want < ttl {
			ttl = want
		}
	}

	rec := proto.MediaRecord{
		MediaID:              mediaID,
		UploaderAccountID:    accountID,
		UploaderDeviceID:     deviceID,
		SHA256:               req.SHA256,
		SizeBytes:            req.SizeBytes,
		MimeType:             req.MimeType,
		ObjectKey:            objectKey,
		UploadedAt:           now,
		ExpiresAt:            now.Add(ttl),
		AuthorizedAccountIDs: authorized,
	}

	if err := s.deps.Store.Insert(ctx, rec); err != nil {
		return resp, apierr.Internal(err)
	}

	// A web client can't PUT to a presigned S3 URL, so it uploads through this
	// server instead: hand back our own (relative) upload endpoint.
	if req.ServerUpload {
		resp.MediaID = mediaID
		resp.UploadURL = "/media/upload?media_id=" + mediaID
		resp.UploadExpiry = now.Add(s.deps.PresignTTL)
		return resp, nil
	}

	// The declared size is signed into the URL, so the PUT must be exactly
	// that many bytes (the client sends Content-Length = ciphertext length,
	// the same value it declared as size_bytes).
	url, err := s.deps.S3.PresignPut(ctx, objectKey, req.SizeBytes, s.deps.PresignTTL)
	if err != nil {
		_ = s.deps.Store.MarkDeleted(ctx, mediaID, now)
		return resp, apierr.Internal(err)
	}

	resp.MediaID = mediaID
	resp.UploadURL = url
	resp.UploadExpiry = now.Add(s.deps.PresignTTL)
	return resp, nil
}

// UploadObject stores the (already E2EE) ciphertext for a media record that
// callerAccountID initialised with ServerUpload. Only the uploader may write it,
// only until the record expires, and the body must be EXACTLY the size declared
// at init, so this is not an open write path.
func (s *Service) UploadObject(ctx context.Context, callerAccountID, mediaID string, body io.Reader, contentLength int64) error {
	rec, err := s.deps.Store.GetByID(ctx, mediaID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return proto.APIError{Code: proto.ErrCodeMediaNotFound, Message: "media not found"}
		}
		return apierr.Internal(err)
	}
	if callerAccountID == "" || rec.UploaderAccountID != callerAccountID {
		return proto.APIError{Code: proto.ErrCodeForbidden, Message: "not the uploader of this media"}
	}
	if !rec.ExpiresAt.After(s.deps.Clock.Now()) {
		return proto.APIError{Code: proto.ErrCodeMediaExpired, Message: "media expired"}
	}
	if contentLength != rec.SizeBytes {
		return proto.APIError{Code: proto.ErrCodeBadRequest, Message: "body size does not match size_bytes"}
	}
	if err := s.deps.S3.PutObject(ctx, rec.ObjectKey, io.LimitReader(body, rec.SizeBytes), rec.SizeBytes, "application/octet-stream"); err != nil {
		return apierr.Internal(err)
	}
	return nil
}

func (s *Service) GetDownload(ctx context.Context, callerAccountID, mediaID string) (proto.GetMediaResponse, error) {
	var resp proto.GetMediaResponse
	rec, err := s.deps.Store.GetByID(ctx, mediaID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return resp, proto.APIError{Code: proto.ErrCodeMediaNotFound, Message: "media not found"}
		}
		return resp, apierr.Internal(err)
	}

	now := s.deps.Clock.Now()
	if !rec.ExpiresAt.After(now) {
		return resp, proto.APIError{Code: proto.ErrCodeMediaExpired, Message: "media expired"}
	}

	// Object-level authorization. When the uploader declared a download audience,
	// only the uploader or a listed account may fetch. GAP: objects uploaded by
	// clients that don't declare an audience (all current clients, and anything
	// pre-migration) carry no list and remain readable by any authenticated
	// caller — the media_id is a random UUID learned only via the E2EE envelope
	// and the bytes are E2EE, so the residual exposure is low. Future clients
	// that populate authorized_account_ids get real per-object enforcement.
	if !authorizedToFetch(rec, callerAccountID) {
		return resp, proto.APIError{Code: proto.ErrCodeForbidden, Message: "not authorized for this media"}
	}

	expiry := now.Add(s.deps.PresignTTL)

	// Prefer a CloudFront signed URL (edge cache) when configured; fall back
	// to an S3 presigned GET if the CDN is disabled or signing fails, so a CDN
	// misconfiguration degrades to origin reads rather than breaking media.
	if s.deps.CDN != nil {
		if url, err := s.deps.CDN.SignedURL(rec.ObjectKey, expiry); err == nil {
			resp.DownloadURL = url
			resp.DownloadExpiry = expiry
			resp.MimeType = rec.MimeType
			resp.SizeBytes = rec.SizeBytes
			return resp, nil
		} else {
			log.Printf("media: CloudFront sign failed, falling back to S3 presign: %v", err)
		}
	}

	url, err := s.deps.S3.PresignGet(ctx, rec.ObjectKey, s.deps.PresignTTL)
	if err != nil {
		return resp, apierr.Internal(err)
	}

	resp.DownloadURL = url
	resp.DownloadExpiry = expiry
	resp.MimeType = rec.MimeType
	resp.SizeBytes = rec.SizeBytes
	return resp, nil
}

// StreamResult is a server-side stream of a media object's bytes. The caller
// (handler) MUST Close Body. ContentType/ContentLength come from the stored
// MediaRecord (authoritative) rather than S3's object metadata, so the
// response is consistent with what the uploader declared.
type StreamResult struct {
	ContentType   string
	ContentLength int64 // bytes; the stored size (-1 if unknown)
	Body          io.ReadCloser
}

// StreamDownload resolves mediaID exactly as GetDownload does (store lookup +
// expiry check) and returns a server-side stream of the object's bytes from
// S3. Used by the onion media-stream endpoint so media bytes stay on the
// no-exit Tor path instead of egressing through a Tor exit node to a CDN/S3
// presigned host. The bytes are already E2EE — this only changes transport.
func (s *Service) StreamDownload(ctx context.Context, callerAccountID, mediaID string) (*StreamResult, error) {
	rec, err := s.deps.Store.GetByID(ctx, mediaID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, proto.APIError{Code: proto.ErrCodeMediaNotFound, Message: "media not found"}
		}
		return nil, apierr.Internal(err)
	}

	now := s.deps.Clock.Now()
	if !rec.ExpiresAt.After(now) {
		return nil, proto.APIError{Code: proto.ErrCodeMediaExpired, Message: "media expired"}
	}

	// Same object-level authorization as GetDownload (see the gap note there).
	if !authorizedToFetch(rec, callerAccountID) {
		return nil, proto.APIError{Code: proto.ErrCodeForbidden, Message: "not authorized for this media"}
	}

	obj, err := s.deps.S3.GetObject(ctx, rec.ObjectKey)
	if err != nil {
		return nil, apierr.Internal(err)
	}

	// Trust the stored size/mime (what the uploader declared) over S3's object
	// metadata. The body itself is opaque E2EE ciphertext.
	length := rec.SizeBytes
	if length <= 0 {
		length = obj.ContentLength
	}
	return &StreamResult{
		ContentType:   rec.MimeType,
		ContentLength: length,
		Body:          obj.Body,
	}, nil
}

// DeleteExpired processes a batch of expired media records. A failure on one
// record (S3 transient error, race with another worker) is logged and
// skipped rather than aborting the whole batch — otherwise a single bad
// object key would block retention indefinitely.
func (s *Service) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	now := s.deps.Clock.Now()
	expired, err := s.deps.Store.ListExpired(ctx, now, batchSize)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, rec := range expired {
		if err := s.deps.S3.DeleteObject(ctx, rec.ObjectKey); err != nil {
			log.Printf("retention: s3 delete failed: %v", err)
			continue
		}
		if err := s.deps.Store.MarkDeleted(ctx, rec.MediaID, now); err != nil {
			log.Printf("retention: mark deleted failed: %v", err)
			continue
		}
		deleted++
	}
	return deleted, nil
}
