package media_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/media"
	"github.com/nanb/nanb-server/internal/proto"
)

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

type seqIDs struct {
	values []string
	i      int
}

func (s *seqIDs) Next() string { v := s.values[s.i]; s.i++; return v }

type fakeS3 struct {
	putErr    error
	getErr    error
	deleteErr error
	deleted   []string

	// server-side upload (PutObject) capture
	putObjErr error
	putKey    string
	putType   string
	putSize   int64
	putBody   []byte

	// presignedSize is the size the last PresignPut was asked to sign.
	presignedSize int64

	// streaming (GetObject) controls
	getObjErr  error
	getObjBody []byte
	getObjType string
	getObjLen  int64
}

func (f *fakeS3) PresignPut(_ context.Context, key string, sizeBytes int64, _ time.Duration) (string, error) {
	f.presignedSize = sizeBytes
	if f.putErr != nil {
		return "", f.putErr
	}
	return "https://fake.s3/" + key + "?put", nil
}

func (f *fakeS3) PresignGet(_ context.Context, key string, _ time.Duration) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	return "https://fake.s3/" + key + "?get", nil
}

func (f *fakeS3) DeleteObject(_ context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, key)
	return nil
}

func (f *fakeS3) PutObject(_ context.Context, key string, body io.Reader, size int64, contentType string) error {
	if f.putObjErr != nil {
		return f.putObjErr
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	f.putKey, f.putType, f.putSize, f.putBody = key, contentType, size, data
	return nil
}

func (f *fakeS3) GetObject(_ context.Context, _ string) (*media.ObjectStream, error) {
	if f.getObjErr != nil {
		return nil, f.getObjErr
	}
	length := f.getObjLen
	if length == 0 {
		length = int64(len(f.getObjBody))
	}
	return &media.ObjectStream{
		ContentType:   f.getObjType,
		ContentLength: length,
		Body:          io.NopCloser(bytes.NewReader(f.getObjBody)),
	}, nil
}

func newSvc() (*media.Service, *media.StoreInMemory, *fakeS3) {
	store := media.NewStoreInMemory()
	s3 := &fakeS3{}
	clock := fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	ids := &seqIDs{values: []string{"m-1", "m-2", "m-3"}}

	svc := media.NewService(media.ServiceDeps{
		Store:            store,
		S3:               s3,
		Clock:            clock,
		IDGen:            ids,
		MaxSizeBytes:     100 << 20,
		DefaultRetention: 30 * 24 * time.Hour,
		PresignTTL:       15 * time.Minute,
	})
	return svc, store, s3
}

func validUploadReq() proto.InitMediaUploadRequest {
	return proto.InitMediaUploadRequest{
		SHA256:    make([]byte, 32),
		SizeBytes: 1024,
		MimeType:  "image/png",
	}
}

func TestInitUpload_HappyPath(t *testing.T) {
	svc, store, _ := newSvc()

	resp, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", validUploadReq())
	require.NoError(t, err)

	assert.Equal(t, "m-1", resp.MediaID)
	assert.Contains(t, resp.UploadURL, "?put")

	rec, err := store.GetByID(context.Background(), "m-1")
	require.NoError(t, err)
	assert.Equal(t, "image/png", rec.MimeType)
	assert.Equal(t, int64(1024), rec.SizeBytes)
	assert.Equal(t, "acc-1", rec.UploaderAccountID)
}

func TestInitUpload_RejectsBadSHA256Length(t *testing.T) {
	svc, _, _ := newSvc()
	req := validUploadReq()
	req.SHA256 = []byte("short")

	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestInitUpload_RejectsZeroSize(t *testing.T) {
	svc, _, _ := newSvc()
	req := validUploadReq()
	req.SizeBytes = 0

	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestInitUpload_RejectsOversizedFile(t *testing.T) {
	svc, _, _ := newSvc()
	req := validUploadReq()
	req.SizeBytes = (100 << 20) + 1

	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodePayloadTooLarge, apiErr.Code)
}

func TestInitUpload_RejectsEmptyMime(t *testing.T) {
	svc, _, _ := newSvc()
	req := validUploadReq()
	req.MimeType = ""

	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestInitUpload_TTLBoundedToDefault(t *testing.T) {
	svc, store, _ := newSvc()
	req := validUploadReq()
	req.TTLSeconds = int64((60 * 24 * time.Hour).Seconds()) // 60 days > 30 day default

	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", req)
	require.NoError(t, err)

	rec, err := store.GetByID(context.Background(), "m-1")
	require.NoError(t, err)
	delta := rec.ExpiresAt.Sub(rec.UploadedAt)
	assert.LessOrEqual(t, delta.Hours(), float64(30*24))
}

func TestInitUpload_TTLAcceptsShorterRequest(t *testing.T) {
	svc, store, _ := newSvc()
	req := validUploadReq()
	req.TTLSeconds = 3600

	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", req)
	require.NoError(t, err)

	rec, err := store.GetByID(context.Background(), "m-1")
	require.NoError(t, err)
	delta := rec.ExpiresAt.Sub(rec.UploadedAt)
	assert.InDelta(t, time.Hour.Seconds(), delta.Seconds(), 1.0)
}

func TestInitUpload_PropagatesS3Error(t *testing.T) {
	svc, store, s3 := newSvc()
	s3.putErr = errors.New("aws down")

	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", validUploadReq())
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)

	// Record should be marked deleted (rolled back).
	_, err = store.GetByID(context.Background(), "m-1")
	assert.ErrorIs(t, err, media.ErrNotFound)
}

type errStore struct {
	media.Store
	failInsert error
	failGet    error
	failMark   error
	failList   error
}

func (e *errStore) Insert(ctx context.Context, m proto.MediaRecord) error {
	if e.failInsert != nil {
		return e.failInsert
	}
	return e.Store.Insert(ctx, m)
}

func (e *errStore) GetByID(ctx context.Context, id string) (proto.MediaRecord, error) {
	if e.failGet != nil {
		return proto.MediaRecord{}, e.failGet
	}
	return e.Store.GetByID(ctx, id)
}

func (e *errStore) MarkDeleted(ctx context.Context, id string, now time.Time) error {
	if e.failMark != nil {
		return e.failMark
	}
	return e.Store.MarkDeleted(ctx, id, now)
}

func (e *errStore) ListExpired(ctx context.Context, now time.Time, limit int) ([]proto.MediaRecord, error) {
	if e.failList != nil {
		return nil, e.failList
	}
	return e.Store.ListExpired(ctx, now, limit)
}

func newSvcWithStore(store media.Store) (*media.Service, *fakeS3) {
	s3 := &fakeS3{}
	clock := fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	ids := &seqIDs{values: []string{"m-1", "m-2", "m-3"}}
	return media.NewService(media.ServiceDeps{
		Store:            store,
		S3:               s3,
		Clock:            clock,
		IDGen:            ids,
		MaxSizeBytes:     100 << 20,
		DefaultRetention: 30 * 24 * time.Hour,
		PresignTTL:       15 * time.Minute,
	}), s3
}

func TestInitUpload_PropagatesInsertError(t *testing.T) {
	es := &errStore{Store: media.NewStoreInMemory(), failInsert: errors.New("db down")}
	svc, _ := newSvcWithStore(es)

	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", validUploadReq())
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestGetDownload_HappyPath(t *testing.T) {
	svc, store, _ := newSvc()
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:    "m-existing",
		ObjectKey:  "media/m-existing",
		MimeType:   "image/png",
		SizeBytes:  100,
		UploadedAt: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC),
	}))

	resp, err := svc.GetDownload(context.Background(), "acc-caller", "m-existing")
	require.NoError(t, err)
	assert.Contains(t, resp.DownloadURL, "?get")
	assert.Equal(t, "image/png", resp.MimeType)
}

func TestGetDownload_NotFound(t *testing.T) {
	svc, _, _ := newSvc()
	_, err := svc.GetDownload(context.Background(), "acc-caller", "missing")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeMediaNotFound, apiErr.Code)
}

func TestGetDownload_PropagatesGenericStoreError(t *testing.T) {
	es := &errStore{Store: media.NewStoreInMemory(), failGet: errors.New("db down")}
	svc, _ := newSvcWithStore(es)

	_, err := svc.GetDownload(context.Background(), "acc-caller", "m-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestGetDownload_Expired(t *testing.T) {
	svc, store, _ := newSvc()
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:    "m-expired",
		ObjectKey:  "media/m-expired",
		MimeType:   "image/png",
		SizeBytes:  100,
		UploadedAt: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
	}))

	_, err := svc.GetDownload(context.Background(), "acc-caller", "m-expired")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeMediaExpired, apiErr.Code)
}

func TestGetDownload_PropagatesS3Error(t *testing.T) {
	svc, store, s3 := newSvc()
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:    "m-1",
		ObjectKey:  "media/m-1",
		MimeType:   "image/png",
		SizeBytes:  100,
		UploadedAt: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC),
	}))
	s3.getErr = errors.New("aws down")

	_, err := svc.GetDownload(context.Background(), "acc-caller", "m-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

// insertAuthzRecord seeds a live media record with an explicit download
// allow-list for the object-level authorization tests.
func insertAuthzRecord(t *testing.T, store *media.StoreInMemory, uploader string, allowed []string) {
	t.Helper()
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:              "m-authz",
		ObjectKey:            "media/m-authz",
		MimeType:             "image/png",
		SizeBytes:            100,
		UploaderAccountID:    uploader,
		UploadedAt:           time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
		ExpiresAt:            time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC),
		AuthorizedAccountIDs: allowed,
	}))
}

func TestGetDownload_DeniesCallerNotInAllowList(t *testing.T) {
	svc, store, _ := newSvc()
	insertAuthzRecord(t, store, "uploader", []string{"uploader", "recipient"})

	_, err := svc.GetDownload(context.Background(), "stranger", "m-authz")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeForbidden, apiErr.Code)
}

func TestGetDownload_AllowsGrantedCaller(t *testing.T) {
	svc, store, _ := newSvc()
	insertAuthzRecord(t, store, "uploader", []string{"uploader", "recipient"})

	resp, err := svc.GetDownload(context.Background(), "recipient", "m-authz")
	require.NoError(t, err)
	assert.Contains(t, resp.DownloadURL, "?get")
}

func TestGetDownload_AllowsUploaderEvenIfNotListed(t *testing.T) {
	svc, store, _ := newSvc()
	insertAuthzRecord(t, store, "uploader", []string{"recipient"}) // uploader omitted

	_, err := svc.GetDownload(context.Background(), "uploader", "m-authz")
	require.NoError(t, err)
}

func TestGetDownload_OpenWhenNoAllowList(t *testing.T) {
	svc, store, _ := newSvc()
	insertAuthzRecord(t, store, "uploader", nil) // legacy: no audience declared

	_, err := svc.GetDownload(context.Background(), "anyone-authenticated", "m-authz")
	require.NoError(t, err)
}

func TestStreamDownload_DeniesCallerNotInAllowList(t *testing.T) {
	svc, store, s3 := newSvc()
	s3.getObjBody = []byte("opaque")
	insertAuthzRecord(t, store, "uploader", []string{"uploader"})

	_, err := svc.StreamDownload(context.Background(), "stranger", "m-authz")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeForbidden, apiErr.Code)
}

func TestInitUpload_RecordsAuthorizedAudienceIncludingUploader(t *testing.T) {
	svc, store, _ := newSvc()
	req := validUploadReq()
	req.AuthorizedAccountIDs = []string{"recipient-1", "recipient-2"}

	_, err := svc.InitUpload(context.Background(), "uploader", "dev-1", req)
	require.NoError(t, err)

	rec, err := store.GetByID(context.Background(), "m-1")
	require.NoError(t, err)
	assert.Contains(t, rec.AuthorizedAccountIDs, "uploader")
	assert.Contains(t, rec.AuthorizedAccountIDs, "recipient-1")
	assert.Contains(t, rec.AuthorizedAccountIDs, "recipient-2")
}

func TestInitUpload_LeavesAllowListEmptyWhenNoneDeclared(t *testing.T) {
	svc, store, _ := newSvc()

	_, err := svc.InitUpload(context.Background(), "uploader", "dev-1", validUploadReq())
	require.NoError(t, err)

	rec, err := store.GetByID(context.Background(), "m-1")
	require.NoError(t, err)
	assert.Empty(t, rec.AuthorizedAccountIDs, "no declared audience → open (legacy) access")
}

func TestInitUpload_RejectsTooManyAuthorizedAccounts(t *testing.T) {
	svc, _, _ := newSvc()
	req := validUploadReq()
	req.AuthorizedAccountIDs = make([]string, media.MaxAuthorizedAccounts+1)

	_, err := svc.InitUpload(context.Background(), "uploader", "dev-1", req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestStreamDownload_HappyPath(t *testing.T) {
	svc, store, s3 := newSvc()
	s3.getObjBody = []byte("opaque-ciphertext-bytes")
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:    "m-stream",
		ObjectKey:  "media/m-stream",
		MimeType:   "image/png",
		SizeBytes:  int64(len("opaque-ciphertext-bytes")),
		UploadedAt: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC),
	}))

	res, err := svc.StreamDownload(context.Background(), "acc-caller", "m-stream")
	require.NoError(t, err)
	defer res.Body.Close()

	assert.Equal(t, "image/png", res.ContentType)
	assert.Equal(t, int64(len("opaque-ciphertext-bytes")), res.ContentLength)
	got, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, "opaque-ciphertext-bytes", string(got))
}

func TestStreamDownload_NotFound(t *testing.T) {
	svc, _, _ := newSvc()
	_, err := svc.StreamDownload(context.Background(), "acc-caller", "missing")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeMediaNotFound, apiErr.Code)
}

func TestStreamDownload_Expired(t *testing.T) {
	svc, store, _ := newSvc()
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:    "m-expired",
		ObjectKey:  "media/m-expired",
		MimeType:   "image/png",
		SizeBytes:  100,
		UploadedAt: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
	}))

	_, err := svc.StreamDownload(context.Background(), "acc-caller", "m-expired")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeMediaExpired, apiErr.Code)
}

func TestStreamDownload_PropagatesS3Error(t *testing.T) {
	svc, store, s3 := newSvc()
	s3.getObjErr = errors.New("aws down")
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:    "m-1",
		ObjectKey:  "media/m-1",
		MimeType:   "image/png",
		SizeBytes:  100,
		UploadedAt: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC),
	}))

	_, err := svc.StreamDownload(context.Background(), "acc-caller", "m-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestStreamDownload_PropagatesGenericStoreError(t *testing.T) {
	es := &errStore{Store: media.NewStoreInMemory(), failGet: errors.New("db down")}
	svc, _ := newSvcWithStore(es)

	_, err := svc.StreamDownload(context.Background(), "acc-caller", "m-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestDeleteExpired_DeletesAndMarks(t *testing.T) {
	svc, store, s3 := newSvc()
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:    "m-old",
		ObjectKey:  "media/m-old",
		MimeType:   "image/png",
		SizeBytes:  100,
		UploadedAt: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
	}))

	deleted, err := svc.DeleteExpired(context.Background(), 100)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)
	assert.Contains(t, s3.deleted, "media/m-old")
}

func TestDeleteExpired_NoExpiredReturnsZero(t *testing.T) {
	svc, _, _ := newSvc()
	deleted, err := svc.DeleteExpired(context.Background(), 100)
	require.NoError(t, err)
	assert.Equal(t, 0, deleted)
}

func TestDeleteExpired_PropagatesListError(t *testing.T) {
	es := &errStore{Store: media.NewStoreInMemory(), failList: errors.New("db down")}
	svc, _ := newSvcWithStore(es)

	_, err := svc.DeleteExpired(context.Background(), 100)
	assert.Error(t, err)
}

// A per-record S3 failure is logged + skipped (not propagated) so a single
// poisoned object can't block retention. The batch-level error is still
// surfaced via the upstream ListExpired path (covered separately).
func TestDeleteExpired_S3FailureSkipsRecord(t *testing.T) {
	svc, store, s3 := newSvc()
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:    "m-old",
		ObjectKey:  "media/m-old",
		MimeType:   "image/png",
		SizeBytes:  100,
		UploadedAt: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
	}))
	s3.deleteErr = errors.New("aws down")

	deleted, err := svc.DeleteExpired(context.Background(), 100)
	assert.NoError(t, err)
	assert.Equal(t, 0, deleted, "failed records are skipped, not counted as deleted")
}

// MarkDeleted failure: same swallow-and-continue contract as the S3 failure.
func TestDeleteExpired_MarkDeletedFailureSkipsRecord(t *testing.T) {
	es := &errStore{Store: media.NewStoreInMemory(), failMark: errors.New("db down")}
	require.NoError(t, es.Store.Insert(context.Background(), proto.MediaRecord{
		MediaID:    "m-old",
		ObjectKey:  "media/m-old",
		UploadedAt: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC),
	}))
	svc, _ := newSvcWithStore(es)

	deleted, err := svc.DeleteExpired(context.Background(), 100)
	assert.NoError(t, err)
	assert.Equal(t, 0, deleted)
}

func TestStoreInMemory_MarkDeleted_NotFound(t *testing.T) {
	store := media.NewStoreInMemory()
	err := store.MarkDeleted(context.Background(), "missing", time.Now())
	assert.ErrorIs(t, err, media.ErrNotFound)
}

func TestStoreInMemory_GetByID_DeletedReturnsNotFound(t *testing.T) {
	store := media.NewStoreInMemory()
	now := time.Now()
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{MediaID: "m-1", ExpiresAt: now.Add(time.Hour)}))
	require.NoError(t, store.MarkDeleted(context.Background(), "m-1", now))

	_, err := store.GetByID(context.Background(), "m-1")
	assert.ErrorIs(t, err, media.ErrNotFound)
}

func TestStoreInMemory_ListExpired_RespectsLimit(t *testing.T) {
	store := media.NewStoreInMemory()
	now := time.Now()
	pastExpiry := now.Add(-time.Hour)
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
			MediaID:   string(rune('a' + i)),
			ExpiresAt: pastExpiry,
		}))
	}

	expired, err := store.ListExpired(context.Background(), now, 2)
	require.NoError(t, err)
	assert.Len(t, expired, 2)
}

func TestStoreInMemory_ListExpired_SkipsDeleted(t *testing.T) {
	store := media.NewStoreInMemory()
	now := time.Now()
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:   "m-1",
		ExpiresAt: now.Add(-time.Hour),
	}))
	require.NoError(t, store.MarkDeleted(context.Background(), "m-1", now))

	expired, err := store.ListExpired(context.Background(), now, 100)
	require.NoError(t, err)
	assert.Empty(t, expired)
}

func TestInitUpload_ServerUploadReturnsOurOwnEndpoint(t *testing.T) {
	svc, _, _ := newSvc()
	req := validUploadReq()
	req.ServerUpload = true

	resp, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", req)
	require.NoError(t, err)

	assert.Equal(t, "/media/upload?media_id=m-1", resp.UploadURL)
}

func TestUploadObject_StoresTheCiphertext(t *testing.T) {
	svc, _, s3 := newSvc()
	req := validUploadReq()
	req.SizeBytes = 5
	req.ServerUpload = true
	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", req)
	require.NoError(t, err)

	err = svc.UploadObject(context.Background(), "acc-1", "m-1", bytes.NewReader([]byte("hello")), 5)

	require.NoError(t, err)
	assert.Equal(t, "media/m-1", s3.putKey)
	assert.Equal(t, []byte("hello"), s3.putBody)
	assert.Equal(t, int64(5), s3.putSize)
}

func TestUploadObject_RejectsAnotherAccount(t *testing.T) {
	svc, _, s3 := newSvc()
	req := validUploadReq()
	req.SizeBytes = 5
	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", req)
	require.NoError(t, err)

	err = svc.UploadObject(context.Background(), "acc-2", "m-1", bytes.NewReader([]byte("hello")), 5)

	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeForbidden, apiErr.Code)
	assert.Nil(t, s3.putBody)
}

func TestUploadObject_RejectsASizeThatDiffersFromInit(t *testing.T) {
	svc, _, s3 := newSvc()
	req := validUploadReq()
	req.SizeBytes = 5
	_, err := svc.InitUpload(context.Background(), "acc-1", "dev-1", req)
	require.NoError(t, err)

	err = svc.UploadObject(context.Background(), "acc-1", "m-1", bytes.NewReader([]byte("hello world")), 11)

	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
	assert.Nil(t, s3.putBody)
}

func TestUploadObject_UnknownMedia(t *testing.T) {
	svc, _, _ := newSvc()

	err := svc.UploadObject(context.Background(), "acc-1", "nope", bytes.NewReader([]byte("x")), 1)

	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeMediaNotFound, apiErr.Code)
}
