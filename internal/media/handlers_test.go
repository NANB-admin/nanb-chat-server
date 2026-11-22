package media_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/media"
	"github.com/nanb/nanb-server/internal/proto"
)

type mockSvc struct {
	init    func(ctx context.Context, accountID, deviceID string, req proto.InitMediaUploadRequest) (proto.InitMediaUploadResponse, error)
	getDown func(ctx context.Context, mediaID string) (proto.GetMediaResponse, error)
	stream  func(ctx context.Context, mediaID string) (*media.StreamResult, error)
	upload  func(ctx context.Context, accountID, mediaID string, body io.Reader, contentLength int64) error
}

func (m *mockSvc) UploadObject(ctx context.Context, accountID, mediaID string, body io.Reader, contentLength int64) error {
	return m.upload(ctx, accountID, mediaID, body, contentLength)
}

func (m *mockSvc) InitUpload(ctx context.Context, accountID, deviceID string, req proto.InitMediaUploadRequest) (proto.InitMediaUploadResponse, error) {
	return m.init(ctx, accountID, deviceID, req)
}

func (m *mockSvc) GetDownload(ctx context.Context, _, mediaID string) (proto.GetMediaResponse, error) {
	return m.getDown(ctx, mediaID)
}

func (m *mockSvc) StreamDownload(ctx context.Context, _, mediaID string) (*media.StreamResult, error) {
	return m.stream(ctx, mediaID)
}

func ctxWithClaims(deviceID, accountID string) context.Context {
	return auth.InjectClaimsForTest(context.Background(), crypto.JWTClaims{
		AccountID: accountID,
		DeviceID:  deviceID,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
}

func TestPostInitUpload_HappyPath(t *testing.T) {
	svc := &mockSvc{
		init: func(ctx context.Context, acc, dev string, r proto.InitMediaUploadRequest) (proto.InitMediaUploadResponse, error) {
			assert.Equal(t, "acc-1", acc)
			assert.Equal(t, "dev-1", dev)
			return proto.InitMediaUploadResponse{MediaID: "m-1", UploadURL: "https://fake/put"}, nil
		},
	}
	h := media.NewHandlers(svc)
	body, _ := json.Marshal(proto.InitMediaUploadRequest{SHA256: make([]byte, 32), SizeBytes: 1, MimeType: "image/png"})
	req := httptest.NewRequest(http.MethodPost, "/media/init", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostInitUpload(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	var resp proto.InitMediaUploadResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "m-1", resp.MediaID)
}

func TestPostInitUpload_NoClaims_Returns401(t *testing.T) {
	h := media.NewHandlers(&mockSvc{})
	body, _ := json.Marshal(proto.InitMediaUploadRequest{})
	req := httptest.NewRequest(http.MethodPost, "/media/init", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostInitUpload(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostInitUpload_BadJSON_Returns400(t *testing.T) {
	h := media.NewHandlers(&mockSvc{})
	req := httptest.NewRequest(http.MethodPost, "/media/init", bytes.NewReader([]byte("not-json"))).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostInitUpload(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostInitUpload_PayloadTooLarge_Returns413(t *testing.T) {
	svc := &mockSvc{
		init: func(ctx context.Context, acc, dev string, r proto.InitMediaUploadRequest) (proto.InitMediaUploadResponse, error) {
			return proto.InitMediaUploadResponse{}, proto.APIError{Code: proto.ErrCodePayloadTooLarge, Message: "x"}
		},
	}
	h := media.NewHandlers(svc)
	body, _ := json.Marshal(proto.InitMediaUploadRequest{})
	req := httptest.NewRequest(http.MethodPost, "/media/init", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostInitUpload(rec, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestPostInitUpload_BadRequest_Returns400(t *testing.T) {
	svc := &mockSvc{
		init: func(ctx context.Context, acc, dev string, r proto.InitMediaUploadRequest) (proto.InitMediaUploadResponse, error) {
			return proto.InitMediaUploadResponse{}, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "x"}
		},
	}
	h := media.NewHandlers(svc)
	body, _ := json.Marshal(proto.InitMediaUploadRequest{})
	req := httptest.NewRequest(http.MethodPost, "/media/init", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostInitUpload(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostInitUpload_GenericError_Returns500(t *testing.T) {
	svc := &mockSvc{
		init: func(ctx context.Context, acc, dev string, r proto.InitMediaUploadRequest) (proto.InitMediaUploadResponse, error) {
			return proto.InitMediaUploadResponse{}, errors.New("boom")
		},
	}
	h := media.NewHandlers(svc)
	body, _ := json.Marshal(proto.InitMediaUploadRequest{})
	req := httptest.NewRequest(http.MethodPost, "/media/init", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostInitUpload(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPostInitUpload_APIInternal_Returns500(t *testing.T) {
	svc := &mockSvc{
		init: func(ctx context.Context, acc, dev string, r proto.InitMediaUploadRequest) (proto.InitMediaUploadResponse, error) {
			return proto.InitMediaUploadResponse{}, proto.APIError{Code: proto.ErrCodeInternal, Message: "x"}
		},
	}
	h := media.NewHandlers(svc)
	body, _ := json.Marshal(proto.InitMediaUploadRequest{})
	req := httptest.NewRequest(http.MethodPost, "/media/init", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostInitUpload(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPostGetMedia_HappyPath(t *testing.T) {
	svc := &mockSvc{
		getDown: func(ctx context.Context, mediaID string) (proto.GetMediaResponse, error) {
			assert.Equal(t, "m-1", mediaID)
			return proto.GetMediaResponse{DownloadURL: "https://fake/get", MimeType: "image/png", SizeBytes: 100}, nil
		},
	}
	h := media.NewHandlers(svc)
	body, _ := json.Marshal(proto.GetMediaRequest{MediaID: "m-1"})
	req := httptest.NewRequest(http.MethodPost, "/media/get", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostGetMedia(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPostGetMedia_NoClaims_Returns401(t *testing.T) {
	h := media.NewHandlers(&mockSvc{})
	body, _ := json.Marshal(proto.GetMediaRequest{MediaID: "m-1"})
	req := httptest.NewRequest(http.MethodPost, "/media/get", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.PostGetMedia(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostGetMedia_BadJSON_Returns400(t *testing.T) {
	h := media.NewHandlers(&mockSvc{})
	req := httptest.NewRequest(http.MethodPost, "/media/get", bytes.NewReader([]byte("nope"))).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostGetMedia(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostGetMedia_NotFound_Returns404(t *testing.T) {
	svc := &mockSvc{
		getDown: func(ctx context.Context, mediaID string) (proto.GetMediaResponse, error) {
			return proto.GetMediaResponse{}, proto.APIError{Code: proto.ErrCodeMediaNotFound, Message: "x"}
		},
	}
	h := media.NewHandlers(svc)
	body, _ := json.Marshal(proto.GetMediaRequest{MediaID: "m-1"})
	req := httptest.NewRequest(http.MethodPost, "/media/get", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostGetMedia(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPostGetMedia_Expired_Returns410(t *testing.T) {
	svc := &mockSvc{
		getDown: func(ctx context.Context, mediaID string) (proto.GetMediaResponse, error) {
			return proto.GetMediaResponse{}, proto.APIError{Code: proto.ErrCodeMediaExpired, Message: "x"}
		},
	}
	h := media.NewHandlers(svc)
	body, _ := json.Marshal(proto.GetMediaRequest{MediaID: "m-1"})
	req := httptest.NewRequest(http.MethodPost, "/media/get", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostGetMedia(rec, req)

	assert.Equal(t, http.StatusGone, rec.Code)
}

func TestPostInitUpload_APIUnauthorized_Returns401(t *testing.T) {
	svc := &mockSvc{
		init: func(ctx context.Context, acc, dev string, r proto.InitMediaUploadRequest) (proto.InitMediaUploadResponse, error) {
			return proto.InitMediaUploadResponse{}, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "x"}
		},
	}
	h := media.NewHandlers(svc)
	body, _ := json.Marshal(proto.InitMediaUploadRequest{})
	req := httptest.NewRequest(http.MethodPost, "/media/init", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostInitUpload(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostGetMedia_GenericError_Returns500(t *testing.T) {
	svc := &mockSvc{
		getDown: func(ctx context.Context, mediaID string) (proto.GetMediaResponse, error) {
			return proto.GetMediaResponse{}, errors.New("boom")
		},
	}
	h := media.NewHandlers(svc)
	body, _ := json.Marshal(proto.GetMediaRequest{MediaID: "m-1"})
	req := httptest.NewRequest(http.MethodPost, "/media/get", bytes.NewReader(body)).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostGetMedia(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestGetStream_HappyPath(t *testing.T) {
	payload := []byte("opaque-ciphertext")
	svc := &mockSvc{
		stream: func(ctx context.Context, mediaID string) (*media.StreamResult, error) {
			assert.Equal(t, "m-1", mediaID)
			return &media.StreamResult{
				ContentType:   "image/png",
				ContentLength: int64(len(payload)),
				Body:          io.NopCloser(bytes.NewReader(payload)),
			}, nil
		},
	}
	h := media.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodGet, "/media/stream?media_id=m-1", nil).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.GetStream(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "image/png", rec.Header().Get("Content-Type"))
	assert.Equal(t, "17", rec.Header().Get("Content-Length"))
	assert.Equal(t, payload, rec.Body.Bytes())
}

// An unexpected (e.g. text/html) content type is downgraded to octet-stream so
// the authed stream endpoint can't be coerced into serving active content.
func TestGetStream_SanitizesContentType(t *testing.T) {
	svc := &mockSvc{
		stream: func(ctx context.Context, mediaID string) (*media.StreamResult, error) {
			return &media.StreamResult{
				ContentType:   "text/html; charset=utf-8",
				ContentLength: 3,
				Body:          io.NopCloser(bytes.NewReader([]byte("abc"))),
			}, nil
		},
	}
	h := media.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodGet, "/media/stream?media_id=m-1", nil).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.GetStream(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
}

func TestGetStream_NoClaims_Returns401(t *testing.T) {
	h := media.NewHandlers(&mockSvc{})
	req := httptest.NewRequest(http.MethodGet, "/media/stream?media_id=m-1", nil)
	rec := httptest.NewRecorder()

	h.GetStream(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGetStream_MissingMediaID_Returns400(t *testing.T) {
	h := media.NewHandlers(&mockSvc{})
	req := httptest.NewRequest(http.MethodGet, "/media/stream", nil).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.GetStream(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGetStream_NotFound_Returns404(t *testing.T) {
	svc := &mockSvc{
		stream: func(ctx context.Context, mediaID string) (*media.StreamResult, error) {
			return nil, proto.APIError{Code: proto.ErrCodeMediaNotFound, Message: "x"}
		},
	}
	h := media.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodGet, "/media/stream?media_id=missing", nil).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.GetStream(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGetStream_Expired_Returns410(t *testing.T) {
	svc := &mockSvc{
		stream: func(ctx context.Context, mediaID string) (*media.StreamResult, error) {
			return nil, proto.APIError{Code: proto.ErrCodeMediaExpired, Message: "x"}
		},
	}
	h := media.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodGet, "/media/stream?media_id=m-1", nil).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.GetStream(rec, req)

	assert.Equal(t, http.StatusGone, rec.Code)
}

func TestPostUpload_PassesTheBodyAndLengthToTheService(t *testing.T) {
	var gotAcc, gotMedia string
	var gotLen int64
	var gotBody []byte
	svc := &mockSvc{
		upload: func(_ context.Context, acc, mediaID string, body io.Reader, n int64) error {
			gotAcc, gotMedia, gotLen = acc, mediaID, n
			gotBody, _ = io.ReadAll(body)
			return nil
		},
	}
	h := media.NewHandlers(svc)
	req := httptest.NewRequest(http.MethodPost, "/media/upload?media_id=m-1", bytes.NewReader([]byte("cipher"))).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostUpload(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "acc-1", gotAcc)
	assert.Equal(t, "m-1", gotMedia)
	assert.Equal(t, int64(6), gotLen)
	assert.Equal(t, []byte("cipher"), gotBody)
}

func TestPostUpload_RequiresAMediaID(t *testing.T) {
	h := media.NewHandlers(&mockSvc{})
	req := httptest.NewRequest(http.MethodPost, "/media/upload", bytes.NewReader([]byte("x"))).
		WithContext(ctxWithClaims("dev-1", "acc-1"))
	rec := httptest.NewRecorder()

	h.PostUpload(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostUpload_RequiresAuth(t *testing.T) {
	h := media.NewHandlers(&mockSvc{})
	req := httptest.NewRequest(http.MethodPost, "/media/upload?media_id=m-1", bytes.NewReader([]byte("x")))
	rec := httptest.NewRecorder()

	h.PostUpload(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
