package media

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/proto"
)

// maxStreamBytes is a hard backstop on the onion media-stream response so a
// mis-sized record can't be coerced into an unbounded copy. It matches the
// 100 MiB media upload ceiling (NANB_MEDIA_MAX_SIZE_MB default).
const maxStreamBytes = 100 << 20

type ServiceAPI interface {
	InitUpload(ctx context.Context, accountID, deviceID string, req proto.InitMediaUploadRequest) (proto.InitMediaUploadResponse, error)
	GetDownload(ctx context.Context, callerAccountID, mediaID string) (proto.GetMediaResponse, error)
	// StreamDownload streams the object's bytes server-side (onion path).
	StreamDownload(ctx context.Context, callerAccountID, mediaID string) (*StreamResult, error)
	// UploadObject stores the uploader's ciphertext server-side (web uploads).
	UploadObject(ctx context.Context, callerAccountID, mediaID string, body io.Reader, contentLength int64) error
}

type Handlers struct {
	svc ServiceAPI
}

func NewHandlers(svc ServiceAPI) *Handlers {
	return &Handlers{svc: svc}
}

func (h *Handlers) PostInitUpload(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}
	var req proto.InitMediaUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid JSON"})
		return
	}
	resp, err := h.svc.InitUpload(r.Context(), claims.AccountID, claims.DeviceID, req)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *Handlers) PostGetMedia(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}
	var req proto.GetMediaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid JSON"})
		return
	}
	resp, err := h.svc.GetDownload(r.Context(), claims.AccountID, req.MediaID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// PostUpload — POST /media/upload?media_id=<id>
//
// Receives the raw (already E2EE) ciphertext for a media record the caller
// initialised with server_upload, and stores it in S3. This exists because a
// browser cannot PUT to the presigned S3 URL (cross-origin, no CORS on the
// bucket); native clients keep the presigned PUT. Auth-gated and bound to the
// uploader + the declared size, so it is never an open write path.
func (h *Handlers) PostUpload(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}
	mediaID := r.URL.Query().Get("media_id")
	if mediaID == "" {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "missing media_id"})
		return
	}
	if r.ContentLength <= 0 {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "Content-Length required"})
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxStreamBytes)
	defer body.Close()
	if err := h.svc.UploadObject(r.Context(), claims.AccountID, mediaID, body, r.ContentLength); err != nil {
		writeAPIError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetStream — GET /media/stream?media_id=<id>
//
// Streams a media object's (already E2EE) bytes back to the client from S3,
// server-side. Used when the client routes over built-in Tor: fetching here
// keeps media on the no-exit onion path (server→S3 stays inside AWS) instead
// of egressing to a CDN/S3 presigned host through a Tor exit node. When NOT on
// Tor the client keeps using POST /media/get (presigned/CloudFront) for CDN
// performance.
//
// Auth-gated exactly like PostGetMedia — never an open proxy.
func (h *Handlers) GetStream(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, proto.APIError{Code: proto.ErrCodeUnauthorized, Message: "unauthorized"})
		return
	}
	mediaID := r.URL.Query().Get("media_id")
	if mediaID == "" {
		writeJSON(w, http.StatusBadRequest, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "missing media_id"})
		return
	}
	res, err := h.svc.StreamDownload(r.Context(), claims.AccountID, mediaID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	defer res.Body.Close()

	w.Header().Set("Content-Type", sanitizeContentType(res.ContentType))
	w.Header().Set("Cache-Control", "private, no-store")
	if res.ContentLength > 0 && res.ContentLength <= maxStreamBytes {
		w.Header().Set("Content-Length", strconv.FormatInt(res.ContentLength, 10))
	}
	w.WriteHeader(http.StatusOK)
	// LimitReader is a backstop in case the stored size was absent/under-reported.
	_, _ = io.Copy(w, io.LimitReader(res.Body, maxStreamBytes))
}

// sanitizeContentType keeps the streamed Content-Type to a benign type so the
// authenticated stream endpoint can't be coerced into serving active content.
// Media blobs are opaque ciphertext, so octet-stream is the safe default;
// image/* and video/* pass through for clients that branch on it.
func sanitizeContentType(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "video/") {
		return ct
	}
	return "application/octet-stream"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, err error) {
	var apiErr proto.APIError
	if errors.As(err, &apiErr) {
		writeJSON(w, statusForCode(apiErr.Code), apiErr)
		return
	}
	writeJSON(w, http.StatusInternalServerError, proto.APIError{Code: proto.ErrCodeInternal, Message: "internal"})
}

func statusForCode(code proto.ErrorCode) int {
	switch code {
	case proto.ErrCodeBadRequest:
		return http.StatusBadRequest
	case proto.ErrCodeUnauthorized:
		return http.StatusUnauthorized
	case proto.ErrCodeForbidden:
		return http.StatusForbidden
	case proto.ErrCodeMediaNotFound:
		return http.StatusNotFound
	case proto.ErrCodeMediaExpired:
		return http.StatusGone
	case proto.ErrCodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusInternalServerError
	}
}
