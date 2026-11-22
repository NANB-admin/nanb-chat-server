package gif

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/proto"
)

type Handlers struct {
	svc *Service
}

func NewHandlers(svc *Service) *Handlers {
	return &Handlers{svc: svc}
}

const defaultLimit = 30

// GetTrending — GET /gifs/trending?limit=
func (h *Handlers) GetTrending(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	results, err := h.svc.Trending(r.Context(), parseLimit(r.URL.Query().Get("limit")))
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	writeGifs(w, results)
}

// GetSearch — GET /gifs/search?q=&limit=
func (h *Handlers) GetSearch(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	results, err := h.svc.Search(
		r.Context(), r.URL.Query().Get("q"), parseLimit(r.URL.Query().Get("limit")))
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	writeGifs(w, results)
}

// GetMedia — GET /gifs/media?url=<provider media url>
//
// Streams a GIF's bytes from the provider's CDN so the download leaves the
// server's IP instead of the user's. The url MUST be an https provider host
// (SSRF guard in the service); anything else is a 400.
func (h *Handlers) GetMedia(w http.ResponseWriter, r *http.Request) {
	if !h.guard(w, r) {
		return
	}
	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		writeAPIError(w, http.StatusBadRequest, proto.APIError{
			Code: proto.ErrCodeBadRequest, Message: "missing url",
		})
		return
	}
	res, err := h.svc.FetchMedia(r.Context(), rawURL)
	if err != nil {
		if errors.Is(err, ErrMediaHostNotAllowed) {
			writeAPIError(w, http.StatusBadRequest, proto.APIError{
				Code: proto.ErrCodeBadRequest, Message: "url must be a giphy host",
			})
			return
		}
		writeUpstreamError(w, err)
		return
	}
	defer res.Body.Close()

	w.Header().Set("Content-Type", sanitizeContentType(res.ContentType))
	w.Header().Set("Cache-Control", "private, max-age=86400")
	if res.ContentLength > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(res.ContentLength, 10))
	}
	w.WriteHeader(http.StatusOK)
	// LimitReader is a backstop in case Content-Length was absent/under-reported.
	_, _ = io.Copy(w, io.LimitReader(res.Body, maxMediaBytes))
}

// sanitizeContentType only lets image/* and video/* through; anything else
// (e.g. an unexpected text/html) becomes octet-stream so the proxy can't be
// coerced into serving active content.
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

// guard enforces a session and that the proxy is configured; it writes the
// error response and returns false when either check fails.
func (h *Handlers) guard(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := auth.ClaimsFromContext(r.Context()); !ok {
		writeAPIError(w, http.StatusUnauthorized, proto.APIError{
			Code: proto.ErrCodeUnauthorized, Message: "no session",
		})
		return false
	}
	if !h.svc.Enabled() {
		writeAPIError(w, http.StatusServiceUnavailable, proto.APIError{
			Code: proto.ErrCodeInternal, Message: "gif proxy not configured",
		})
		return false
	}
	return true
}

func parseLimit(raw string) int {
	if raw == "" {
		return defaultLimit
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return defaultLimit
	}
	return n // bounds enforced in the service
}

func writeGifs(w http.ResponseWriter, results []GifResult) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(gifResponse{Data: results})
}

func writeAPIError(w http.ResponseWriter, status int, e proto.APIError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(e)
}

// writeUpstreamError logs the underlying cause (which may name the provider) but
// only returns an opaque 502 to the client.
func writeUpstreamError(w http.ResponseWriter, err error) {
	log.Printf("gif: upstream error: %v", err)
	writeAPIError(w, http.StatusBadGateway, proto.APIError{
		Code: proto.ErrCodeInternal, Message: "gif upstream error",
	})
}
