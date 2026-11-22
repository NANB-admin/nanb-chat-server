package gif_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/nanb/nanb-server/internal/auth"
	"github.com/nanb/nanb-server/internal/crypto"
	"github.com/nanb/nanb-server/internal/gif"
)

func authedReq(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, http.NoBody)
	ctx := auth.InjectClaimsForTest(req.Context(), crypto.JWTClaims{
		AccountID: "acct", DeviceID: "dev",
	})
	return req.WithContext(ctx)
}

func TestHandlers_Trending_ReturnsNormalizedData(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"x","images":` +
			`{"downsized":{"url":"https://media.giphy.com/x.gif","width":"12","height":"8"}}}]}`))
	}))
	defer upstream.Close()

	h := gif.NewHandlers(gif.NewService(gif.ServiceDeps{APIKey: "k", BaseURL: upstream.URL}))
	w := httptest.NewRecorder()
	h.GetTrending(w, authedReq("GET", "/gifs/trending?limit=5"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %s", ct)
	}
	var got struct {
		Data []gif.GifResult `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v — body %s", err, w.Body.String())
	}
	if len(got.Data) != 1 || got.Data[0].ID != "x" {
		t.Fatalf("data = %+v, want one id=x", got.Data)
	}
	if got.Data[0].PreviewURL != "https://media.giphy.com/x.gif" {
		t.Fatalf("previewURL = %s", got.Data[0].PreviewURL)
	}
}

func TestHandlers_Unauthenticated_401(t *testing.T) {
	h := gif.NewHandlers(gif.NewService(gif.ServiceDeps{APIKey: "k"}))
	w := httptest.NewRecorder()
	// No injected claims → unauthenticated.
	h.GetTrending(w, httptest.NewRequest("GET", "/gifs/trending", http.NoBody))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestHandlers_Disabled_503(t *testing.T) {
	h := gif.NewHandlers(gif.NewService(gif.ServiceDeps{APIKey: ""}))
	w := httptest.NewRecorder()
	h.GetSearch(w, authedReq("GET", "/gifs/search?q=x"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestHandlers_Media_MissingURL_400(t *testing.T) {
	h := gif.NewHandlers(gif.NewService(gif.ServiceDeps{APIKey: "k"}))
	w := httptest.NewRecorder()
	h.GetMedia(w, authedReq("GET", "/gifs/media"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandlers_Media_DisallowedHost_400(t *testing.T) {
	h := gif.NewHandlers(gif.NewService(gif.ServiceDeps{APIKey: "k"}))
	w := httptest.NewRecorder()
	bad := "/gifs/media?url=" + url.QueryEscape("https://evil.example.com/x.gif")
	h.GetMedia(w, authedReq("GET", bad))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandlers_Media_StreamsAndSanitizesType(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/gif")
		_, _ = w.Write([]byte("GIFDATA"))
	}))
	defer upstream.Close()

	h := gif.NewHandlers(gif.NewService(gif.ServiceDeps{
		APIKey: "k", HTTPClient: upstream.Client(), AllowMediaHost: func(string) bool { return true },
	}))
	w := httptest.NewRecorder()
	path := "/gifs/media?url=" + url.QueryEscape(upstream.URL+"/x.gif")
	h.GetMedia(w, authedReq("GET", path))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/gif" {
		t.Fatalf("content-type = %s", ct)
	}
	if w.Body.String() != "GIFDATA" {
		t.Fatalf("body = %s", w.Body.String())
	}
}
