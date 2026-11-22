package gif_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nanb/nanb-server/internal/gif"
)

// A minimal Giphy search payload: one result with a preview + send rendition
// and dimensions on fixed_width.
const giphyBody = `{"data":[{"id":"abc","images":{` +
	`"fixed_width_downsampled":{"url":"https://media.giphy.com/preview.gif","width":"200","height":"150"},` +
	`"fixed_width":{"url":"https://media.giphy.com/fw.gif","width":"200","height":"150"},` +
	`"downsized":{"url":"https://media.giphy.com/send.gif","width":"0","height":"0"}` +
	`}}]}`

func TestService_Search_AddsParamsAndNormalizes(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(giphyBody))
	}))
	defer srv.Close()

	svc := gif.NewService(gif.ServiceDeps{APIKey: "k", BaseURL: srv.URL})
	results, err := svc.Search(context.Background(), "cats", 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if gotPath != "/search" {
		t.Fatalf("path = %s, want /search", gotPath)
	}
	for _, want := range []string{
		"api_key=k", "rating=pg-13", "bundle=messaging_non_clips", "q=cats", "limit=10",
	} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	g := results[0]
	if g.ID != "abc" {
		t.Fatalf("id = %s", g.ID)
	}
	// Preview prefers the downsampled rendition; send prefers downsized.
	if g.PreviewURL != "https://media.giphy.com/preview.gif" {
		t.Fatalf("previewURL = %s", g.PreviewURL)
	}
	if g.SendURL != "https://media.giphy.com/send.gif" {
		t.Fatalf("sendURL = %s", g.SendURL)
	}
	// Dimensions come from fixed_width (strings parsed to numbers).
	if g.Width != 200 || g.Height != 150 {
		t.Fatalf("dims = %vx%v, want 200x150", g.Width, g.Height)
	}
}

func TestService_Normalize_DropsResultsMissingRenditions(t *testing.T) {
	// One good result + one with no usable renditions → only the good one.
	body := `{"data":[` +
		`{"id":"ok","images":{"downsized":{"url":"https://media.giphy.com/a.gif","width":"10","height":"10"}}},` +
		`{"id":"bad","images":{}}` +
		`]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	svc := gif.NewService(gif.ServiceDeps{APIKey: "k", BaseURL: srv.URL})
	results, err := svc.Trending(context.Background(), 10)
	if err != nil {
		t.Fatalf("trending: %v", err)
	}
	if len(results) != 1 || results[0].ID != "ok" {
		t.Fatalf("results = %+v, want only id=ok", results)
	}
}

func TestService_ClampsLimit(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	svc := gif.NewService(gif.ServiceDeps{APIKey: "k", BaseURL: srv.URL})
	if _, err := svc.Trending(context.Background(), 9999); err != nil {
		t.Fatalf("trending: %v", err)
	}
	if !strings.Contains(gotQuery, "limit=50") {
		t.Fatalf("limit not clamped to 50: %s", gotQuery)
	}
}

func TestService_UpstreamNon2xx_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	svc := gif.NewService(gif.ServiceDeps{APIKey: "k", BaseURL: srv.URL})
	if _, err := svc.Trending(context.Background(), 10); err == nil {
		t.Fatal("expected error on non-2xx upstream")
	}
}

func TestService_Disabled(t *testing.T) {
	svc := gif.NewService(gif.ServiceDeps{APIKey: ""})
	if svc.Enabled() {
		t.Fatal("expected disabled with empty key")
	}
	if _, err := svc.Search(context.Background(), "x", 5); err == nil {
		t.Fatal("expected error when disabled")
	}
}

func TestService_FetchMedia_RejectsNonProviderHost(t *testing.T) {
	svc := gif.NewService(gif.ServiceDeps{APIKey: "k"})
	_, err := svc.FetchMedia(context.Background(), "https://evil.example.com/x.gif")
	if !errors.Is(err, gif.ErrMediaHostNotAllowed) {
		t.Fatalf("err = %v, want ErrMediaHostNotAllowed", err)
	}
}

func TestService_FetchMedia_RejectsNonHTTPS(t *testing.T) {
	svc := gif.NewService(gif.ServiceDeps{APIKey: "k"})
	// Host is fine, but http:// must be rejected (no plaintext, and blocks
	// file:// / gopher:// style tricks).
	_, err := svc.FetchMedia(context.Background(), "http://media.giphy.com/x.gif")
	if !errors.Is(err, gif.ErrMediaHostNotAllowed) {
		t.Fatalf("err = %v, want ErrMediaHostNotAllowed", err)
	}
}

func TestService_FetchMedia_StreamsFromAllowedHost(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/gif")
		_, _ = w.Write([]byte("GIF89a-bytes"))
	}))
	defer srv.Close()

	svc := gif.NewService(gif.ServiceDeps{
		APIKey:         "k",
		HTTPClient:     srv.Client(), // trusts the test cert
		AllowMediaHost: func(string) bool { return true },
	})
	res, err := svc.FetchMedia(context.Background(), srv.URL+"/media/x/giphy.gif")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer res.Body.Close()
	if res.ContentType != "image/gif" {
		t.Fatalf("content-type = %s", res.ContentType)
	}
	b, _ := io.ReadAll(res.Body)
	if string(b) != "GIF89a-bytes" {
		t.Fatalf("body = %s", b)
	}
}

func TestService_FetchMedia_RejectsTooLarge(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "999999999") // ~1GB, over the cap
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := gif.NewService(gif.ServiceDeps{
		APIKey: "k", HTTPClient: srv.Client(), AllowMediaHost: func(string) bool { return true },
	})
	if _, err := svc.FetchMedia(context.Background(), srv.URL+"/big.gif"); err == nil {
		t.Fatal("expected error for over-cap Content-Length")
	}
}
