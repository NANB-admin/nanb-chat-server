// Package gif proxies a GIF content provider (Giphy) so the API key lives only
// on the server and never ships inside the mobile binary. Clients call
// /gifs/search and /gifs/trending (authenticated); the server appends the key,
// calls the provider, and returns a normalized, provider-neutral JSON shape
// (see GifResult) — so the client parser is independent of the upstream schema
// and the provider can be swapped by replacing only the adapter file.
//
// It also proxies the chosen GIF's *bytes* (/gifs/media) so the download
// happens from the server's IP, not the user's — keeping the user's address and
// which-GIF-they-picked off the provider. That proxy is strictly limited to
// provider hosts (SSRF guard): it will never fetch an arbitrary URL.
package gif

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Service holds the provider API key and performs the upstream calls.
type Service struct {
	apiKey    string
	baseURL   string
	rating    string
	bundle    string
	http      *http.Client
	allowHost func(host string) bool
}

type ServiceDeps struct {
	APIKey string
	// BaseURL defaults to Giphy's REST endpoint; overridable in tests.
	BaseURL string
	// HTTPClient defaults to a client with a 20s timeout + a redirect guard.
	HTTPClient *http.Client
	// AllowMediaHost restricts which hosts the media proxy (and redirects) may
	// reach — the SSRF guard. Defaults to giphy.com + *.giphy.com. Overridable
	// in tests (e.g. to allow an httptest host).
	AllowMediaHost func(host string) bool
}

func NewService(d ServiceDeps) *Service {
	base := d.BaseURL
	if base == "" {
		base = "https://api.giphy.com/v1/gifs"
	}
	allow := d.AllowMediaHost
	if allow == nil {
		allow = isGiphyHost
	}
	hc := d.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: 20 * time.Second,
			// Never follow a redirect off an allowed host (defense in depth for
			// both the JSON calls and the media proxy).
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("gif: too many redirects")
				}
				if !allow(req.URL.Hostname()) {
					return fmt.Errorf("gif: redirect to disallowed host %q", req.URL.Hostname())
				}
				return nil
			},
		}
	}
	return &Service{
		apiKey:    d.APIKey,
		baseURL:   base,
		rating:    giphyRating,
		bundle:    giphyBundle,
		http:      hc,
		allowHost: allow,
	}
}

// Enabled reports whether a provider key is configured. When false the handlers
// return 503 rather than calling upstream.
func (s *Service) Enabled() bool { return s.apiKey != "" }

const (
	maxLimit      = 50       // Giphy's per-page cap
	maxBody       = 4 << 20  // 4 MiB cap on the upstream JSON we read
	maxMediaBytes = 30 << 20 // 30 MiB cap on a proxied GIF
)

// ErrMediaHostNotAllowed is returned when /gifs/media is asked to fetch a URL
// that is not an https provider host. Callers map it to 400.
var ErrMediaHostNotAllowed = errors.New("gif: media host not allowed")

// Trending returns normalized trending GIFs.
func (s *Service) Trending(ctx context.Context, limit int) ([]GifResult, error) {
	return s.fetch(ctx, giphyTrendingPath, url.Values{
		"limit": {strconv.Itoa(clampLimit(limit))},
	})
}

// Search returns normalized GIFs for query q.
func (s *Service) Search(ctx context.Context, q string, limit int) ([]GifResult, error) {
	return s.fetch(ctx, giphySearchPath, url.Values{
		"q":     {q},
		"limit": {strconv.Itoa(clampLimit(limit))},
	})
}

func (s *Service) fetch(ctx context.Context, path string, params url.Values) ([]GifResult, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("gif: not configured")
	}
	params.Set("api_key", s.apiKey)
	params.Set("rating", s.rating)
	params.Set("bundle", s.bundle)

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, s.baseURL+path+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gif: upstream status %d", resp.StatusCode)
	}
	var gr giphyResponse
	if err := json.Unmarshal(body, &gr); err != nil {
		return nil, fmt.Errorf("gif: decode upstream: %w", err)
	}
	return normalizeGiphy(gr), nil
}

// MediaResult is a streamable upstream media response. The caller MUST Close Body.
type MediaResult struct {
	ContentType   string
	ContentLength int64 // -1 when unknown
	Body          io.ReadCloser
}

// FetchMedia fetches a GIF's bytes from the provider's CDN, but ONLY if rawURL
// is an https URL on an allowed provider host (SSRF guard). It returns a
// streamable body the caller copies to the client; the caller is responsible
// for capping the copy at maxMediaBytes.
func (s *Service) FetchMedia(ctx context.Context, rawURL string) (*MediaResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || !s.allowHost(u.Hostname()) {
		return nil, ErrMediaHostNotAllowed
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("gif: media upstream status %d", resp.StatusCode)
	}
	if resp.ContentLength > maxMediaBytes {
		resp.Body.Close()
		return nil, fmt.Errorf("gif: media too large (%d bytes)", resp.ContentLength)
	}
	return &MediaResult{
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		Body:          resp.Body,
	}, nil
}

// isGiphyHost matches giphy.com and any subdomain (media*.giphy.com, i.giphy.com…).
func isGiphyHost(host string) bool {
	host = strings.ToLower(host)
	return host == "giphy.com" || strings.HasSuffix(host, ".giphy.com")
}

func clampLimit(n int) int {
	if n < 1 {
		return 1
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}
