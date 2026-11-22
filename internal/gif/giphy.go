package gif

import "strconv"

// This file is the Giphy provider adapter: the upstream request specifics
// (path, params) and the Giphy response DTOs, plus normalization into the
// neutral []GifResult. To swap GIF providers, replace this file — service.go
// and handlers.go are provider-agnostic (they only speak GifResult).

// Giphy v1 endpoints, relative to the base URL (https://api.giphy.com/v1/gifs).
const (
	giphySearchPath   = "/search"
	giphyTrendingPath = "/trending"
)

const (
	// giphyRating keeps overtly adult content out of a general chat surface.
	giphyRating = "pg-13"
	// giphyBundle is Giphy's recommended rendition set for messaging (fewer,
	// smaller renditions per result).
	giphyBundle = "messaging_non_clips"
)

// giphyResponse is the subset of Giphy's JSON we consume.
type giphyResponse struct {
	Data []giphyResult `json:"data"`
}

type giphyResult struct {
	ID     string                    `json:"id"`
	Images map[string]giphyRendition `json:"images"`
}

// giphyRendition — Giphy sends width/height as strings.
type giphyRendition struct {
	URL    string `json:"url"`
	Width  string `json:"width"`
	Height string `json:"height"`
}

// normalizeGiphy maps a Giphy response into the neutral []GifResult. Entries
// missing an id or a usable preview/send rendition are dropped (the client
// would filter them anyway).
func normalizeGiphy(r giphyResponse) []GifResult {
	out := make([]GifResult, 0, len(r.Data))
	for _, it := range r.Data {
		// Preview: prefer a downsampled animated rendition to save bandwidth.
		preview := firstRenditionURL(it.Images,
			"fixed_width_downsampled", "fixed_width", "downsized", "original")
		// Send: prefer a downsized rendition (~<2 MB) to bound the encrypted upload.
		send := firstRenditionURL(it.Images,
			"downsized", "downsized_medium", "fixed_width", "original")
		if it.ID == "" || preview == "" || send == "" {
			continue
		}
		w, h := giphyDims(it.Images)
		out = append(out, GifResult{
			ID:         it.ID,
			PreviewURL: preview,
			SendURL:    send,
			Width:      w,
			Height:     h,
		})
	}
	return out
}

// firstRenditionURL returns the URL of the first present, non-empty rendition
// among keys, in preference order.
func firstRenditionURL(m map[string]giphyRendition, keys ...string) string {
	for _, k := range keys {
		if r, ok := m[k]; ok && r.URL != "" {
			return r.URL
		}
	}
	return ""
}

// giphyDims reads dimensions from fixed_width, falling back to original.
func giphyDims(m map[string]giphyRendition) (float64, float64) {
	for _, k := range []string{"fixed_width", "original"} {
		if r, ok := m[k]; ok {
			w, h := parseDim(r.Width), parseDim(r.Height)
			if w > 0 && h > 0 {
				return w, h
			}
		}
	}
	return 0, 0
}

func parseDim(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return f
}
