package gif

// GifResult is the provider-neutral shape returned to clients by /gifs/search
// and /gifs/trending. The client parses exactly these fields and never sees the
// upstream provider's response schema — so swapping providers is a server-only
// change.
//
// PreviewURL/SendURL are upstream CDN URLs the client fetches back through
// /gifs/media (so the CDN never sees the user's IP); the SSRF guard in the
// service restricts which hosts those may point at.
type GifResult struct {
	ID         string  `json:"id"`
	PreviewURL string  `json:"previewUrl"`
	SendURL    string  `json:"sendUrl"`
	Width      float64 `json:"width"`
	Height     float64 `json:"height"`
}

// gifResponse wraps the results under a `data` key. Tightly coupled to
// GifResult (it exists only to shape the JSON envelope), so it lives here.
type gifResponse struct {
	Data []GifResult `json:"data"`
}
