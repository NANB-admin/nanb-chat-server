package httputil

import (
	"net/http"
	"strings"
)

const (
	corsAllowMethods = "GET, POST, PATCH, DELETE, OPTIONS"
	corsAllowHeaders = "Authorization, Content-Type"
	corsMaxAgeSecs   = "600"
)

// CORS returns middleware that lets a browser client served from one of the
// allowedOrigins call the REST API.
//
// Deliberately narrow:
//   - exact-match origins only (scheme + host + port) — never a wildcard, never
//     a prefix match, so "https://chat.example.org.evil.example" is not allowed;
//   - no Access-Control-Allow-Credentials — the API authenticates with a Bearer
//     header, not cookies, so the browser must never attach ambient credentials;
//   - an unlisted origin simply receives no CORS headers (the browser blocks
//     the response); the request is still served, exactly as before.
//
// An empty allowedOrigins list returns a pass-through, so the feature is OFF
// until NANB_WEB_ORIGINS is configured and existing behaviour is unchanged.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o = strings.TrimSpace(o); o != "" {
			allowed[o] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if _, ok := allowed[origin]; !ok || origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")

			isPreflight := r.Method == http.MethodOptions &&
				r.Header.Get("Access-Control-Request-Method") != ""
			if isPreflight {
				h.Set("Access-Control-Allow-Methods", corsAllowMethods)
				h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
				h.Set("Access-Control-Max-Age", corsMaxAgeSecs)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
