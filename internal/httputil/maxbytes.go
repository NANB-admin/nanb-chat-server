// Package httputil holds small, reusable HTTP middleware shared across the
// server's handler packages.
package httputil

import "net/http"

// MaxBytes returns a middleware that caps a request body at n bytes via
// http.MaxBytesReader. A handler that reads past the cap gets an error from the
// very next Read — so an oversized body is rejected BEFORE it is fully buffered
// or decoded — and the server responds 413 if the handler then writes.
//
// Apply a cap SIZED PER ENDPOINT (small for token/session/control bodies,
// larger for message and key-package submits). Do NOT stack two MaxBytes on one
// route: the inner wrapper reads THROUGH the outer one, so the smaller cap
// always wins and an intended larger override would be silently defeated.
func MaxBytes(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}
