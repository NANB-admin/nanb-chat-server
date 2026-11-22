package httputil

import (
	"net/http"
	"time"
)

// ExtendDeadlines returns a middleware that pushes THIS request's connection
// read and write deadlines out to now+d, overriding the server-wide
// ReadTimeout/WriteTimeout (http.Server applies those to every request, which
// is right for small JSON calls but would cut off a 100 MB media upload or a
// streamed download over a slow Tor circuit).
//
// It uses http.ResponseController, which unwraps middleware response-writer
// wrappers. If the writer (or a test recorder) does not support deadlines the
// error is ignored: the request simply keeps the server default.
func ExtendDeadlines(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			deadline := time.Now().Add(d)
			_ = rc.SetReadDeadline(deadline)
			_ = rc.SetWriteDeadline(deadline)
			next.ServeHTTP(w, r)
		})
	}
}
