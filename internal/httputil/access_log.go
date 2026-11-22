package httputil

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// AccessLog logs one line per request: method, the matched ROUTE PATTERN,
// status and latency. It deliberately does NOT log the requested URL or the
// caller's address.
//
// chi's stock middleware.Logger writes the real path and RemoteAddr, which put
// `GET /accounts/<username>` next to a client address in the server log: a record
// of who looked up whom. The route pattern (`/accounts/{username}`) says what
// kind of request it was without saying about whom, and with no address there is
// nothing to tie it to a person. Enough to watch errors and latency.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		defer func() {
			log.Printf("%s %s -> %d in %s", r.Method, routePattern(r), ww.Status(), time.Since(start))
		}()
		next.ServeHTTP(ww, r)
	})
}

// routePattern is the matched chi pattern, available once routing has run (so
// call it after the handler). "-" when the request never matched a route.
func routePattern(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if p := rctx.RoutePattern(); p != "" {
			return p
		}
	}
	return "-"
}
