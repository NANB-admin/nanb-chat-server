package httputil

import (
	"context"
	"net/http"
)

// onionCtxKey marks a request that arrived on the Tor onion listener.
type onionCtxKey struct{}

// MarkOnion wraps the handler served on the onion listener (NANB_TOR_LISTEN_ADDR)
// so everything downstream can tell onion traffic apart. Every onion request
// reaches the server from the local Tor daemon, so its peer address says
// nothing about the client, and any forwarded-for header on it is whatever the
// (anonymous) client chose to send — neither may be used as a client identity.
func MarkOnion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), onionCtxKey{}, true)))
	})
}

// IsOnion reports whether the request was served by a MarkOnion-wrapped handler.
func IsOnion(ctx context.Context) bool {
	v, _ := ctx.Value(onionCtxKey{}).(bool)
	return v
}
