package httputil

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/netip"
	"strings"
)

// OnionClientKey is the client key every onion request shares: the server
// can't tell Tor clients apart, so they get ONE budget of their own — separate
// from every clearnet key, so clearnet abuse can never spend it.
const OnionClientKey = "onion"

const (
	cloudFrontViewerAddressHeader = "CloudFront-Viewer-Address"
	realIPHeader                  = "X-Real-IP"
	// ipv6ClientPrefixBits groups IPv6 clients by /64: one subscriber usually
	// holds a whole /64, so keying on the full address would let a single
	// client rotate through billions of "different" keys.
	ipv6ClientPrefixBits = 64
)

// clientKeyCtxKey carries the resolved client key on the request context.
type clientKeyCtxKey struct{}

// ClientIPResolver derives the rate-limit identity ("client key") of a request:
// OnionClientKey for onion traffic, otherwise the client IP (IPv6 collapsed to
// its /64). Forwarded headers are believed only from a trusted proxy — see
// ClientIPConfig.
type ClientIPResolver struct {
	cfg ClientIPConfig
}

// NewClientIPResolver builds a resolver for cfg.
func NewClientIPResolver(cfg ClientIPConfig) *ClientIPResolver {
	return &ClientIPResolver{cfg: cfg}
}

// Middleware resolves the client key once and stores it on the request
// context. It MUST run before anything that rewrites RemoteAddr (chi's
// middleware.RealIP believes any client-sent X-Real-IP / True-Client-IP), so it
// is installed at the very top of the router.
func (c *ClientIPResolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), clientKeyCtxKey{}, c.Key(r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Key returns r's client key. See ClientIPResolver.
func (c *ClientIPResolver) Key(r *http.Request) string {
	if IsOnion(r.Context()) {
		return OnionClientKey
	}
	peer, ok := parseHostPort(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}
	if !c.trusted(peer) {
		return keyForAddr(peer)
	}
	if c.fromCloudFront(r) {
		if viewer, ok := parseViewerAddress(r.Header.Get(cloudFrontViewerAddressHeader)); ok {
			return keyForAddr(viewer)
		}
	}
	if real, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(realIPHeader))); err == nil {
		return keyForAddr(real)
	}
	return keyForAddr(peer)
}

// ClientKey returns the key Middleware stored for r. Without the middleware
// (unit tests, or a route mounted elsewhere) it falls back to the peer address
// alone, never to a forwarded header.
func ClientKey(r *http.Request) string {
	if k, ok := r.Context().Value(clientKeyCtxKey{}).(string); ok && k != "" {
		return k
	}
	if IsOnion(r.Context()) {
		return OnionClientKey
	}
	if peer, ok := parseHostPort(r.RemoteAddr); ok {
		return keyForAddr(peer)
	}
	return r.RemoteAddr
}

func (c *ClientIPResolver) trusted(peer netip.Addr) bool {
	for _, p := range c.cfg.TrustedProxies {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// fromCloudFront reports whether r carries the CloudFront origin secret.
func (c *ClientIPResolver) fromCloudFront(r *http.Request) bool {
	if c.cfg.OriginSecret == "" || c.cfg.OriginSecretHeader == "" {
		return false
	}
	got := r.Header.Get(c.cfg.OriginSecretHeader)
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.cfg.OriginSecret)) == 1
}

// parseHostPort parses a "host:port" peer address (RemoteAddr form).
func parseHostPort(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// parseViewerAddress parses CloudFront-Viewer-Address, "IP:port" — with an
// IPv6 address NOT bracketed (e.g. "2001:db8::1:443"), so the port is whatever
// follows the last colon.
func parseViewerAddress(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, false
	}
	// Not parseHostPort: a bare "2001:db8::1:443" is ALSO a valid IPv6 address,
	// so a plain-address parse would swallow the port into the address.
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s[:i])
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func keyForAddr(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	if p, err := a.Prefix(ipv6ClientPrefixBits); err == nil {
		return p.String()
	}
	return a.String()
}
