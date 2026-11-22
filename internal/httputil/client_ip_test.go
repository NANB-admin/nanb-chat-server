package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/httputil"
)

const (
	originSecretHeader = "X-Origin-Verify"
	originSecret       = "s3cret"
	caddyPeer          = "172.18.0.5:41000" // the reverse proxy on the compose network
)

func newResolver(secret string) *httputil.ClientIPResolver {
	return httputil.NewClientIPResolver(httputil.ClientIPConfig{
		TrustedProxies:     []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")},
		OriginSecretHeader: originSecretHeader,
		OriginSecret:       secret,
	})
}

func requestFrom(peer string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/sessions/challenge", nil)
	r.RemoteAddr = peer
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// resolvedKey runs r through the resolver's middleware and returns the key a
// downstream handler sees via httputil.ClientKey.
func resolvedKey(res *httputil.ClientIPResolver, r *http.Request) string {
	var got string
	res.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		got = httputil.ClientKey(req)
	})).ServeHTTP(httptest.NewRecorder(), r)
	return got
}

func TestClientIP_UntrustedPeer_IsKeyedByItsOwnAddress(t *testing.T) {
	r := requestFrom("203.0.113.7:5555", map[string]string{"X-Real-IP": "198.51.100.1"})

	assert.Equal(t, "203.0.113.7", resolvedKey(newResolver(originSecret), r))
}

func TestClientIP_TrustedProxy_UsesXRealIP(t *testing.T) {
	r := requestFrom(caddyPeer, map[string]string{"X-Real-IP": "198.51.100.1"})

	assert.Equal(t, "198.51.100.1", resolvedKey(newResolver(originSecret), r))
}

func TestClientIP_TrustedProxy_WithoutHeader_FallsBackToPeer(t *testing.T) {
	r := requestFrom(caddyPeer, nil)

	assert.Equal(t, "172.18.0.5", resolvedKey(newResolver(originSecret), r))
}

func TestClientIP_CloudFrontViewerAddress_UsedWithOriginSecret(t *testing.T) {
	r := requestFrom(caddyPeer, map[string]string{
		"X-Real-IP":                 "130.176.0.1", // the CloudFront edge
		"CloudFront-Viewer-Address": "198.51.100.9:46532",
		originSecretHeader:          originSecret,
	})

	assert.Equal(t, "198.51.100.9", resolvedKey(newResolver(originSecret), r))
}

func TestClientIP_CloudFrontViewerAddress_IgnoredWithoutOriginSecret(t *testing.T) {
	r := requestFrom(caddyPeer, map[string]string{
		"X-Real-IP":                 "203.0.113.50",
		"CloudFront-Viewer-Address": "198.51.100.9:46532", // spoofed by a direct-to-origin client
	})

	assert.Equal(t, "203.0.113.50", resolvedKey(newResolver(originSecret), r))
}

func TestClientIP_CloudFrontViewerAddress_IgnoredWithWrongOriginSecret(t *testing.T) {
	r := requestFrom(caddyPeer, map[string]string{
		"X-Real-IP":                 "203.0.113.50",
		"CloudFront-Viewer-Address": "198.51.100.9:46532",
		originSecretHeader:          "guess",
	})

	assert.Equal(t, "203.0.113.50", resolvedKey(newResolver(originSecret), r))
}

func TestClientIP_CloudFrontViewerAddress_IgnoredWhenNoSecretConfigured(t *testing.T) {
	r := requestFrom(caddyPeer, map[string]string{
		"X-Real-IP":                 "203.0.113.50",
		"CloudFront-Viewer-Address": "198.51.100.9:46532",
		originSecretHeader:          "",
	})

	assert.Equal(t, "203.0.113.50", resolvedKey(newResolver(""), r))
}

func TestClientIP_CloudFrontIPv6ViewerAddress_DropsThePort(t *testing.T) {
	r := requestFrom(caddyPeer, map[string]string{
		"CloudFront-Viewer-Address": "2001:db8:1:2:3:4:5:6:443",
		originSecretHeader:          originSecret,
	})

	assert.Equal(t, "2001:db8:1:2::/64", resolvedKey(newResolver(originSecret), r))
}

func TestClientIP_IPv6Clients_AreGroupedByPrefix64(t *testing.T) {
	a := resolvedKey(newResolver(""), requestFrom("[2001:db8:aa:bb::1]:443", nil))
	b := resolvedKey(newResolver(""), requestFrom("[2001:db8:aa:bb::ffff]:443", nil))

	assert.Equal(t, a, b)
}

func TestClientIP_OnionRequest_SharesTheOnionKey(t *testing.T) {
	r := requestFrom("172.18.0.9:5000", map[string]string{"X-Real-IP": "198.51.100.1"})
	var got string
	h := httputil.MarkOnion(newResolver(originSecret).Middleware(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		got = httputil.ClientKey(req)
	})))

	h.ServeHTTP(httptest.NewRecorder(), r)

	assert.Equal(t, httputil.OnionClientKey, got)
}

func TestClientKey_WithoutMiddleware_UsesPeerOnly(t *testing.T) {
	r := requestFrom("203.0.113.7:5555", map[string]string{"X-Real-IP": "198.51.100.1"})

	assert.Equal(t, "203.0.113.7", httputil.ClientKey(r))
}
