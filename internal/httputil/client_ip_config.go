package httputil

import "net/netip"

// ClientIPConfig tells ClientIPResolver which forwarded headers to believe.
//
// TrustedProxies are the peers whose X-Real-IP is honoured (in production the
// Caddy container on the private compose network, which OVERWRITES X-Real-IP
// with its own peer address, so a client can't inject one through it).
//
// OriginSecret, when non-empty, is the value CloudFront attaches to every
// origin request as the OriginSecretHeader custom origin header. Only a request
// carrying it — i.e. one that really came through CloudFront — may name the
// viewer via CloudFront-Viewer-Address; anyone can hit the origin directly and
// send that header themselves. Unset → the CloudFront header is ignored and
// clearnet requests are keyed by X-Real-IP (the CloudFront edge address).
type ClientIPConfig struct {
	TrustedProxies     []netip.Prefix
	OriginSecretHeader string
	OriginSecret       string
}
