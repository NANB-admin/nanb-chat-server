package main

import (
	"log"
	"net/netip"
	"os"

	"github.com/nanb/nanb-server/internal/httputil"
)

// defaultTrustedProxies: loopback and the private ranges. In the compose
// deployment the server's :8080 is reachable only from Caddy on the private
// compose network (no published host port), so "private peer" == "Caddy".
const defaultTrustedProxies = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"

// originVerifyHeader is the custom origin header CloudFront is configured to
// add (with NANB_ORIGIN_VERIFY_SECRET as its value) to every request it
// forwards to the origin hostname.
const originVerifyHeader = "X-Origin-Verify"

// clientIPConfigFromEnv reads how the real client IP is recovered:
//
//   - NANB_TRUSTED_PROXY_CIDRS: peers whose X-Real-IP is believed (default:
//     loopback + private ranges). Caddy sets X-Real-IP to its own peer,
//     overwriting anything the client sent.
//   - NANB_ORIGIN_VERIFY_SECRET: when set, a request carrying it in
//     X-Origin-Verify came through CloudFront, so its CloudFront-Viewer-Address
//     (the real viewer) is believed. Unset → clients behind CloudFront are keyed
//     by the edge address Caddy saw. Onion traffic never consults either.
func clientIPConfigFromEnv() httputil.ClientIPConfig {
	var prefixes []netip.Prefix
	for _, raw := range splitCSV(envOrDefault("NANB_TRUSTED_PROXY_CIDRS", defaultTrustedProxies)) {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			log.Printf("WARN: NANB_TRUSTED_PROXY_CIDRS: ignoring %q: %v", raw, err)
			continue
		}
		prefixes = append(prefixes, p)
	}
	secret := os.Getenv("NANB_ORIGIN_VERIFY_SECRET")
	if secret == "" {
		log.Println("client-ip: NANB_ORIGIN_VERIFY_SECRET unset; CloudFront clients are rate-limited by edge address")
	}
	return httputil.ClientIPConfig{
		TrustedProxies:     prefixes,
		OriginSecretHeader: originVerifyHeader,
		OriginSecret:       secret,
	}
}
