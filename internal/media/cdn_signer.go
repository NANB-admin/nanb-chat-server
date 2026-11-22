package media

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/cloudfront/sign"
)

// CDNSigner produces a CloudFront signed URL for a stored object so downloads
// hit the edge cache (close to the viewer) instead of crossing to the S3
// origin in us-west-1 every time. It is OPTIONAL on the Service: when nil,
// GetDownload falls back to an S3 presigned GET, so an unconfigured or
// misconfigured CDN never breaks media — it just loses the edge cache.
type CDNSigner interface {
	// SignedURL returns a CloudFront URL for objectKey that is valid until
	// expiresAt (canned policy). objectKey is the same S3 key used for the
	// origin, e.g. "media/<id>".
	SignedURL(objectKey string, expiresAt time.Time) (string, error)
}

// CloudFrontConfig configures a cloudFrontSigner. KeyID is the CloudFront
// *public key* id (the Key-Pair-Id that rides in the signed URL) — when the
// distribution trusts a key group, that is the public key's id, not an
// account-level key-pair id. PrivateKeyPEM is the matching RSA private key.
type CloudFrontConfig struct {
	Domain        string // distribution domain, e.g. d3t1szqy3t1no7.cloudfront.net (scheme optional)
	KeyID         string // CloudFront public key id, e.g. KO23REV95KJIC
	PrivateKeyPEM string // PEM-encoded RSA private key (PKCS#8 or PKCS#1)
}

type cloudFrontSigner struct {
	baseURL string
	signer  *sign.URLSigner
}

// NewCloudFrontSigner builds a signer from config. It accepts either a PKCS#8
// ("BEGIN PRIVATE KEY") or PKCS#1 ("BEGIN RSA PRIVATE KEY") PEM — CloudFront's
// own console hands out PKCS#8, openssl genrsa hands out PKCS#1.
func NewCloudFrontSigner(cfg CloudFrontConfig) (CDNSigner, error) {
	if cfg.Domain == "" || cfg.KeyID == "" || cfg.PrivateKeyPEM == "" {
		return nil, fmt.Errorf("cloudfront signer: domain, key id, and private key are all required")
	}

	priv, err := loadSigner(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("cloudfront signer: load private key: %w", err)
	}

	domain := strings.TrimSuffix(cfg.Domain, "/")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")

	return &cloudFrontSigner{
		baseURL: "https://" + domain,
		signer:  sign.NewURLSigner(cfg.KeyID, priv),
	}, nil
}

func loadSigner(pem string) (crypto.Signer, error) {
	// Try PKCS#8 first (what CloudFront's key-pair UI emits), then PKCS#1.
	if s, err := sign.LoadPEMPrivKeyPKCS8AsSigner(strings.NewReader(pem)); err == nil {
		return s, nil
	}
	rsaKey, err := sign.LoadPEMPrivKey(strings.NewReader(pem))
	if err != nil {
		return nil, err
	}
	return rsaKey, nil
}

func (c *cloudFrontSigner) SignedURL(objectKey string, expiresAt time.Time) (string, error) {
	raw := c.baseURL + "/" + strings.TrimPrefix(objectKey, "/")
	return c.signer.Sign(raw, expiresAt)
}
