package media_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/media"
	"github.com/nanb/nanb-server/internal/proto"
)

func genPKCS8PEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func genPKCS1PEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

// The real CloudFront signer (PKCS#8, what the AWS console emits) produces a
// canned-policy URL: https://<domain>/<key>?Expires&Signature&Key-Pair-Id.
func TestCloudFrontSigner_SignsCannedURL(t *testing.T) {
	signer, err := media.NewCloudFrontSigner(media.CloudFrontConfig{
		Domain:        "d3t1szqy3t1no7.cloudfront.net",
		KeyID:         "KTESTKEYID",
		PrivateKeyPEM: genPKCS8PEM(t),
	})
	require.NoError(t, err)

	raw, err := signer.SignedURL("media/abc123", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	u, err := url.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "d3t1szqy3t1no7.cloudfront.net", u.Host)
	assert.Equal(t, "/media/abc123", u.Path)
	q := u.Query()
	assert.Equal(t, "KTESTKEYID", q.Get("Key-Pair-Id"))
	assert.NotEmpty(t, q.Get("Expires"))
	assert.NotEmpty(t, q.Get("Signature"))
}

// openssl genrsa hands out PKCS#1; the loader must accept it too.
func TestCloudFrontSigner_AcceptsPKCS1AndStripsScheme(t *testing.T) {
	signer, err := media.NewCloudFrontSigner(media.CloudFrontConfig{
		Domain:        "https://cdn.example.com/",
		KeyID:         "K1",
		PrivateKeyPEM: genPKCS1PEM(t),
	})
	require.NoError(t, err)

	raw, err := signer.SignedURL("media/x", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Contains(t, raw, "https://cdn.example.com/media/x?")
}

func TestNewCloudFrontSigner_RejectsMissingConfig(t *testing.T) {
	_, err := media.NewCloudFrontSigner(media.CloudFrontConfig{Domain: "d.cloudfront.net", KeyID: "K"})
	assert.Error(t, err)
}

func TestNewCloudFrontSigner_RejectsBadPEM(t *testing.T) {
	_, err := media.NewCloudFrontSigner(media.CloudFrontConfig{
		Domain:        "d.cloudfront.net",
		KeyID:         "K",
		PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nnotbase64\n-----END PRIVATE KEY-----\n",
	})
	assert.Error(t, err)
}

// --- GetDownload CDN routing -------------------------------------------------

type fakeCDN struct {
	base string
	err  error
}

func (f *fakeCDN) SignedURL(objectKey string, _ time.Time) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.base + "/" + objectKey + "?cf", nil
}

func newSvcWithCDN(cdn media.CDNSigner) (*media.Service, *media.StoreInMemory, *fakeS3) {
	store := media.NewStoreInMemory()
	s3 := &fakeS3{}
	clock := fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	ids := &seqIDs{values: []string{"m-1"}}
	svc := media.NewService(media.ServiceDeps{
		Store:            store,
		S3:               s3,
		Clock:            clock,
		IDGen:            ids,
		MaxSizeBytes:     100 << 20,
		DefaultRetention: 30 * 24 * time.Hour,
		PresignTTL:       15 * time.Minute,
		CDN:              cdn,
	})
	return svc, store, s3
}

func insertLiveMedia(t *testing.T, store *media.StoreInMemory) {
	t.Helper()
	require.NoError(t, store.Insert(context.Background(), proto.MediaRecord{
		MediaID:    "m-cdn",
		ObjectKey:  "media/m-cdn",
		MimeType:   "image/png",
		SizeBytes:  100,
		UploadedAt: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
		ExpiresAt:  time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC),
	}))
}

func TestGetDownload_UsesCDNWhenConfigured(t *testing.T) {
	svc, store, _ := newSvcWithCDN(&fakeCDN{base: "https://cdn.example.com"})
	insertLiveMedia(t, store)

	resp, err := svc.GetDownload(context.Background(), "acc-caller", "m-cdn")
	require.NoError(t, err)
	assert.Equal(t, "https://cdn.example.com/media/m-cdn?cf", resp.DownloadURL)
	assert.Equal(t, "image/png", resp.MimeType)
	assert.Equal(t, int64(100), resp.SizeBytes)
}

// A CDN signing failure must degrade to the S3 presigned GET, never error out.
func TestGetDownload_FallsBackToS3WhenCDNFails(t *testing.T) {
	svc, store, _ := newSvcWithCDN(&fakeCDN{err: errors.New("sign boom")})
	insertLiveMedia(t, store)

	resp, err := svc.GetDownload(context.Background(), "acc-caller", "m-cdn")
	require.NoError(t, err)
	assert.Contains(t, resp.DownloadURL, "?get", "should fall back to S3 presigned URL")
}
