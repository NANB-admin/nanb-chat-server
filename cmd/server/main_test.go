package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"
)

// Outside dev mode a missing signing key must fail closed, so a misconfigured
// prod deploy refuses to boot instead of minting an ephemeral key that
// invalidates every session on restart.
func TestLoadOrGenerateJWTKey_MissingKeyFailsClosedOutsideDevMode(t *testing.T) {
	_, err := loadOrGenerateJWTKey("", false)
	if !errors.Is(err, errMissingJWTKeyProd) {
		t.Fatalf("want errMissingJWTKeyProd, got %v", err)
	}
}

// In dev mode the ephemeral-key convenience is preserved.
func TestLoadOrGenerateJWTKey_MissingKeyGeneratesInDevMode(t *testing.T) {
	priv, err := loadOrGenerateJWTKey("", true)
	if err != nil {
		t.Fatalf("dev mode should generate a key: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("generated key size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

// A configured key is decoded regardless of dev mode.
func TestLoadOrGenerateJWTKey_DecodesConfiguredKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(priv)

	got, err := loadOrGenerateJWTKey(b64, false)
	if err != nil {
		t.Fatalf("a valid configured key must load: %v", err)
	}
	if !bytes.Equal(got, priv) {
		t.Fatalf("loaded key does not match the configured one")
	}
}

func TestLoadOrGenerateJWTKey_RejectsWrongLengthKey(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("too-short"))
	_, err := loadOrGenerateJWTKey(b64, false)
	if !errors.Is(err, errInvalidJWTKey) {
		t.Fatalf("want errInvalidJWTKey, got %v", err)
	}
}

// The server must bound whole-request reads/writes and idle connections, not
// just the header phase, so a trickling client cannot pin a connection forever.
func TestNewServer_SetsReadWriteAndIdleTimeouts(t *testing.T) {
	srv := newServer(":0", http.NotFoundHandler())
	if srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("timeouts must all be set, got read=%v write=%v idle=%v",
			srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}

// Keep-alive must outlive CloudFront's origin keep-alive (<=60s) so the edge
// closes idle pooled connections rather than racing this server's close.
func TestNewServer_IdleTimeoutExceedsCDNKeepAlive(t *testing.T) {
	srv := newServer(":0", http.NotFoundHandler())
	if srv.IdleTimeout <= 60*time.Second {
		t.Fatalf("IdleTimeout = %v, want > 60s", srv.IdleTimeout)
	}
}
