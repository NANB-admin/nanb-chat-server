package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
)

type APNSConfig struct {
	KeyID    string
	TeamID   string
	BundleID string
	AuthKey  *ecdsa.PrivateKey
	// Production switches APNs endpoint to api.push.apple.com (default is sandbox).
	Production bool
}

type APNSClient struct {
	cli      *apns2.Client
	bundleID string
}

func NewAPNSClient(cfg APNSConfig) *APNSClient {
	return &APNSClient{cli: NewAPNSTokenClient(cfg), bundleID: cfg.BundleID}
}

// NewAPNSTokenClient builds the JWT-authenticated APNs transport. Exported so
// the alert sender ([NewAPNSClient]) and the VoIP sender ([NewAPNSVoipClient])
// share ONE client — same auth key and connection pool; they differ only in
// topic and push type. Apple rate-limits new APNs JWTs, so minting a second
// client (and a second token) for the same key is wasteful at best.
func NewAPNSTokenClient(cfg APNSConfig) *apns2.Client {
	tok := &token.Token{
		AuthKey: cfg.AuthKey,
		KeyID:   cfg.KeyID,
		TeamID:  cfg.TeamID,
	}
	c := apns2.NewTokenClient(tok)
	if cfg.Production {
		return c.Production()
	}
	return c.Development()
}

func (a *APNSClient) SendWakeup(_ context.Context, t Token, extra map[string]string) error {
	p := payload.NewPayload().ContentAvailable().MutableContent()
	for k, v := range extra {
		p = p.Custom(k, v)
	}
	n := &apns2.Notification{
		DeviceToken: t.Token,
		Topic:       a.bundleID,
		Payload:     p,
	}
	resp, err := a.cli.Push(n)
	if err != nil {
		return err
	}
	if !resp.Sent() {
		// A rejection naming a dead device token is wrapped so the caller prunes
		// it; every other reason stays a plain (retryable) error.
		if apnsReasonIsDeadToken(resp.Reason) {
			return fmt.Errorf("apns push rejected: %s (%s): %w", resp.Reason, resp.ApnsID, ErrTokenInvalid)
		}
		return fmt.Errorf("apns push rejected: %s (%s)", resp.Reason, resp.ApnsID)
	}
	return nil
}

// LoadAPNSAuthKeyFromFile reads a `.p8` private key file and parses it.
func LoadAPNSAuthKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read apns key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("apns key: invalid PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse apns key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apns key: not ECDSA")
	}
	return ecKey, nil
}
