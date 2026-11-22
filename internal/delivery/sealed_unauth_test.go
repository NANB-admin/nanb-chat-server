package delivery_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/delivery"
	"github.com/nanb/nanb-server/internal/proto"
)

// mockVerifier stands in for the identity service's AccessKeyVerifier.
type mockVerifier struct {
	fn func(ctx context.Context, recipientDeviceID string, key []byte) (string, bool, error)
}

func (m *mockVerifier) VerifyAccessKey(ctx context.Context, recipientDeviceID string, key []byte) (string, bool, error) {
	return m.fn(ctx, recipientDeviceID, key)
}

func sealedBody(t *testing.T, key []byte) []byte {
	t.Helper()
	b, _ := json.Marshal(proto.SubmitMessageRequest{
		EnvelopeType:      proto.EnvelopeTypeSealed,
		RecipientDeviceID: "dev-r",
		Ciphertext:        []byte("opaque-sealed-blob"),
		AccessKey:         key,
	})
	return b
}

func TestPostSealed_HappyPath_NoSenderAuthoritativeRecipient(t *testing.T) {
	var gotSender, gotRecipientAcct string
	var gotAccessKey []byte
	svc := &mockSvc{
		submit: func(_ context.Context, sender string, r proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			gotSender = sender
			gotRecipientAcct = r.RecipientAccountID
			gotAccessKey = r.AccessKey
			return proto.SubmitMessageResponse{EnvelopeID: "env-s", ServerTS: time.Unix(1, 0).UTC()}, nil
		},
	}
	h := delivery.NewHandlers(svc, nil)
	h.SetAccessKeyVerifier(&mockVerifier{
		fn: func(_ context.Context, dev string, key []byte) (string, bool, error) {
			assert.Equal(t, "dev-r", dev)
			return "acct-r", true, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/messages/sealed", bytes.NewReader(sealedBody(t, []byte("the-uak"))))
	rec := httptest.NewRecorder()
	h.PostSealedMessage(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	// The sender is the zero-UUID sentinel — the server never learns who sent it.
	assert.Equal(t, proto.SealedSentinelUUID, gotSender)
	// The recipient account is the server-resolved one, not anything the client set.
	assert.Equal(t, "acct-r", gotRecipientAcct)
	// The UAK is scrubbed before the envelope is stored.
	assert.Nil(t, gotAccessKey)
}

func TestPostSealed_WrongKey_Returns403_NoSubmit(t *testing.T) {
	submitted := false
	svc := &mockSvc{
		submit: func(context.Context, string, proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			submitted = true
			return proto.SubmitMessageResponse{}, nil
		},
	}
	h := delivery.NewHandlers(svc, nil)
	h.SetAccessKeyVerifier(&mockVerifier{
		fn: func(context.Context, string, []byte) (string, bool, error) { return "acct-r", false, nil },
	})

	req := httptest.NewRequest(http.MethodPost, "/messages/sealed", bytes.NewReader(sealedBody(t, []byte("wrong"))))
	rec := httptest.NewRecorder()
	h.PostSealedMessage(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, submitted, "an unauthorized sealed deposit must not be stored")
}

func TestPostSealed_NoVerifier_Returns503(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, nil) // verifier never set
	req := httptest.NewRequest(http.MethodPost, "/messages/sealed", bytes.NewReader(sealedBody(t, []byte("k"))))
	rec := httptest.NewRecorder()
	h.PostSealedMessage(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestPostSealed_MissingFields_Returns400(t *testing.T) {
	h := delivery.NewHandlers(&mockSvc{}, nil)
	h.SetAccessKeyVerifier(&mockVerifier{
		fn: func(context.Context, string, []byte) (string, bool, error) { return "acct-r", true, nil },
	})

	cases := map[string]proto.SubmitMessageRequest{
		"no access key": {EnvelopeType: proto.EnvelopeTypeSealed, RecipientDeviceID: "dev-r", Ciphertext: []byte("x")},
		"not sealed":    {EnvelopeType: proto.EnvelopeTypeMLSApplication, RecipientDeviceID: "dev-r", Ciphertext: []byte("x"), AccessKey: []byte("k")},
		"no recipient":  {EnvelopeType: proto.EnvelopeTypeSealed, Ciphertext: []byte("x"), AccessKey: []byte("k")},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(r)
			req := httptest.NewRequest(http.MethodPost, "/messages/sealed", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			h.PostSealedMessage(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

// sealedHandlers wires a handler whose verifier accepts only goodKey for any
// device, and counts how many envelopes reached the service.
func sealedHandlers(goodKey string, submitted *int) *delivery.Handlers {
	svc := &mockSvc{
		submit: func(context.Context, string, proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
			*submitted++
			return proto.SubmitMessageResponse{EnvelopeID: "e", ServerTS: time.Unix(1, 0).UTC()}, nil
		},
	}
	h := delivery.NewHandlers(svc, nil)
	h.SetAccessKeyVerifier(&mockVerifier{
		fn: func(_ context.Context, _ string, key []byte) (string, bool, error) {
			return "acct-r", string(key) == goodKey, nil
		},
	})
	return h
}

// postSealedFrom posts a sealed send for device dev with key, from peer.
func postSealedFrom(h *delivery.Handlers, peer, dev, key string) int {
	b, _ := json.Marshal(proto.SubmitMessageRequest{
		EnvelopeType:      proto.EnvelopeTypeSealed,
		RecipientDeviceID: dev,
		Ciphertext:        []byte("opaque-sealed-blob"),
		AccessKey:         []byte(key),
	})
	req := httptest.NewRequest(http.MethodPost, "/messages/sealed", bytes.NewReader(b))
	req.RemoteAddr = peer
	rec := httptest.NewRecorder()
	h.PostSealedMessage(rec, req)
	return rec.Code
}

// The owner's rule: valid sealed sends are never rate limited, however many.
func TestPostSealed_ValidSendsAreNeverRateLimited(t *testing.T) {
	var submitted int
	h := sealedHandlers("uak", &submitted)

	for i := 0; i < 500; i++ {
		postSealedFrom(h, "203.0.113.1:1", "dev-r", "uak")
	}

	assert.Equal(t, 500, submitted)
}

func TestPostSealed_RepeatedWrongKeys_AreThrottled(t *testing.T) {
	var submitted int
	h := sealedHandlers("uak", &submitted)

	codes := map[int]int{}
	for i := 0; i < 40; i++ {
		codes[postSealedFrom(h, "203.0.113.1:1", "dev-r", "wrong")]++
	}

	assert.Greater(t, codes[http.StatusTooManyRequests], 0)
}

func TestPostSealed_ThrottledSourceIsRefusedBeforeVerification(t *testing.T) {
	verifications := 0
	h := delivery.NewHandlers(&mockSvc{}, nil)
	h.SetAccessKeyVerifier(&mockVerifier{
		fn: func(context.Context, string, []byte) (string, bool, error) {
			verifications++
			return "acct-r", false, nil
		},
	})

	for i := 0; i < 100; i++ {
		postSealedFrom(h, "203.0.113.1:1", "dev-r", "wrong")
	}

	assert.Less(t, verifications, 100, "once throttled, attempts must stop costing lookups")
}

func TestPostSealed_OneSourcesFailuresDoNotThrottleAnother(t *testing.T) {
	var submitted int
	h := sealedHandlers("uak", &submitted)
	for i := 0; i < 100; i++ {
		postSealedFrom(h, "203.0.113.1:1", "dev-r", "wrong")
	}

	assert.Equal(t, http.StatusCreated, postSealedFrom(h, "198.51.100.2:1", "dev-r", "uak"))
}

func TestPostSealed_FailuresAgainstOneDeviceDoNotThrottleAnotherDevice(t *testing.T) {
	var submitted int
	h := sealedHandlers("uak", &submitted)
	for i := 0; i < 25; i++ {
		postSealedFrom(h, "203.0.113.1:1", "dev-victim", "wrong")
	}

	assert.Equal(t, http.StatusCreated, postSealedFrom(h, "203.0.113.1:1", "dev-other", "uak"))
}

func TestPostSealed_OverlongRecipientDeviceID_Returns400(t *testing.T) {
	var submitted int
	h := sealedHandlers("uak", &submitted)

	code := postSealedFrom(h, "203.0.113.1:1", strings.Repeat("d", 65), "uak")

	assert.Equal(t, http.StatusBadRequest, code)
}
