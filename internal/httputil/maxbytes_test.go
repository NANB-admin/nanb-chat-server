package httputil_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nanb/nanb-server/internal/httputil"
)

// An oversized body must error out of the read BEFORE the whole payload is
// buffered — the handler never sees more than the cap's worth of bytes.
func TestMaxBytes_RejectsOversizedBodyBeforeFullRead(t *testing.T) {
	const cap = 16
	var readErr error
	var readN int
	h := httputil.MaxBytes(cap)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		readN = len(b)
		readErr = err
	}))

	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(make([]byte, cap*100)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if readErr == nil {
		t.Fatalf("expected an error when reading past the %d-byte cap", cap)
	}
	if readN > cap {
		t.Fatalf("read %d bytes, must not exceed the cap %d before erroring", readN, cap)
	}
}

// A JSON decode of an oversized body fails rather than fully materialising it.
func TestMaxBytes_OversizedJSONDecodeFails(t *testing.T) {
	const cap = 32
	var decodeErr error
	h := httputil.MaxBytes(cap)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var v map[string]string
		decodeErr = json.NewDecoder(r.Body).Decode(&v)
	}))

	big, _ := json.Marshal(map[string]string{"k": string(make([]byte, cap*10))})
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(big))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if decodeErr == nil {
		t.Fatalf("expected decode of an oversized body to fail")
	}
}

func TestMaxBytes_AllowsBodyWithinCap(t *testing.T) {
	const cap = 1024
	var got []byte
	h := httputil.MaxBytes(cap)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
	}))

	payload := []byte("small enough")
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if string(got) != string(payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}
