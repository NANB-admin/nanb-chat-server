package apierr_test

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/nanb/nanb-server/internal/apierr"
	"github.com/nanb/nanb-server/internal/proto"
)

const leakyDBText = `ERROR: duplicate key value violates unique constraint "accounts_pkey" (SQLSTATE 23505)`

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestInternal_KeepsInternalErrorCode(t *testing.T) {
	got := apierr.Internal(errors.New(leakyDBText))
	if got.Code != proto.ErrCodeInternal {
		t.Fatalf("code = %q, want %q", got.Code, proto.ErrCodeInternal)
	}
}

func TestInternal_MessageDoesNotLeakRawError(t *testing.T) {
	got := apierr.Internal(errors.New(leakyDBText))
	if strings.Contains(got.Message, "accounts_pkey") || got.Message != apierr.InternalMessage {
		t.Fatalf("message leaks internals: %q", got.Message)
	}
}

func TestInternal_LogsRealErrorServerSide(t *testing.T) {
	buf := captureLog(t)
	apierr.Internal(errors.New(leakyDBText))
	if !strings.Contains(buf.String(), "accounts_pkey") {
		t.Fatalf("real error not logged: %q", buf.String())
	}
}

func TestInternal_LogNamesCallingFunction(t *testing.T) {
	buf := captureLog(t)
	apierr.Internal(errors.New("boom"))
	if !strings.Contains(buf.String(), "TestInternal_LogNamesCallingFunction") {
		t.Fatalf("log should name the caller: %q", buf.String())
	}
}
