package httputil_test

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/httputil"
)

// captureLog runs one request through AccessLog and returns what it logged.
func captureLog(t *testing.T, method, target string) string {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	r := chi.NewRouter()
	r.Use(httputil.AccessLog)
	r.Get("/accounts/{username}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = "203.0.113.7:54321"
	r.ServeHTTP(httptest.NewRecorder(), req)
	return buf.String()
}

func TestAccessLog_LogsTheRoutePattern(t *testing.T) {
	assert.Contains(t, captureLog(t, http.MethodGet, "/accounts/alice"), "/accounts/{username}")
}

func TestAccessLog_DoesNotLogTheUsernameInThePath(t *testing.T) {
	assert.NotContains(t, captureLog(t, http.MethodGet, "/accounts/alice"), "alice")
}

func TestAccessLog_DoesNotLogTheCallersAddress(t *testing.T) {
	assert.NotContains(t, captureLog(t, http.MethodGet, "/accounts/alice"), "203.0.113.7")
}

func TestAccessLog_LogsTheStatus(t *testing.T) {
	assert.Contains(t, captureLog(t, http.MethodGet, "/accounts/alice"), "-> 404")
}

func TestAccessLog_AnUnmatchedRouteIsLoggedWithoutItsPath(t *testing.T) {
	out := captureLog(t, http.MethodGet, "/secret-bob/lookup")

	assert.NotContains(t, out, "secret-bob")
}
