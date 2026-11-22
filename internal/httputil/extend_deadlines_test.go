package httputil_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nanb/nanb-server/internal/httputil"
)

// newTimedServer starts a real server with tight Read/Write timeouts so the
// tests exercise the actual net/http deadline behaviour.
func newTimedServer(t *testing.T, h http.Handler, timeout time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ReadTimeout = timeout
	srv.Config.WriteTimeout = timeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// pausedReader yields "hello" only after pausing, longer than the server timeout.
type pausedReader struct {
	pause time.Duration
	done  bool
}

func (p *pausedReader) Read(b []byte) (int, error) {
	if p.done {
		return 0, io.EOF
	}
	time.Sleep(p.pause)
	p.done = true
	return copy(b, "hello"), nil
}

func TestExtendDeadlines_SlowUploadSurvivesServerReadTimeout(t *testing.T) {
	var got string
	h := httputil.ExtendDeadlines(5 * time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	srv := newTimedServer(t, h, 150*time.Millisecond)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, &pausedReader{pause: 400 * time.Millisecond})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if got != "hello" {
		t.Fatalf("handler read %q, want the full slow body", got)
	}
}

func TestExtendDeadlines_WithoutItSlowUploadIsCutOff(t *testing.T) {
	var got string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
	})
	srv := newTimedServer(t, h, 150*time.Millisecond)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, &pausedReader{pause: 400 * time.Millisecond})
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	if got == "hello" {
		t.Fatal("expected the server ReadTimeout to cut off the slow body")
	}
}

func TestExtendDeadlines_SlowDownloadSurvivesServerWriteTimeout(t *testing.T) {
	h := httputil.ExtendDeadlines(5 * time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "part1")
		w.(http.Flusher).Flush()
		time.Sleep(400 * time.Millisecond)
		_, _ = io.WriteString(w, "part2")
	}))
	srv := newTimedServer(t, h, 150*time.Millisecond)

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || string(b) != "part1part2" {
		t.Fatalf("got %q, %v; want the full streamed body", b, err)
	}
}

func TestExtendDeadlines_UnsupportedWriterStillServes(t *testing.T) {
	h := httputil.ExtendDeadlines(time.Second)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "ok" {
		t.Fatalf("handler did not run, body %q", rec.Body.String())
	}
}
// variant 1 22670
// variant 2 30914
// variant 3 22703
// variant 4 14736
// variant 5 31080
