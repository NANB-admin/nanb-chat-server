package httputil_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nanb/nanb-server/internal/httputil"
)

const webOrigin = "https://chat.example.org"

// next records whether the wrapped handler ran, so tests can assert that a
// preflight is answered by the middleware and a normal request is passed on.
type nextProbe struct{ called bool }

func (p *nextProbe) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		p.called = true
		w.WriteHeader(http.StatusOK)
	})
}

func doCORS(allowed []string, method, origin string, extra map[string]string) (*httptest.ResponseRecorder, *nextProbe) {
	probe := &nextProbe{}
	h := httputil.CORS(allowed)(probe.handler())
	req := httptest.NewRequest(method, "/devices/pending/abc", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, probe
}

func TestCORS_AllowedOrigin_IsEchoedBack(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodGet, webOrigin, nil)

	assert.Equal(t, webOrigin, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_AllowedOrigin_VariesOnOrigin(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodGet, webOrigin, nil)

	assert.Contains(t, rec.Header().Values("Vary"), "Origin")
}

func TestCORS_AllowedOrigin_RequestStillReachesHandler(t *testing.T) {
	_, probe := doCORS([]string{webOrigin}, http.MethodGet, webOrigin, nil)

	assert.True(t, probe.called)
}

func TestCORS_UnlistedOrigin_GetsNoAllowOriginHeader(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodGet, "https://evil.example", nil)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_OriginWithSamePrefixButDifferentHost_IsNotAllowed(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodGet, webOrigin+".evil.example", nil)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_NoOriginHeader_AddsNoCORSHeaders(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodGet, "", nil)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_NeverAllowsCredentials(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodGet, webOrigin, nil)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORS_NeverUsesWildcardOrigin(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodGet, webOrigin, nil)

	assert.NotEqual(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
}

func preflightHeaders() map[string]string {
	return map[string]string{
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "authorization,content-type",
	}
}

func TestCORS_Preflight_FromAllowedOrigin_Returns204(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodOptions, webOrigin, preflightHeaders())

	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestCORS_Preflight_IsAnsweredWithoutReachingHandler(t *testing.T) {
	_, probe := doCORS([]string{webOrigin}, http.MethodOptions, webOrigin, preflightHeaders())

	assert.False(t, probe.called)
}

func TestCORS_Preflight_AdvertisesAuthorizationHeader(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodOptions, webOrigin, preflightHeaders())

	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "Authorization")
}

func TestCORS_Preflight_AdvertisesRestMethods(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodOptions, webOrigin, preflightHeaders())

	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "DELETE")
}

func TestCORS_Preflight_AllowsCachingTheAnswer(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodOptions, webOrigin, preflightHeaders())

	assert.NotEmpty(t, rec.Header().Get("Access-Control-Max-Age"))
}

func TestCORS_Preflight_FromUnlistedOrigin_IsNotApproved(t *testing.T) {
	rec, _ := doCORS([]string{webOrigin}, http.MethodOptions, "https://evil.example", preflightHeaders())

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_EmptyAllowList_LeavesRequestsUntouched(t *testing.T) {
	rec, probe := doCORS(nil, http.MethodGet, webOrigin, nil)

	assert.True(t, probe.called)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_EmptyAllowList_DoesNotAnswerPreflight(t *testing.T) {
	_, probe := doCORS(nil, http.MethodOptions, webOrigin, preflightHeaders())

	assert.True(t, probe.called)
}
