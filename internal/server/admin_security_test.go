package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func adminPostReq(t *testing.T, secret, name, remoteAddr string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/_admin/tokens?name="+name, nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	r.RemoteAddr = remoteAddr
	return r
}

func TestAdmin_RejectsXForwardedFor(t *testing.T) {
	const secret = "topsecret"
	iss := NewAdminSecretIssuer(secret, newMemTokenStore(), time.Hour, zap.NewNop())

	r := adminPostReq(t, secret, "alice", "127.0.0.1:1234")
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	w := httptest.NewRecorder()
	iss.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 when XFF present", w.Code)
	}
}

func TestAdmin_RejectsXRealIP(t *testing.T) {
	const secret = "topsecret"
	iss := NewAdminSecretIssuer(secret, newMemTokenStore(), time.Hour, zap.NewNop())

	r := adminPostReq(t, secret, "alice", "127.0.0.1:1234")
	r.Header.Set("X-Real-IP", "203.0.113.7")
	w := httptest.NewRecorder()
	iss.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 when X-Real-IP present", w.Code)
	}
}

func TestAdmin_TrustsProxyHeadersWhenEnvSet(t *testing.T) {
	t.Setenv("RIFT_TRUST_PROXY_HEADERS", "yes")
	const secret = "topsecret"
	iss := NewAdminSecretIssuer(secret, newMemTokenStore(), time.Hour, zap.NewNop())

	r := adminPostReq(t, secret, "alice", "127.0.0.1:1234")
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	w := httptest.NewRecorder()
	iss.ServeHTTP(w, r)

	if w.Code == http.StatusForbidden {
		t.Errorf("status = %d — should not 403 when RIFT_TRUST_PROXY_HEADERS=yes; body=%s", w.Code, w.Body.String())
	}
}

func TestAdmin_BadBearerEscalatesToIPBlock(t *testing.T) {
	const secret = "topsecret"
	iss := NewAdminSecretIssuer(secret, newMemTokenStore(), time.Hour, zap.NewNop())
	rl := newRateLimiter()
	iss.SetAuthRL(rl)

	for i := 0; i < maxAuthFailures+1; i++ {
		w := httptest.NewRecorder()
		iss.ServeHTTP(w, adminPostReq(t, "wrong", "alice", "127.0.0.1:9999"))
	}

	if !rl.IsBlocked("127.0.0.1") {
		t.Error("expected 127.0.0.1 to be blocked after repeated bad-bearer attempts")
	}

	// Now a request with the CORRECT secret from the same IP should be
	// rejected because the rateLimiter has it blocked.
	w := httptest.NewRecorder()
	iss.ServeHTTP(w, adminPostReq(t, secret, "alice", "127.0.0.1:9999"))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d after IP block, want 403; body=%s", w.Code, w.Body.String())
	}
}
