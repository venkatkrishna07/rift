package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// newTestHTTPHandler builds an httpHandler with the given domain and a
// permissive visitor rate limiter for tests.
func newTestHTTPHandler(t *testing.T, domain string) *httpHandler {
	t.Helper()
	return &httpHandler{
		reg:           NewRegistry(20000, 20100, 0),
		log:           zap.NewNop(),
		maxBodyBytes:  1 << 20,
		streamTimeout: 30 * time.Second,
		visitorRL:     newPerIPLimiter(rate.Limit(1000), 1000, time.Minute),
		domain:        domain,
	}
}

func TestHTTPHandler_RejectsForeignHost(t *testing.T) {
	h := newTestHTTPHandler(t, "tunnel.example.com")

	cases := []struct {
		name    string
		host    string
		want    int
	}{
		{"foreign-domain", "evil.com", http.StatusMisdirectedRequest},
		{"foreign-with-similar-suffix", "tunnel.example.com.evil.com", http.StatusMisdirectedRequest},
		{"sub-of-foreign", "x.evil.com", http.StatusMisdirectedRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tc.host
			req.RemoteAddr = "203.0.113.5:1234"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("host=%s: got %d want %d body=%q", tc.host, rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

func TestHTTPHandler_AllowsLegalHost_404OnMissingTunnel(t *testing.T) {
	// When the host is legal but no tunnel registered, expect 404 (not 421).
	h := newTestHTTPHandler(t, "tunnel.example.com")

	cases := []string{
		"tunnel.example.com",
		"foo.tunnel.example.com",
		"FOO.tunnel.example.com",       // case-insensitive
		"foo.tunnel.example.com:8443",  // port stripped
	}
	for _, host := range cases {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = host
			req.RemoteAddr = "203.0.113.5:1234"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusNotFound {
				t.Fatalf("host=%s: got %d want 404 body=%q", host, rr.Code, rr.Body.String())
			}
		})
	}
}

// fakeIssuer matches every POST /_admin/tokens; tracks if ServeHTTP fired.
type fakeIssuer struct{ served bool }

func (f *fakeIssuer) Match(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == "/_admin/tokens"
}
func (f *fakeIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.served = true
	w.WriteHeader(http.StatusOK)
}

func TestHTTPHandler_HostPinBlocksAdminIssuer(t *testing.T) {
	// Admin issuer dispatch must run BEHIND the host check.
	iss := &fakeIssuer{}
	h := newTestHTTPHandler(t, "tunnel.example.com")
	h.issuer = iss

	req := httptest.NewRequest(http.MethodPost, "/_admin/tokens?name=x", nil)
	req.Host = "evil.com"
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("got %d want 421 body=%q", rr.Code, rr.Body.String())
	}
	if iss.served {
		t.Fatalf("issuer ServeHTTP fired despite foreign Host")
	}
}

func TestHTTPHandler_HostPinAllowsAdminIssuerOnLegalHost(t *testing.T) {
	iss := &fakeIssuer{}
	h := newTestHTTPHandler(t, "tunnel.example.com")
	h.issuer = iss

	req := httptest.NewRequest(http.MethodPost, "/_admin/tokens?name=x", nil)
	req.Host = "tunnel.example.com"
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !iss.served {
		t.Fatalf("issuer ServeHTTP did not fire on legal Host (status=%d body=%q)", rr.Code, rr.Body.String())
	}
}

func TestHTTPHandler_EmptyDomainSkipsHostCheck(t *testing.T) {
	// When domain is unset (e.g. mounted on a different mux for tests), the
	// handler must not 421 — it falls back to the legacy subdomain split.
	h := newTestHTTPHandler(t, "")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "anything.example.com"
	req.RemoteAddr = "203.0.113.5:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("got %d want 404 (no tunnel registered) body=%q", rr.Code, rr.Body.String())
	}
}
