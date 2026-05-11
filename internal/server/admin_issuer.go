package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/venkatkrishna07/rift/internal/store"
)


// AdminSecretIssuer provisions tunnel tokens via a bearer-secret protected
// HTTP endpoint. It is the v1 TokenIssuer implementation.
//
// Endpoint: POST /_admin/tokens?name=<name>[&ttl=24h]
// Header:   Authorization: Bearer <secret>
// Response: {"name":"<name>","token":"rift_...","ttl":"24h0m0s"}
//
// Access is restricted to loopback addresses only.
// Requests are rate-limited to 5 per minute per IP to prevent brute-force.
type AdminSecretIssuer struct {
	secret            string
	ts                store.TokenStore
	defaultTTL        time.Duration // 0 = no expiry
	log               *zap.Logger
	rl                *perIPLimiter
	revokes           *RevokeRegistry // wired by Server.SetTokenIssuer; nil disables DELETE
	authRL            *rateLimiter    // shared per-IP auth-failure tracker; nil disables IP block
	trustProxyHeaders bool            // wired by Server.SetTokenIssuer from ServerConfig
}

// SetRevokes installs the registry used to fire revoke callbacks on
// DELETE /_admin/tokens/:name. Server.SetTokenIssuer calls this automatically
// for *AdminSecretIssuer values.
func (a *AdminSecretIssuer) SetRevokes(r *RevokeRegistry) { a.revokes = r }

// SetAuthRL installs the per-IP auth-failure tracker. Repeated bad bearers
// now escalate to the same block that QUIC auth failures trigger, so a
// loopback-spoofing attacker cannot brute-force forever.
func (a *AdminSecretIssuer) SetAuthRL(rl *rateLimiter) { a.authRL = rl }

// SetTrustProxyHeaders configures whether X-Forwarded-For / X-Real-IP on the
// admin endpoint is tolerated. Defaults to false; rift terminates TLS itself
// in the documented deployment shape.
func (a *AdminSecretIssuer) SetTrustProxyHeaders(trust bool) { a.trustProxyHeaders = trust }

// NewAdminSecretIssuer returns a new AdminSecretIssuer.
// defaultTTL is applied to every token unless overridden by the ?ttl= query param; 0 = no expiry.
func NewAdminSecretIssuer(secret string, ts store.TokenStore, defaultTTL time.Duration, log *zap.Logger) *AdminSecretIssuer {
	return &AdminSecretIssuer{
		secret:     secret,
		ts:         ts,
		defaultTTL: defaultTTL,
		log:        log,
		// 5 req/min per IP (one token every 12s), burst 5; evict idle entries after 1h.
		rl: newPerIPLimiter(rate.Every(12*time.Second), 5, time.Hour),
	}
}

// Match returns true for issue (POST /_admin/tokens) and revoke
// (DELETE /_admin/tokens/:name) requests.
func (a *AdminSecretIssuer) Match(r *http.Request) bool {
	if r.Method == http.MethodPost && r.URL.Path == "/_admin/tokens" {
		return true
	}
	if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/_admin/tokens/") {
		return true
	}
	return false
}

// ServeHTTP gates by IP allowlist + rate limit + bearer secret, then
// dispatches POST → handleIssue, DELETE → handleRevoke.
func (a *AdminSecretIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r.RemoteAddr)

	// Detect that rift is sitting behind an HTTP reverse proxy. The admin
	// endpoint's loopback check trusts r.RemoteAddr only — a proxy would
	// hand us 127.0.0.1 for every visitor, opening the endpoint to the
	// world. Refuse rather than misinterpret X-Forwarded-For. Operators
	// who genuinely run rift behind a proxy must terminate the admin
	// listener separately.
	if !a.trustProxyHeaders && !proxyTrusted() && (r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "") {
		a.log.Warn("admin endpoint refused — proxy headers detected",
			zap.String("ip", ip),
			zap.String("xff", r.Header.Get("X-Forwarded-For")),
		)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if !isAdminAllowedIP(ip) {
		a.log.Warn("admin endpoint access denied — IP not allowed", zap.String("ip", ip))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if a.authRL != nil && a.authRL.IsBlocked(ip) {
		a.log.Warn("admin endpoint blocked — IP previously over auth-failure threshold", zap.String("ip", ip))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if !a.rl.Allow(ip) {
		a.log.Warn("admin endpoint rate limited", zap.String("ip", ip))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// Hash both sides to fixed-length digests so the constant-time compare is
	// genuinely constant-time regardless of bearer length (prevents secret-
	// length leakage via early-exit on length mismatch in subtle.ConstantTimeCompare).
	bearerHash := sha256.Sum256([]byte(bearer))
	secretHash := sha256.Sum256([]byte(a.secret))
	if subtle.ConstantTimeCompare(bearerHash[:], secretHash[:]) != 1 {
		blocked := false
		if a.authRL != nil {
			blocked = a.authRL.RecordFailure(ip)
		}
		a.log.Warn("admin endpoint auth failed",
			zap.String("ip", ip),
			zap.Bool("now_blocked", blocked),
		)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodPost:
		a.handleIssue(w, r)
	case http.MethodDelete:
		a.handleRevoke(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *AdminSecretIssuer) handleIssue(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" || len(name) > 256 {
		http.Error(w, "name must be 1–256 characters", http.StatusBadRequest)
		return
	}

	ttl := a.defaultTTL
	if ttlStr := r.URL.Query().Get("ttl"); ttlStr != "" {
		d, err := time.ParseDuration(ttlStr)
		if err != nil {
			http.Error(w, "invalid ttl: "+err.Error(), http.StatusBadRequest)
			return
		}
		ttl = d
	}

	tok, err := store.GenerateToken()
	if err != nil {
		a.log.Error("generate token", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := a.ts.Add(r.Context(), name, tok, ttl); err != nil {
		a.log.Error("save token", zap.String("name", name), zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	a.log.Info("token provisioned", zap.String("name", name), zap.Duration("ttl", ttl))
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(struct {
		Name  string `json:"name"`
		Token string `json:"token"`
		TTL   string `json:"ttl,omitempty"`
	}{Name: name, Token: tok, TTL: func() string {
		if ttl == 0 {
			return ""
		}
		return ttl.String()
	}()}); err != nil {
		// Token is already stored — log enough context for the operator to retrieve it.
		a.log.Error("failed to write token response; token was stored under name",
			zap.String("name", name),
			zap.Error(err),
		)
	}
}

func (a *AdminSecretIssuer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/_admin/tokens/")
	if name == "" || strings.Contains(name, "/") || len(name) > 256 {
		http.Error(w, "name must be 1–256 characters and contain no slashes", http.StatusBadRequest)
		return
	}

	deleted, err := a.ts.Delete(r.Context(), name)
	if err != nil {
		a.log.Error("delete token", zap.String("name", name), zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	killed := 0
	if a.revokes != nil {
		killed = a.revokes.Revoke(name)
	}

	if !deleted && killed == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	a.log.Info("token revoked",
		zap.String("name", name),
		zap.Bool("deleted", deleted),
		zap.Int("killed", killed),
	)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Name    string `json:"name"`
		Deleted bool   `json:"deleted"`
		Killed  int    `json:"killed"`
	}{Name: name, Deleted: deleted, Killed: killed})
}

// isAdminAllowedIP returns true if ip is a loopback address.
func isAdminAllowedIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// proxyTrusted reports whether the operator has opted in to trusting reverse
// proxy headers. The default is false; admin endpoint refuses requests
// carrying X-Forwarded-For so it cannot be fooled into trusting an
// attacker that reached it through a proxy that terminates TLS upstream.
func proxyTrusted() bool {
	return os.Getenv("RIFT_TRUST_PROXY_HEADERS") == "yes"
}
