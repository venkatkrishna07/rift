package server

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
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
	secret     string
	ts         store.TokenStore
	defaultTTL time.Duration // 0 = no expiry
	log        *zap.Logger
	rl         *perIPLimiter
}

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

// Match returns true for POST /_admin/tokens requests.
func (a *AdminSecretIssuer) Match(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == "/_admin/tokens"
}

// ServeHTTP validates the bearer secret, generates a token, stores it, and
// returns it as JSON.
func (a *AdminSecretIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r.RemoteAddr)

	// Restrict to loopback only.
	if !isAdminAllowedIP(ip) {
		a.log.Warn("admin endpoint access denied — IP not allowed", zap.String("ip", ip))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Rate limit: 5 req/min per IP.
	if !a.rl.Allow(ip) {
		a.log.Warn("admin endpoint rate limited", zap.String("ip", ip))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// Constant-time comparison prevents timing-based secret enumeration.
	if subtle.ConstantTimeCompare([]byte(bearer), []byte(a.secret)) != 1 {
		a.log.Warn("admin endpoint auth failed", zap.String("ip", ip))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

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

// isAdminAllowedIP returns true if ip is a loopback address.
func isAdminAllowedIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}
