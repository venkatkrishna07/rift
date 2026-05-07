package rift

import (
	"crypto/tls"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/server"
)

// Server is a running rift tunnel server.
type Server = server.Server

// NewServer constructs a tunnel server.
//
//   - cfg.Dev=true allows ts to be nil (token auth disabled).
//   - tlsCfg is required and must be non-nil; obtain it from DevTLSConfig or
//     ProdTLSConfig (or supply your own pre-provisioned cert). Run panics if
//     tlsCfg is nil.
//   - acmeHandler may be nil; when non-nil it is served on cfg.ACMEAddr
//     for HTTP-01 ACME challenges.
//   - log is required (use zap.NewNop() if you don't want logging).
//
// Call (*Server).Run(ctx) to start. Run blocks until ctx is cancelled.
func NewServer(
	cfg ServerConfig,
	ts TokenStore,
	tlsCfg *tls.Config,
	acmeHandler http.Handler,
	log *zap.Logger,
) *Server {
	return server.New(cfg, ts, tlsCfg, acmeHandler, log)
}

// DevTLSConfig returns a self-signed wildcard cert for *.domain.
// Development use only.
func DevTLSConfig(domain string) (*tls.Config, error) {
	return server.DevTLSConfig(domain)
}

// ProdTLSConfig returns a Let's Encrypt-backed *tls.Config and an HTTP handler
// for HTTP-01 challenges. Mount the returned handler on port 80 (or whatever
// you set as ServerConfig.ACMEAddr).
func ProdTLSConfig(domain, cacheDir string) (*tls.Config, http.Handler) {
	return server.ProdTLSConfig(domain, cacheDir)
}

// NewAdminSecretIssuer returns a TokenIssuer that handles
// POST /_admin/tokens with a bearer-secret header.
//
// Wire it into the server by setting ServerConfig.AdminSecret (the server
// instantiates the issuer internally based on that value). This standalone
// constructor is exposed for callers who want to mount the issuer on their
// own HTTP mux outside the embedded server.
func NewAdminSecretIssuer(secret string, ts TokenStore, defaultTTL time.Duration, log *zap.Logger) TokenIssuer {
	return server.NewAdminSecretIssuer(secret, ts, defaultTTL, log)
}
