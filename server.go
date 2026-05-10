package rift

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/venkatkrishna07/rift/internal/server"
)

// Server is a running rift tunnel server. Construct with NewServer, run with
// Run, and stop with Shutdown.
//
// A Server is single-use: after Shutdown it must not be reused. Construct a
// fresh Server for each lifecycle.
//
// All exported methods (Run, Shutdown, Addr) are safe for concurrent use
// from multiple goroutines. The typical pattern is to call Run from one
// goroutine and Shutdown from a signal handler.
type Server struct {
	inner *server.Server
}

// NewServer constructs a tunnel server.
//
// Required:
//   - cfg.Domain
//   - cfg.ListenAddr
//   - WithTLSConfig in prod mode (cfg.Dev=false)
//
// Defaults:
//   - When cfg.Dev=true and WithTLSConfig is omitted, a self-signed wildcard
//     cert for cfg.Domain is generated automatically.
//   - When WithLogger is omitted, NopLogger is used.
//
// Returns an error for misconfiguration; never panics.
func NewServer(cfg ServerConfig, opts ...ServerOption) (*Server, error) {
	if cfg.Domain == "" {
		return nil, errors.New("rift: ServerConfig.Domain is required")
	}
	if cfg.ListenAddr == "" {
		return nil, errors.New("rift: ServerConfig.ListenAddr is required")
	}

	o := serverOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	if o.logger == nil {
		o.logger = NopLogger()
	}

	if o.tlsCfg == nil {
		if !cfg.Dev {
			return nil, errors.New("rift: WithTLSConfig is required when ServerConfig.Dev is false")
		}
		tlsCfg, err := DevTLSConfig(cfg.Domain)
		if err != nil {
			return nil, err
		}
		o.tlsCfg = tlsCfg
	}

	inner := server.New(cfg.toInternal(), o.tokenStore, o.tlsCfg, o.acmeHandler, zapFromLogger(o.logger))
	if o.tokenIssuer != nil {
		inner.SetTokenIssuer(o.tokenIssuer)
	}
	return &Server{inner: inner}, nil
}

// Run starts the listeners and blocks until ctx is cancelled or a fatal error
// occurs.
func (s *Server) Run(ctx context.Context) error { return s.inner.Run(ctx) }

// Shutdown cancels the running supervisor context and waits for Run to
// return. Returns ctx.Err() if the supplied context expires first.
//
// A Server is single-use: do not call Run again after Shutdown. Construct a
// fresh Server for each lifecycle. Shutdown is safe to call before Run (no-op,
// returns nil) and safe to call multiple times.
func (s *Server) Shutdown(ctx context.Context) error { return s.inner.Shutdown(ctx) }

// Addr returns the bound UDP listener address, or nil before Run binds it.
// Safe to call concurrently.
func (s *Server) Addr() net.Addr { return s.inner.Addr() }

// DevTLSConfig returns a self-signed wildcard cert for *.domain.
// Development use only.
func DevTLSConfig(domain string) (*tls.Config, error) {
	return server.DevTLSConfig(domain)
}

// ProdTLSConfig returns a Let's Encrypt-backed *tls.Config and an HTTP handler
// for HTTP-01 challenges. Mount the returned handler on port 80 (or whatever
// you set as ServerConfig.ACMEAddr).
//
// log receives ACME issuance attempts (debug) and renewal failures (warn).
// Pass nil or NopLogger() for silence.
func ProdTLSConfig(domain, cacheDir string, log Logger) (*tls.Config, http.Handler) {
	return server.ProdTLSConfig(domain, cacheDir, zapFromLogger(log))
}

// NewAdminSecretIssuer returns a TokenIssuer that handles
// POST /_admin/tokens with a bearer-secret header. Access is restricted to
// loopback source addresses; non-loopback callers receive 403.
//
// Inject it into a server with the WithTokenIssuer option.
func NewAdminSecretIssuer(secret string, ts TokenStore, defaultTTL time.Duration, log Logger) TokenIssuer {
	return server.NewAdminSecretIssuer(secret, ts, defaultTTL, zapFromLogger(log))
}
