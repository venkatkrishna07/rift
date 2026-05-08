package rift

import (
	"crypto/tls"
	"net/http"
)

// ServerOption configures a Server constructed by NewServer.
type ServerOption func(*serverOptions)

type serverOptions struct {
	tlsCfg      *tls.Config
	tokenStore  TokenStore
	tokenIssuer TokenIssuer
	acmeHandler http.Handler
	logger      Logger
}

// WithTLSConfig supplies the TLS config used by the QUIC and HTTPS listeners.
// Required in prod mode; auto-derived from DevTLSConfig when ServerConfig.Dev
// is true and this option is omitted.
func WithTLSConfig(c *tls.Config) ServerOption {
	return func(o *serverOptions) { o.tlsCfg = c }
}

// WithTokenStore injects the persistent token store the server uses to
// validate auth tokens. Required outside dev mode.
func WithTokenStore(ts TokenStore) ServerOption {
	return func(o *serverOptions) { o.tokenStore = ts }
}

// WithTokenIssuer mounts a TokenIssuer that receives matching HTTP requests
// before tunnel routing. Use NewAdminSecretIssuer or your own implementation.
func WithTokenIssuer(iss TokenIssuer) ServerOption {
	return func(o *serverOptions) { o.tokenIssuer = iss }
}

// WithACMEHandler attaches an HTTP handler served on ServerConfig.ACMEAddr
// for HTTP-01 ACME challenges. Pair with ProdTLSConfig.
func WithACMEHandler(h http.Handler) ServerOption {
	return func(o *serverOptions) { o.acmeHandler = h }
}

// WithLogger plugs in the Logger used by the server. Defaults to NopLogger().
func WithLogger(l Logger) ServerOption {
	return func(o *serverOptions) { o.logger = l }
}

// ClientOption configures a Client constructed by NewClient.
type ClientOption func(*clientOptions)

type clientOptions struct {
	tokenStore TokenStore
	logger     Logger
}

// WithClientTokenStore caches the server-issued token on disk so subsequent
// Connect calls reuse it without manual provisioning.
func WithClientTokenStore(ts TokenStore) ClientOption {
	return func(o *clientOptions) { o.tokenStore = ts }
}

// WithClientLogger plugs in the Logger used by the client. Defaults to
// NopLogger().
func WithClientLogger(l Logger) ClientOption {
	return func(o *clientOptions) { o.logger = l }
}
