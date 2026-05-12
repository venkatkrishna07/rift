package rift

import "net/http"

// TokenIssuer mounts an HTTP route that provisions tokens.
//
// Match decides whether ServeHTTP should handle a request. The server calls
// Match before its tunnel-routing logic; if Match returns true the request
// is dispatched to ServeHTTP and tunnel routing is skipped.
//
// Wire an issuer into a server with the WithTokenIssuer option.
// Implementations must be safe for concurrent use.
//
// rift ships an AdminSecretIssuer that protects POST /_admin/tokens with a
// bearer secret. The interface is intentionally minimal so callers can swap
// in custom flows, for example:
//
//   - an OIDC verifier that mints a tunnel token after validating a JWT;
//   - an mTLS-cert mapper that derives a token from the client certificate;
//   - a webhook-backed issuer that delegates auth to an external service.
//
// Implementations that mutate the server's TokenStore should still call
// TokenStore.Add (or an equivalent atomic write) so revoke wiring continues
// to work.
type TokenIssuer interface {
	Match(r *http.Request) bool
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}
