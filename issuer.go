package rift

import "net/http"

// TokenIssuer mounts an HTTP route that provisions tokens.
//
// Match decides whether ServeHTTP should handle a request. The server calls
// Match before its tunnel-routing logic; if Match returns true the request
// is dispatched to ServeHTTP and tunnel routing is skipped.
//
// Wire an issuer into a server with the WithTokenIssuer option (added in a
// later phase). Implementations must be safe for concurrent use.
type TokenIssuer interface {
	Match(r *http.Request) bool
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}
