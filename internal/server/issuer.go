package server

import "net/http"

// TokenIssuer handles HTTP routes for token provisioning.
//
// Implementations:
//   - AdminSecretIssuer — bearer-secret protected endpoint (v1)
//   - OAuthIssuer       — provider-based device flow (future)
//
// To add a new issuer: implement this interface and wire it in server.go.
// No changes to httpHandler or tunnel routing are needed.
type TokenIssuer interface {
	// Match returns true if this issuer wants to handle the request.
	// Called before any tunnel routing logic.
	Match(r *http.Request) bool

	// ServeHTTP handles the matched request.
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}
