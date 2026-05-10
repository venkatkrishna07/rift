package rift

import "github.com/venkatkrishna07/rift/internal/server"

// ErrSubdomainTaken is returned when registering an HTTP tunnel under a
// subdomain that another active tunnel already claims.
//
// Match with errors.Is on errors returned from server registration paths.
var ErrSubdomainTaken = server.ErrSubdomainTaken

// ErrPortsExhausted is returned when registering a TCP tunnel and no free
// port can be allocated within the server's configured port range.
var ErrPortsExhausted = server.ErrPortsExhausted

// ErrAuthFailed is returned by the client when the server rejects the auth
// frame (missing, malformed, or invalid token), and is the sentinel that
// the server's connection handler wraps around its internal auth-rejection
// errors.
var ErrAuthFailed = server.ErrAuthFailed

// ErrTokenExpired is returned when an authenticated connection is closed
// because its token's expiry time elapsed. Callers can refresh the token
// and reconnect rather than treating this as a hard auth failure.
var ErrTokenExpired = server.ErrTokenExpired

// ErrIPBlocked is returned when the server rejects a connection because
// the source IP exceeded its allowed failed-auth count and is now blocked
// by the rate limiter.
var ErrIPBlocked = server.ErrIPBlocked

// ErrTokenRevoked is returned when an authenticated connection is closed
// because an operator revoked the token via the admin revoke endpoint.
// Distinct from ErrTokenExpired so callers can surface the right action —
// a new token must be provisioned, refreshing the same token will not work.
var ErrTokenRevoked = server.ErrTokenRevoked
