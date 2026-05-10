package server

import "errors"

// ErrAuthFailed indicates the client's auth frame was rejected: missing,
// malformed, or carrying an invalid/unknown token. Wrapped with %w by
// producer sites so callers can match it with errors.Is.
var ErrAuthFailed = errors.New("rift: authentication failed")

// ErrTokenExpired indicates the connection was closed because the token's
// expiry time passed. Distinct from ErrAuthFailed so callers can react
// (e.g. refresh a token) without retry-looping on rejected credentials.
var ErrTokenExpired = errors.New("rift: token expired")

// ErrIPBlocked indicates the source IP was rejected by the per-IP rate
// limiter for excessive failed auth attempts.
var ErrIPBlocked = errors.New("rift: source IP blocked by rate limiter")

// ErrTokenRevoked indicates the connection was closed because an operator
// revoked the token via DELETE /_admin/tokens/:name. Distinct from
// ErrTokenExpired and ErrAuthFailed so callers can surface the right
// remediation (provision a new token rather than refresh or retry).
var ErrTokenRevoked = errors.New("rift: token revoked")
