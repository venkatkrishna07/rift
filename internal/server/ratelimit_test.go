package server

import "testing"

// TestRateLimiterStopIdempotent guards against the panic that occurs when
// Stop's internal channel close runs more than once.
func TestRateLimiterStopIdempotent(t *testing.T) {
	rl := newRateLimiter()
	rl.Stop()
	rl.Stop()
	rl.Stop()
}
