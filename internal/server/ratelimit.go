package server

import (
	"sync"
	"time"
)

const (
	maxAuthFailures   = 5
	authFailureWindow = 15 * time.Minute
	rlCleanupInterval = 5 * time.Minute
)

// rateLimiter tracks per-IP auth failures and blocks repeat offenders.
type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rlEntry
	done    chan struct{}
}

type rlEntry struct {
	failures int
	blocked  bool
	reset    time.Time
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		entries: make(map[string]*rlEntry),
		done:    make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Stop terminates the background cleanup goroutine.
func (r *rateLimiter) Stop() { close(r.done) }

// RecordFailure records an auth failure for ip and returns true if the IP is now blocked.
func (r *rateLimiter) RecordFailure(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.getOrCreate(ip)
	e.failures++
	if e.failures >= maxAuthFailures {
		e.blocked = true
	}
	return e.blocked
}

// IsBlocked reports whether ip is currently rate-limited.
func (r *rateLimiter) IsBlocked(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entries[ip]
	if e == nil {
		return false
	}
	if time.Now().After(e.reset) {
		delete(r.entries, ip)
		return false
	}
	return e.blocked
}

func (r *rateLimiter) getOrCreate(ip string) *rlEntry {
	e := r.entries[ip]
	if e == nil || time.Now().After(e.reset) {
		e = &rlEntry{reset: time.Now().Add(authFailureWindow)}
		r.entries[ip] = e
	}
	return e
}

func (r *rateLimiter) cleanup() {
	ticker := time.NewTicker(rlCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			r.mu.Lock()
			now := time.Now()
			for ip, e := range r.entries {
				if now.After(e.reset) {
					delete(r.entries, ip)
				}
			}
			r.mu.Unlock()
		}
	}
}
