package server

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
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

// ── per-IP token-bucket limiter ────────────────────────────────────────────

// perIPLimiter maintains a per-source-IP token bucket using golang.org/x/time/rate.
// Idle entries are evicted by a background goroutine started via start().
type perIPLimiter struct {
	r       rate.Limit
	burst   int
	idleTTL time.Duration
	mu      sync.Mutex
	buckets  map[string]*rate.Limiter
	lastSeen map[string]time.Time
}

func newPerIPLimiter(r rate.Limit, burst int, idleTTL time.Duration) *perIPLimiter {
	return &perIPLimiter{
		r:        r,
		burst:    burst,
		idleTTL:  idleTTL,
		buckets:  make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
	}
}

// Allow returns true if ip is within its rate limit.
func (p *perIPLimiter) Allow(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.buckets[ip]
	if !ok {
		l = rate.NewLimiter(p.r, p.burst)
		p.buckets[ip] = l
	}
	p.lastSeen[ip] = time.Now()
	return l.Allow()
}

// start launches a background goroutine that evicts entries idle longer than idleTTL.
// The sweep interval is idleTTL/2 (minimum 1 minute).
func (p *perIPLimiter) start(ctx context.Context) {
	interval := p.idleTTL / 2
	if interval < time.Minute {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cutoff := time.Now().Add(-p.idleTTL)
				p.mu.Lock()
				for ip, t := range p.lastSeen {
					if t.Before(cutoff) {
						delete(p.buckets, ip)
						delete(p.lastSeen, ip)
					}
				}
				p.mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
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
