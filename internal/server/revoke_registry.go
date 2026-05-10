package server

import (
	"sync"
	"sync/atomic"
)

// RevokeRegistry maps a token name to a set of side-effect callbacks fired
// when the token is revoked.
//
// Callers (typically connection handlers) Register a callback after a
// successful authentication. Revoke fires every callback for the supplied
// name and clears the entry. The unregister func returned from Register is
// idempotent and removes that single registration.
type RevokeRegistry struct {
	mu     sync.Mutex
	fns    map[string]map[uint64]func()
	nextID atomic.Uint64
}

func NewRevokeRegistry() *RevokeRegistry {
	return &RevokeRegistry{fns: make(map[string]map[uint64]func())}
}

// Register stores fn under name and returns an unregister func.
func (r *RevokeRegistry) Register(name string, fn func()) func() {
	id := r.nextID.Add(1)
	r.mu.Lock()
	if r.fns[name] == nil {
		r.fns[name] = make(map[uint64]func())
	}
	r.fns[name][id] = fn
	r.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if m, ok := r.fns[name]; ok {
				delete(m, id)
				if len(m) == 0 {
					delete(r.fns, name)
				}
			}
		})
	}
}

// Revoke fires every callback registered under name and clears the entry.
// Returns the number of callbacks invoked. Callbacks are invoked outside the
// registry lock so they may safely touch the registry themselves.
func (r *RevokeRegistry) Revoke(name string) int {
	r.mu.Lock()
	fns := r.fns[name]
	delete(r.fns, name)
	r.mu.Unlock()

	for _, fn := range fns {
		fn()
	}
	return len(fns)
}

// Count returns the number of callbacks currently registered under name.
// Useful for tests.
func (r *RevokeRegistry) Count(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.fns[name])
}
