package rift

import (
	"context"
	"time"

	"github.com/venkatkrishna07/rift/internal/store"
)

// TokenStore persists tokens for the server (auth) and the client (caching).
//
// Implementations must be safe for concurrent use by multiple goroutines.
//
// SECURITY: server-side implementations should store SHA-256 hashes; the
// client-side cache persists tokens in plaintext, so restrict access to the
// data directory accordingly.
type TokenStore interface {
	Validate(ctx context.Context, token string) (bool, error)
	Add(ctx context.Context, name, token string, ttl time.Duration) error
	Lookup(ctx context.Context, key string) (string, error)
	Save(ctx context.Context, key, token string) error
	TokenExpiry(ctx context.Context, token string) (time.Time, error)
	Close() error
}

// OpenBadgerStore opens a BadgerDB-backed TokenStore at path.
//
// File-system contract: the directory is created with mode 0700 on first
// use. If the directory already exists with looser permissions, the
// supplied Logger receives a Warn-level entry; the open proceeds so
// existing deployments are not broken. Pass nil or NopLogger() for silence.
//
// Threat model:
//
//   - Server-side use (records added via TokenStore.Add) writes only the
//     SHA-256 hash of the token to disk; the raw token is never persisted.
//   - Client-side use (records added via TokenStore.Save under
//     "client:<addr>") writes the raw token in plaintext because the
//     client must replay it on each reconnect. Restrict access to the data
//     directory accordingly; do not place it on shared filesystems.
//
// The returned TokenStore is safe for concurrent use.
func OpenBadgerStore(path string, log Logger) (TokenStore, error) {
	return store.OpenBadger(path, zapFromLogger(log))
}

// OpenBadgerReadOnlyStore opens an existing BadgerDB at path in read-only
// mode. Multiple processes may open the same database concurrently when each
// uses this entry point — useful for read-only client caches alongside a
// running writer. Returns (nil, nil) when the database does not yet exist,
// allowing callers to proceed without a cached token.
//
// The same threat model as OpenBadgerStore applies: server-side records are
// SHA-256 hashed; client-side records ("client:<addr>") are plaintext.
//
// The logger is reserved for future diagnostics; pass nil or NopLogger() for
// silence. The returned TokenStore is safe for concurrent use.
func OpenBadgerReadOnlyStore(path string, log Logger) (TokenStore, error) {
	bs, err := store.OpenBadgerReadOnly(path, zapFromLogger(log))
	if err != nil {
		return nil, err
	}
	if bs == nil {
		return nil, nil
	}
	return bs, nil
}

// GenerateToken returns a cryptographically random token in the canonical
// rift format ("rift_" + 64 hex chars). Suitable for provisioning into a
// TokenStore.
func GenerateToken() (string, error) {
	return store.GenerateToken()
}

var _ TokenStore = (*store.BadgerStore)(nil)
