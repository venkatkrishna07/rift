// Package store provides token persistence for rift server and client.
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// TokenStore abstracts token persistence — swappable without touching business logic.
type TokenStore interface {
	// Validate reports whether token is a valid server-issued token.
	Validate(ctx context.Context, token string) (bool, error)
	// Add stores a new named token on the server side.
	// ttl is the token lifetime; 0 means no expiry.
	Add(ctx context.Context, name, token string, ttl time.Duration) error
	// Lookup retrieves a stored token by key (client-side: key = server address).
	Lookup(ctx context.Context, key string) (string, error)
	// Save stores an arbitrary key→token mapping (client-side persistence).
	Save(ctx context.Context, key, token string) error
	// TokenExpiry returns when the token expires; zero time means no expiry.
	TokenExpiry(ctx context.Context, token string) (time.Time, error)
	// Close flushes and releases resources.
	Close() error
}

// GenerateToken returns a cryptographically random token with format "rift_<64 hex chars>".
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return "rift_" + hex.EncodeToString(b), nil
}
