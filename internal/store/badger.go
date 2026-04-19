package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const (
	prefixToken  = "token:"  // server: sha256(token) → name
	prefixClient = "client:" // client: server-addr → token
)

// BadgerStore is a BadgerDB-backed TokenStore.
type BadgerStore struct {
	db *badger.DB
}

// OpenBadger opens (or creates) a BadgerDB at path.
func OpenBadger(path string) (*BadgerStore, error) {
	// Create directory with restrictive permissions if it doesn't exist.
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("create DB dir %s: %w", path, err)
	}
	// Warn if the directory is group- or world-readable.
	if info, err := os.Stat(path); err == nil {
		if info.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(os.Stderr, "WARNING: rift DB directory %s has permissions %04o — expected 0700\n", path, info.Mode().Perm())
		}
	}

	opts := badger.DefaultOptions(path)
	opts.Logger = nil       // suppress badger's own logging; zap handles ours
	opts.SyncWrites = false // async writes — WAL still guarantees durability on crash
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open badger at %s: %w", path, err)
	}
	return &BadgerStore{db: db}, nil
}

// OpenBadgerReadOnly opens an existing BadgerDB at path in read-only mode.
// Multiple processes can hold read-only handles simultaneously — no lock conflict.
// Returns nil without error if the path does not exist yet.
func OpenBadgerReadOnly(path string) (*BadgerStore, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	opts := badger.DefaultOptions(path)
	opts.Logger = nil
	opts.ReadOnly = true
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open badger (read-only) at %s: %w", path, err)
	}
	return &BadgerStore{db: db}, nil
}

// Close flushes pending writes and closes the database.
func (s *BadgerStore) Close() error { return s.db.Close() }

// tokenKey returns the DB key for a token: prefixToken + hex(sha256(token)).
func tokenKey(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return []byte(prefixToken + hex.EncodeToString(h[:]))
}

// Add stores sha256(token)→name under the server-side prefix. O(1) write.
// ttl is the token lifetime; 0 means no expiry.
func (s *BadgerStore) Add(_ context.Context, name, token string, ttl time.Duration) error {
	return s.db.Update(func(tx *badger.Txn) error {
		e := badger.NewEntry(tokenKey(token), []byte(name))
		if ttl > 0 {
			e = e.WithTTL(ttl)
		}
		return tx.SetEntry(e)
	})
}

// Validate checks whether token exists. O(1) — keyed by sha256(token).
func (s *BadgerStore) Validate(_ context.Context, token string) (bool, error) {
	err := s.db.View(func(tx *badger.Txn) error {
		_, err := tx.Get(tokenKey(token))
		return err
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

// Lookup retrieves a token by key (client-side: key = server address).
func (s *BadgerStore) Lookup(_ context.Context, key string) (string, error) {
	var val []byte
	err := s.db.View(func(tx *badger.Txn) error {
		item, err := tx.Get([]byte(prefixClient + key))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		val, err = item.ValueCopy(nil)
		return err
	})
	return string(val), err
}

// Save stores key→token under the client-side prefix.
func (s *BadgerStore) Save(_ context.Context, key, token string) error {
	return s.db.Update(func(tx *badger.Txn) error {
		return tx.Set([]byte(prefixClient+key), []byte(token))
	})
}

// TokenExpiry returns when the token expires; zero time means no expiry.
func (s *BadgerStore) TokenExpiry(_ context.Context, token string) (time.Time, error) {
	var expiry time.Time
	err := s.db.View(func(tx *badger.Txn) error {
		item, err := tx.Get(tokenKey(token))
		if err != nil {
			return err
		}
		if exp := item.ExpiresAt(); exp != 0 {
			expiry = time.Unix(int64(exp), 0)
		}
		return nil
	})
	return expiry, err
}
