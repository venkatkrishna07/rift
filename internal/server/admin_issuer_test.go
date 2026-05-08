package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// memTokenStore is an in-memory store.TokenStore for tests in this file.
type memTokenStore struct {
	mu     sync.Mutex
	tokens map[string]string
}

func newMemTokenStore() *memTokenStore { return &memTokenStore{tokens: make(map[string]string)} }

func (m *memTokenStore) Validate(_ context.Context, token string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tokens {
		if t == token {
			return true, nil
		}
	}
	return false, nil
}
func (m *memTokenStore) Add(_ context.Context, name, token string, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[name] = token
	return nil
}
func (m *memTokenStore) Lookup(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokens[key], nil
}
func (m *memTokenStore) Save(_ context.Context, key, token string) error {
	return m.Add(context.Background(), key, token, 0)
}
func (m *memTokenStore) TokenExpiry(context.Context, string) (time.Time, error) {
	return time.Time{}, nil
}
func (m *memTokenStore) Close() error { return nil }

// TestAdminIssuer_ConstantTimeCompareLengthAgnostic verifies the SHA-256
// hashing path: bearer secrets of length 1 and length 1000 both reach the
// constant-time compare and return 401 (not panic, not 200).
func TestAdminIssuer_ConstantTimeCompareLengthAgnostic(t *testing.T) {
	const secret = "topsecret"
	store := newMemTokenStore()
	iss := NewAdminSecretIssuer(secret, store, time.Hour, zap.NewNop())

	cases := []struct {
		name   string
		bearer string
	}{
		{"len_1", "x"},
		{"len_1000", strings.Repeat("a", 1000)},
		{"empty", ""},
		{"prefix_of_secret", secret[:3]},
		{"secret_plus_suffix", secret + "extra"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/_admin/tokens?name=alice", nil)
			req.Header.Set("Authorization", "Bearer "+tc.bearer)
			req.RemoteAddr = "127.0.0.1:54321"
			rr := httptest.NewRecorder()
			iss.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("bearer=%q: got %d want 401 body=%s", tc.bearer, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestAdminIssuer_CorrectSecretStillWorks ensures the SHA-256 path doesn't
// break the happy path.
func TestAdminIssuer_CorrectSecretStillWorks(t *testing.T) {
	const secret = "topsecret"
	store := newMemTokenStore()
	iss := NewAdminSecretIssuer(secret, store, time.Hour, zap.NewNop())

	req := httptest.NewRequest(http.MethodPost, "/_admin/tokens?name=bob", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.RemoteAddr = "127.0.0.1:54321"
	rr := httptest.NewRecorder()
	iss.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got %d want 200 body=%s", rr.Code, rr.Body.String())
	}
}
