package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/venkatkrishna07/rift"
)

// memTokenStore is an in-memory rift.TokenStore for tests.
type memTokenStore struct {
	mu     sync.Mutex
	tokens map[string]string // name -> token
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

func (m *memTokenStore) OwnerOf(_ context.Context, token string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, t := range m.tokens {
		if t == token {
			return name, true, nil
		}
	}
	return "", false, nil
}

func (m *memTokenStore) Delete(_ context.Context, name string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokens[name]; !ok {
		return false, nil
	}
	delete(m.tokens, name)
	return true, nil
}

func (m *memTokenStore) Close() error { return nil }

// TestAdminIssuerE2E exercises the WithTokenIssuer wiring from the public rift
// package through the internal HTTP handler. It does not bind a real listener
// — the issuer's ServeHTTP is exercised directly so we can drive RemoteAddr.
func TestAdminIssuerE2E(t *testing.T) {
	const secret = "topsecret"
	store := newMemTokenStore()
	issuer := rift.NewAdminSecretIssuer(secret, store, time.Hour, rift.NopLogger())

	t.Run("wrong_secret_loopback_returns_401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/_admin/tokens?name=alice", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		req.RemoteAddr = "127.0.0.1:54321"
		rr := httptest.NewRecorder()

		if !issuer.Match(req) {
			t.Fatalf("issuer should Match POST /_admin/tokens")
		}
		issuer.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("right_secret_non_loopback_returns_403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/_admin/tokens?name=alice", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		req.RemoteAddr = "203.0.113.5:9999"
		rr := httptest.NewRecorder()

		issuer.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("want 403, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("right_secret_loopback_returns_token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/_admin/tokens?name=bob", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		req.RemoteAddr = "127.0.0.1:54322"
		rr := httptest.NewRecorder()

		issuer.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Name  string `json:"name"`
			Token string `json:"token"`
			TTL   string `json:"ttl"`
		}
		body, _ := io.ReadAll(rr.Body)
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode response: %v body=%s", err, string(body))
		}
		if resp.Name != "bob" {
			t.Fatalf("want name=bob, got %q", resp.Name)
		}
		if !strings.HasPrefix(resp.Token, "rift_") {
			t.Fatalf("want rift_-prefixed token, got %q", resp.Token)
		}
		stored, _ := store.Lookup(context.Background(), "bob")
		if stored != resp.Token {
			t.Fatalf("token not persisted: stored=%q response=%q", stored, resp.Token)
		}
	})
}

// TestPkgRiftServerWithTokenIssuer asserts WithTokenIssuer is the wiring path
// for token issuance — no AdminSecret on ServerConfig is involved.
func TestPkgRiftServerWithTokenIssuer(t *testing.T) {
	tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
	if err != nil {
		t.Fatalf("DevTLSConfig: %v", err)
	}
	store := newMemTokenStore()
	issuer := rift.NewAdminSecretIssuer("s3cret", store, time.Hour, rift.NopLogger())

	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	},
		rift.WithTLSConfig(tlsCfg),
		rift.WithLogger(rift.NopLogger()),
		rift.WithTokenStore(store),
		rift.WithTokenIssuer(issuer),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
}
