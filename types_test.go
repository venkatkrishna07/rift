package rift_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/venkatkrishna07/rift/internal/server"
	"github.com/venkatkrishna07/rift/internal/store"
	"github.com/venkatkrishna07/rift"
)

// stubTokenStore satisfies rift.TokenStore. The compiler enforces that every
// method on the curated interface is reachable.
type stubTokenStore struct{}

func (stubTokenStore) Validate(context.Context, string) (bool, error)           { return false, nil }
func (stubTokenStore) Add(context.Context, string, string, time.Duration) error { return nil }
func (stubTokenStore) Lookup(context.Context, string) (string, error)           { return "", nil }
func (stubTokenStore) Save(context.Context, string, string) error               { return nil }
func (stubTokenStore) TokenExpiry(context.Context, string) (time.Time, error) {
	return time.Time{}, nil
}
func (stubTokenStore) OwnerOf(context.Context, string) (string, bool, error) { return "", false, nil }
func (stubTokenStore) Delete(context.Context, string) (bool, error)          { return false, nil }
func (stubTokenStore) Close() error                                          { return nil }

// stubTokenIssuer satisfies rift.TokenIssuer.
type stubTokenIssuer struct{}

func (stubTokenIssuer) Match(*http.Request) bool                     { return false }
func (stubTokenIssuer) ServeHTTP(http.ResponseWriter, *http.Request) {}

// Compile-time assertions:
//   - user-defined types satisfy the curated interfaces;
//   - internal implementations still satisfy the curated interfaces (so the
//     wrapper does not silently exclude any production-path types).
var (
	_ rift.TokenStore  = stubTokenStore{}
	_ rift.TokenIssuer = stubTokenIssuer{}
	_ rift.TokenStore  = (*store.BadgerStore)(nil)
	_ rift.TokenIssuer = (*server.AdminSecretIssuer)(nil)
)

// TestCuratedTypesAreUsable exercises the curated wrapper structs. Notice
// AdminSecret is no longer settable on ServerConfig — that field has been
// removed from the public surface and is wired via WithTokenIssuer instead.
func TestCuratedTypesAreUsable(t *testing.T) {
	cfg := rift.ServerConfig{
		Domain:        "tunnel.example.com",
		ListenAddr:    ":443",
		ACMEAddr:      ":80",
		Dev:           true,
		MaxBodyBytes:  1024,
		StreamTimeout: time.Minute,
		MaxTotalConns: 10,
		TCPPortMin:    20000,
		TCPPortMax:    30000,
		TokenTTL:      time.Hour,
		DBPath:        "/tmp/rift",
	}
	if cfg.EffectiveMaxBodyBytes() != 1024 {
		t.Fatalf("ServerConfig methods not exposed via wrapper")
	}

	cli := rift.ClientConfig{
		Server:   "tunnel.example.com:443",
		Token:    "rift_x",
		Tunnels:  []rift.TunnelSpec{{LocalPort: 3000, Proto: rift.ProtoHTTP, Name: "app"}},
		Protocol: rift.ProtocolRift,
	}
	if cli.EffectiveStreamTimeout() == 0 {
		t.Fatalf("ClientConfig methods not exposed via wrapper")
	}

	if rift.DefaultTokenTTL == 0 {
		t.Fatalf("DefaultTokenTTL not exposed")
	}

	if rift.ProtocolMCP == "" || rift.ProtocolMCP == rift.ProtocolRift {
		t.Fatalf("ProtocolMCP wrapper is broken or duplicates ProtocolRift")
	}
	if rift.ProtoHTTP == "" || rift.ProtoTCP == "" || rift.ProtoHTTP == rift.ProtoTCP {
		t.Fatalf("ProtoHTTP/ProtoTCP wrappers broken: %q / %q", rift.ProtoHTTP, rift.ProtoTCP)
	}
}
