package rift_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/venkatkrishna07/rift"
)

func TestNewServerDevMode(t *testing.T) {
	tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
	if err != nil {
		t.Fatalf("DevTLSConfig: %v", err)
	}

	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	}, rift.WithTLSConfig(tlsCfg), rift.WithLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := srv.Run(ctx); !isContextErr(err) {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
}

func isContextErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func TestProdTLSConfigShape(t *testing.T) {
	cfg, h := rift.ProdTLSConfig("tunnel.example.com", t.TempDir())
	if cfg == nil || h == nil {
		t.Fatalf("ProdTLSConfig returned nil components: cfg=%v h=%v", cfg, h)
	}
}

func TestNewAdminSecretIssuer(t *testing.T) {
	iss := rift.NewAdminSecretIssuer("topsecret", nil, time.Hour, rift.NopLogger())
	if iss == nil {
		t.Fatal("NewAdminSecretIssuer returned nil")
	}
	var _ rift.TokenIssuer = iss
}
