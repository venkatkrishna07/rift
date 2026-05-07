package rift_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/pkg/rift"
)

func TestNewServerDevMode(t *testing.T) {
	tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
	if err != nil {
		t.Fatalf("DevTLSConfig: %v", err)
	}

	srv := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	}, nil, tlsCfg, nil, zap.NewNop())
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := srv.Run(ctx); err != nil && !isContextErr(err) {
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
	iss := rift.NewAdminSecretIssuer("topsecret", nil, time.Hour, zap.NewNop())
	if iss == nil {
		t.Fatal("NewAdminSecretIssuer returned nil")
	}
	var _ rift.TokenIssuer = iss
}
