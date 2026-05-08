package rift_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/venkatkrishna07/rift"
)

func TestServerShutdownReturnsBeforeRun(t *testing.T) {
	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	}, rift.WithLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	runErr := make(chan error, 1)
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	go func() { runErr <- srv.Run(runCtx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Addr() != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("Addr() never became non-nil within 2s")
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}

	select {
	case err := <-runErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit within 2s after Shutdown")
	}
}

func TestNewServerErrorsOnMissingDomain(t *testing.T) {
	if _, err := rift.NewServer(rift.ServerConfig{ListenAddr: "127.0.0.1:0"}); err == nil {
		t.Fatal("expected error for missing Domain, got nil")
	}
}

func TestNewServerErrorsOnMissingTLS(t *testing.T) {
	_, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.example.com",
		ListenAddr: "127.0.0.1:0",
		Dev:        false,
	})
	if err == nil {
		t.Fatal("expected error for prod-mode without TLS, got nil")
	}
}

func TestNewServerDevAutoTLS(t *testing.T) {
	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	})
	if err != nil {
		t.Fatalf("NewServer with Dev=true and no TLS opt: %v", err)
	}
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestNewServerErrorsOnMissingListenAddr(t *testing.T) {
	if _, err := rift.NewServer(rift.ServerConfig{Domain: "tunnel.localhost", Dev: true}); err == nil {
		t.Fatal("expected error for missing ListenAddr, got nil")
	}
}

func TestServerShutdownBeforeRun(t *testing.T) {
	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown before Run: %v", err)
	}
}

func TestServerShutdownTwice(t *testing.T) {
	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	runErr := make(chan error, 1)
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	go func() { runErr <- srv.Run(runCtx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && srv.Addr() == nil {
		time.Sleep(20 * time.Millisecond)
	}

	first, fc := context.WithTimeout(context.Background(), 2*time.Second)
	defer fc()
	if err := srv.Shutdown(first); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	second, sc := context.WithTimeout(context.Background(), time.Second)
	defer sc()
	if err := srv.Shutdown(second); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
	<-runErr
}
