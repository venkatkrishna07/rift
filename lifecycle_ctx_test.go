package rift_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/venkatkrishna07/rift"
)

func TestServerRunReturnsCtxCanceledOnCancel(t *testing.T) {
	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if srv.Addr() != nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
	}()
	runErr := srv.Run(ctx)
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", runErr)
	}
}

func TestServerRunReturnsCtxDeadlineExceeded(t *testing.T) {
	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	runErr := srv.Run(ctx)
	if !errors.Is(runErr, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", runErr)
	}
}

func TestClientConnectReturnsCtxCanceled(t *testing.T) {
	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              "127.0.0.1:1",
		Token:               "rift_dummy",
		Tunnels:             []rift.TunnelSpec{{LocalPort: 65535, Proto: rift.ProtoHTTP, Name: "x"}},
		Insecure:            true,
		AcknowledgeInsecure: true,
		Protocol:            rift.ProtocolRift,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err = cli.Connect(ctx)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context error, got %v", err)
	}
}
