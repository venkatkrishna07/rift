package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// dialFreePort returns a free TCP port by briefly binding to :0.
func dialFreePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("dialFreePort: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	return port
}

func TestServeTCPTunnelBindSuccess(t *testing.T) {
	port := dialFreePort(t)

	reg := NewRegistry(0, 0)
	tun, err := reg.RegisterTCP(nil)
	if err != nil {
		t.Fatalf("RegisterTCP: %v", err)
	}

	bindCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())

	log := zaptest.NewLogger(t)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serveTCPTunnel(ctx, nil, tun.ID, port, reg, 30*time.Second, bindCh, log)
	}()

	select {
	case err := <-bindCh:
		if err != nil {
			cancel()
			wg.Wait()
			t.Fatalf("expected nil bind error, got: %v", err)
		}
		// Successfully bound — cancel context to stop the goroutine and wait for clean exit.
		cancel()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("goroutine did not exit after context cancellation")
		}
	case <-time.After(2 * time.Second):
		cancel()
		wg.Wait()
		t.Fatal("timed out waiting for bind result")
	}
}

func TestServeTCPTunnelBindError(t *testing.T) {
	// Bind a listener and keep it open to occupy the port.
	occupied, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to bind occupied listener: %v", err)
	}
	defer occupied.Close()

	port := uint16(occupied.Addr().(*net.TCPAddr).Port)

	reg := NewRegistry(0, 0)
	tun, err := reg.RegisterTCP(nil)
	if err != nil {
		t.Fatalf("RegisterTCP: %v", err)
	}

	bindCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := zaptest.NewLogger(t)

	go serveTCPTunnel(ctx, nil, tun.ID, port, reg, 30*time.Second, bindCh, log)

	select {
	case err := <-bindCh:
		if err == nil {
			t.Fatal("expected a bind error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bind error")
	}
}
