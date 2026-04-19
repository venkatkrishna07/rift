package relay

import (
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestRelayIdleTimeout(t *testing.T) {
	a, aRemote := net.Pipe()
	b, bRemote := net.Pipe()
	defer a.Close()
	defer b.Close()

	log, _ := zap.NewDevelopment()
	timeout := 200 * time.Millisecond

	done := make(chan struct{})
	go func() {
		defer close(done)
		Relay(aRemote, bRemote, timeout, log)
	}()

	// Send one byte so relay starts, then go idle.
	if _, err := a.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	select {
	case <-done:
		// relay self-terminated after idle — expected
	case <-time.After(timeout * 6):
		t.Fatal("relay did not close after idle timeout")
	}
}

func TestRelayZeroTimeoutExitsOnClose(t *testing.T) {
	a, aRemote := net.Pipe()
	b, bRemote := net.Pipe()

	log, _ := zap.NewDevelopment()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Relay(aRemote, bRemote, 0, log)
	}()

	a.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit after connection close")
	}
	b.Close()
}

func TestRelayDataFlows(t *testing.T) {
	a, aRemote := net.Pipe()
	b, bRemote := net.Pipe()
	defer a.Close()
	defer b.Close()

	log, _ := zap.NewDevelopment()
	go Relay(aRemote, bRemote, 0, log)

	want := []byte("hello relay")
	go func() { a.Write(want) }()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
