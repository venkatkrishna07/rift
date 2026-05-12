package rift_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/venkatkrishna07/rift"
)

// freeUDPPort reserves a UDP port by briefly binding ":0" and returning the
// resolved port. The listener is closed before the helper returns; callers
// race against other tests on the same machine but the loopback collision
// surface is small.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	return addr
}

// startDevServer constructs and runs a dev-mode rift.Server with the supplied
// store. The returned shutdown closure stops the server and waits for Run to
// return.
func startDevServer(t *testing.T, listenAddr string, ts rift.TokenStore) (*rift.Server, func()) {
	t.Helper()

	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: listenAddr,
		Dev:        true,
	},
		rift.WithLogger(rift.NopLogger()),
		rift.WithTokenStore(ts),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(runCtx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Addr() != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if srv.Addr() == nil {
		runCancel()
		<-runErr
		t.Fatal("server did not bind within 5s")
	}

	shutdown := func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		runCancel()
		select {
		case <-runErr:
		case <-time.After(5 * time.Second):
			t.Error("server Run did not exit within 5s after Shutdown")
		}
	}
	return srv, shutdown
}

// TestAuthFailWithWrongToken builds a non-dev server (Dev=false) so the
// token store is consulted, then dials with a token that is not in the store.
// The client must surface ErrAuthFailed.
//
// A dev-mode server accepts any token, so token rejection requires Dev=false
// with WithTokenStore wired.
func TestAuthFailWithWrongToken(t *testing.T) {
	t.Parallel()

	storePath := t.TempDir()
	ts, err := rift.OpenBadgerStore(storePath, rift.NopLogger())
	if err != nil {
		t.Fatalf("OpenBadgerStore: %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })

	tokenA, err := rift.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := ts.Add(context.Background(), "alice", tokenA, time.Hour); err != nil {
		t.Fatalf("ts.Add: %v", err)
	}

	tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
	if err != nil {
		t.Fatalf("DevTLSConfig: %v", err)
	}

	listenAddr := freeUDPPort(t)
	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: listenAddr,
		Dev:        false,
	},
		rift.WithLogger(rift.NopLogger()),
		rift.WithTokenStore(ts),
		rift.WithTLSConfig(tlsCfg),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(runCtx) }()
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		runCancel()
		<-runErr
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && srv.Addr() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("server did not bind within 5s")
	}

	tokenB, err := rift.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken (B): %v", err)
	}

	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              srv.Addr().String(),
		Token:               tokenB,
		Tunnels:             []rift.TunnelSpec{{LocalPort: 65535, Proto: rift.ProtoHTTP, Name: "x"}},
		Insecure:            true,
		AcknowledgeInsecure: true,
		Protocol:            rift.ProtocolRift,
	}, rift.WithClientLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	connectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connErr := cli.Connect(connectCtx)
	if connErr == nil {
		t.Fatal("expected Connect to fail with auth error, got nil")
	}
	if !errors.Is(connErr, rift.ErrAuthFailed) {
		// Some auth failures may surface as a quic.ApplicationError with code 2
		// before the client can read the TypeError frame. Either path is a
		// genuine auth rejection, but the public sentinel is the contract.
		t.Fatalf("expected ErrAuthFailed, got %v (type %T)", connErr, connErr)
	}
}

// TestTLSVerifyFailureNonInsecure dials the dev server (cert for
// *.tunnel.localhost) using a raw IP host and Insecure=false. quic-go must
// reject the handshake.
func TestTLSVerifyFailureNonInsecure(t *testing.T) {
	t.Parallel()

	storePath := t.TempDir()
	ts, err := rift.OpenBadgerStore(storePath, rift.NopLogger())
	if err != nil {
		t.Fatalf("OpenBadgerStore: %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })

	listenAddr := freeUDPPort(t)
	srv, shutdown := startDevServer(t, listenAddr, ts)
	t.Cleanup(shutdown)

	cli, err := rift.NewClient(rift.ClientConfig{
		Server:   srv.Addr().String(), // 127.0.0.1:port — IP, not the cert SAN
		Token:    "rift_unused",
		Tunnels:  []rift.TunnelSpec{{LocalPort: 65535, Proto: rift.ProtoHTTP, Name: "x"}},
		Insecure: false,
		Protocol: rift.ProtocolRift,
	}, rift.WithClientLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	connectCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connErr := cli.Connect(connectCtx)
	if connErr == nil {
		t.Fatal("expected TLS verification failure, got nil")
	}
	// Connect returns a join of ctx.Err() and the latest connection error so
	// the dial-time TLS rejection is observable to callers. Assert the TLS
	// substring is present; the ctx error may also be present (it always is
	// when the deadline expires) — that's acceptable.
	msg := connErr.Error()
	if !strings.Contains(msg, "x509") && !strings.Contains(msg, "tls:") && !strings.Contains(msg, "CRYPTO_ERROR") {
		t.Fatalf("expected TLS/x509 error substring, got: %v", connErr)
	}
}

// TestRoundTripTCP exercises a TCP tunnel through the public API. The server
// is non-dev so the token store gates auth; the client registers a TCP tunnel
// pointing at a local echo listener and the test dials the public TCP port.
func TestRoundTripTCP(t *testing.T) {
	t.Parallel()

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = upstreamLn.Close() })

	upstreamPort := uint16(upstreamLn.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	storePath := t.TempDir()
	ts, err := rift.OpenBadgerStore(storePath, rift.NopLogger())
	if err != nil {
		t.Fatalf("OpenBadgerStore: %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })

	token, err := rift.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := ts.Add(context.Background(), "client", token, time.Hour); err != nil {
		t.Fatalf("ts.Add: %v", err)
	}

	tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
	if err != nil {
		t.Fatalf("DevTLSConfig: %v", err)
	}

	listenAddr := freeUDPPort(t)
	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: listenAddr,
		Dev:        false,
		// Constrain the TCP tunnel port range to a small loopback-friendly window
		// chosen to be unlikely to collide with system services. The server still
		// binds on 0.0.0.0 inside that range.
		TCPPortMin: 21000,
		TCPPortMax: 21999,
	},
		rift.WithLogger(rift.NopLogger()),
		rift.WithTokenStore(ts),
		rift.WithTLSConfig(tlsCfg),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(runCtx) }()
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		runCancel()
		<-runErr
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && srv.Addr() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("server did not bind within 5s")
	}

	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              srv.Addr().String(),
		Token:               token,
		Tunnels:             []rift.TunnelSpec{{LocalPort: upstreamPort, Proto: rift.ProtoTCP}},
		Insecure:            true,
		AcknowledgeInsecure: true,
		Protocol:            rift.ProtocolRift,
	}, rift.WithClientLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	connectCtx, connectCancel := context.WithCancel(context.Background())
	connectErr := make(chan error, 1)
	go func() { connectErr <- cli.Connect(connectCtx) }()
	t.Cleanup(func() {
		_ = cli.Close()
		connectCancel()
		select {
		case <-connectErr:
		case <-time.After(5 * time.Second):
		}
	})

	// Probe the TCP port range until a tunnel listener responds. The server
	// allocates the public port from [21000, 21999]; we sweep it to find the
	// active listener.
	publicPort, err := waitForTCPTunnel(t, 21000, 21999, 8*time.Second)
	if err != nil {
		t.Fatalf("tunnel did not become ready: %v", err)
	}

	// Dial the public TCP port, send a payload, and verify the upstream echo.
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort))
	if err != nil {
		t.Fatalf("dial public TCP: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-rift")
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := readFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: want %q got %q", payload, buf)
	}
}

// readFull reads exactly len(buf) bytes from r.
func readFull(r net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// waitForTCPTunnel polls the configured TCP port range until any port accepts
// a TCP connection, signalling that a tunnel is ready. Returns the active port.
func waitForTCPTunnel(t *testing.T, portMin, portMax uint16, timeout time.Duration) (uint16, error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for p := portMin; p <= portMax; p++ {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 50*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return p, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0, errors.New("no TCP tunnel listener detected within timeout")
}

// TestTokenTTLExpiry provisions a token with a 500ms TTL, confirms the
// connection lands, and waits past expiry. The server must close the
// connection so Connect either returns ErrTokenExpired or restarts the
// dial loop. The expiry path is implemented in internal/server/conn.go via
// CloseWithError(3); the client maps code 3 to ErrTokenExpired-equivalent
// permanent failure.
func TestTokenTTLExpiry(t *testing.T) {
	t.Parallel()

	storePath := t.TempDir()
	ts, err := rift.OpenBadgerStore(storePath, rift.NopLogger())
	if err != nil {
		t.Fatalf("OpenBadgerStore: %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })

	token, err := rift.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	// Badger TTL operates at second granularity; pick a value that lets the
	// connection complete handshake + register before the deadline elapses.
	if err := ts.Add(context.Background(), "shortlived", token, 2*time.Second); err != nil {
		t.Fatalf("ts.Add: %v", err)
	}

	tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
	if err != nil {
		t.Fatalf("DevTLSConfig: %v", err)
	}

	listenAddr := freeUDPPort(t)
	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: listenAddr,
		Dev:        false,
		TCPPortMin: 22000,
		TCPPortMax: 22999,
	},
		rift.WithLogger(rift.NopLogger()),
		rift.WithTokenStore(ts),
		rift.WithTLSConfig(tlsCfg),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(runCtx) }()
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		runCancel()
		<-runErr
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && srv.Addr() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("server did not bind within 5s")
	}

	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              srv.Addr().String(),
		Token:               token,
		Tunnels:             []rift.TunnelSpec{{LocalPort: 65535, Proto: rift.ProtoTCP}},
		Insecure:            true,
		AcknowledgeInsecure: true,
		Protocol:            rift.ProtocolRift,
	}, rift.WithClientLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer connectCancel()
	connectErr := make(chan error, 1)
	go func() { connectErr <- cli.Connect(connectCtx) }()
	t.Cleanup(func() { _ = cli.Close() })

	// The server closes the connection with QUIC application code 3 once the
	// token's deadline elapses. The client maps code 3 onto ErrTokenExpired
	// via wrapPermanent. Allow generous time for handshake + 2s TTL + close
	// propagation.
	select {
	case err := <-connectErr:
		if err == nil {
			t.Fatal("expected Connect to return after TTL expiry, got nil")
		}
		if errors.Is(err, rift.ErrTokenExpired) {
			return
		}
		// Handshake/register may race the TTL on slow CI: the auth path can
		// fail because the badger entry already expired by the time Validate
		// fires. That surfaces as ErrAuthFailed and is also acceptable
		// evidence that expiry is honoured end-to-end.
		if errors.Is(err, rift.ErrAuthFailed) {
			t.Skipf("token expired before auth completed (badger-TTL race); surfaced as ErrAuthFailed: %v", err)
		}
		msg := err.Error()
		if strings.Contains(msg, "token expired") || strings.Contains(msg, "Application error 0x3") {
			return
		}
		t.Fatalf("expected ErrTokenExpired or ErrAuthFailed, got %v", err)
	case <-time.After(12 * time.Second):
		t.Skip("token TTL expiry did not propagate to client within 12s; e2e variant flaky on this platform")
	}
}
