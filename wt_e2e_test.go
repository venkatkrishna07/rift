package rift_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"

	"github.com/venkatkrishna07/rift"
)

func TestWebTransportRoundTrip(t *testing.T) {
	t.Parallel()

	// Local TCP echo server.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = upstreamLn.Close() })
	upstreamPort := uint16(upstreamLn.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(c)
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
	if err := ts.Add(context.Background(), "wtclient", token, time.Hour); err != nil {
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

	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              srv.Addr().String(),
		Token:               token,
		Tunnels:             []rift.TunnelSpec{{LocalPort: upstreamPort, Proto: rift.ProtoWT, Name: "wtdemo"}},
		Insecure:            true,
		AcknowledgeInsecure: true,
		Protocol:            rift.ProtocolRift,
	}, rift.WithClientLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	cliCtx, cliCancel := context.WithCancel(context.Background())
	cliErr := make(chan error, 1)
	go func() { cliErr <- cli.Connect(cliCtx) }()
	t.Cleanup(func() {
		cliCancel()
		<-cliErr
	})

	// Wait for client to register the tunnel. Probe by attempting WT dial with
	// a short retry loop.
	wtURL := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort("wtdemo.tunnel.localhost", portOnly(srv.Addr().String())),
		Path:   "/",
	}

	dialer := &webtransport.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test only
			NextProtos:         []string{"h3"},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}

	var sess *webtransport.Session
	dialDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(dialDeadline) {
		dialCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_, s, derr := dialer.Dial(dialCtx, wtURL.String(), nil)
		cancel()
		if derr == nil {
			sess = s
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if sess == nil {
		t.Fatalf("could not dial WT within 5s — wtURL=%s", wtURL.String())
	}
	t.Cleanup(func() { _ = sess.CloseWithError(0, "test done") })

	stream, err := sess.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	defer stream.Close()

	payload := []byte("hello-webtransport")
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(payload))
	if err := stream.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Errorf("echo mismatch: got %q want %q", buf, payload)
	}
}

func portOnly(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

// TestWebTransportUniStream covers the WT unidirectional stream path:
// visitor → server → client → local TCP, write-only. The local TCP echo
// listener exposes the bytes it received via a channel so the test can
// assert delivery.
func TestWebTransportUniStream(t *testing.T) {
	t.Parallel()

	received := make(chan []byte, 1)
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = upstreamLn.Close() })
	upstreamPort := uint16(upstreamLn.Addr().(*net.TCPAddr).Port)
	go func() {
		c, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := io.ReadFull(c, buf[:len("hello-uni\n")])
		received <- append([]byte(nil), buf[:n]...)
	}()

	srv, token := startWTServer(t)

	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              srv.Addr().String(),
		Token:               token,
		Tunnels:             []rift.TunnelSpec{{LocalPort: upstreamPort, Proto: rift.ProtoWT, Name: "unidemo"}},
		Insecure:            true,
		AcknowledgeInsecure: true,
		Protocol:            rift.ProtocolRift,
	}, rift.WithClientLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cliCtx, cliCancel := context.WithCancel(context.Background())
	cliErr := make(chan error, 1)
	go func() { cliErr <- cli.Connect(cliCtx) }()
	t.Cleanup(func() { cliCancel(); <-cliErr })

	wtURL := &url.URL{Scheme: "https", Host: net.JoinHostPort("unidemo.tunnel.localhost", portOnly(srv.Addr().String())), Path: "/"}
	sess := dialWT(t, wtURL.String(), 5*time.Second)
	t.Cleanup(func() { _ = sess.CloseWithError(0, "test done") })

	uni, err := sess.OpenUniStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenUniStreamSync: %v", err)
	}
	if _, err := uni.Write([]byte("hello-uni\n")); err != nil {
		t.Fatalf("uni write: %v", err)
	}
	_ = uni.Close()

	select {
	case got := <-received:
		if string(got) != "hello-uni\n" {
			t.Errorf("local TCP got %q, want %q", got, "hello-uni\n")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local TCP did not receive uni-stream bytes within 3s")
	}
}

// TestWebTransportDatagramForward verifies the visitor → server → client →
// local UDP path one-way. The UDP listener pushes received bytes onto a
// channel so the test can confirm delivery.
func TestWebTransportDatagramForward(t *testing.T) {
	t.Parallel()

	received := make(chan []byte, 4)
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { _ = udpLn.Close() })
	udpPort := uint16(udpLn.LocalAddr().(*net.UDPAddr).Port)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := udpLn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			received <- append([]byte(nil), buf[:n]...)
		}
	}()

	srv, token := startWTServer(t)

	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              srv.Addr().String(),
		Token:               token,
		Tunnels:             []rift.TunnelSpec{{LocalPort: 65535, DatagramLocalPort: udpPort, Proto: rift.ProtoWT, Name: "dgramfwd"}},
		Insecure:            true,
		AcknowledgeInsecure: true,
		Protocol:            rift.ProtocolRift,
	}, rift.WithClientLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cliCtx, cliCancel := context.WithCancel(context.Background())
	cliErr := make(chan error, 1)
	go func() { cliErr <- cli.Connect(cliCtx) }()
	t.Cleanup(func() { cliCancel(); <-cliErr })

	wtURL := &url.URL{Scheme: "https", Host: net.JoinHostPort("dgramfwd.tunnel.localhost", portOnly(srv.Addr().String())), Path: "/"}
	sess := dialWT(t, wtURL.String(), 5*time.Second)
	t.Cleanup(func() { _ = sess.CloseWithError(0, "test done") })

	payload := []byte("forward-only")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = sess.SendDatagram(payload)
		select {
		case got := <-received:
			if string(got) != string(payload) {
				t.Errorf("payload mismatch: got %q want %q", got, payload)
			}
			return
		case <-time.After(100 * time.Millisecond):
			// retry — datagram may have been lost or session not fully ready
		}
	}
	t.Fatal("local UDP did not receive datagram within 3s")
}

// TestWebTransportDatagramRoundTrip covers both directions: visitor sends a
// datagram, local UDP echoes it back, visitor reads the reply.
func TestWebTransportDatagramRoundTrip(t *testing.T) {
	t.Parallel()

	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { _ = udpLn.Close() })
	udpPort := uint16(udpLn.LocalAddr().(*net.UDPAddr).Port)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udpLn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpLn.WriteToUDP(buf[:n], addr)
		}
	}()

	srv, token := startWTServer(t)

	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              srv.Addr().String(),
		Token:               token,
		Tunnels:             []rift.TunnelSpec{{LocalPort: 65535, DatagramLocalPort: udpPort, Proto: rift.ProtoWT, Name: "dgramrt"}},
		Insecure:            true,
		AcknowledgeInsecure: true,
		Protocol:            rift.ProtocolRift,
	}, rift.WithClientLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cliCtx, cliCancel := context.WithCancel(context.Background())
	cliErr := make(chan error, 1)
	go func() { cliErr <- cli.Connect(cliCtx) }()
	t.Cleanup(func() { cliCancel(); <-cliErr })

	wtURL := &url.URL{Scheme: "https", Host: net.JoinHostPort("dgramrt.tunnel.localhost", portOnly(srv.Addr().String())), Path: "/"}
	sess := dialWT(t, wtURL.String(), 5*time.Second)
	t.Cleanup(func() { _ = sess.CloseWithError(0, "test done") })

	// Reader goroutine drains any echo'd datagram.
	type result struct {
		data []byte
		err  error
	}
	got := make(chan result, 4)
	go func() {
		for {
			d, err := sess.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			got <- result{d, nil}
		}
	}()

	payload := []byte("round-trip-dgram")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = sess.SendDatagram(payload)
		select {
		case r := <-got:
			if string(r.data) == string(payload) {
				return
			}
		case <-time.After(150 * time.Millisecond):
			// retry; UDP + QUIC datagrams are best-effort
		}
	}
	t.Fatal("did not receive echo datagram within 5s")
}

// startWTServer constructs and starts a prod-mode rift server with a single
// token. Returns the server and the freshly minted token.
func startWTServer(t *testing.T) (*rift.Server, string) {
	t.Helper()

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
	if err := ts.Add(context.Background(), "wt-test", token, time.Hour); err != nil {
		t.Fatalf("ts.Add: %v", err)
	}
	tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
	if err != nil {
		t.Fatalf("DevTLSConfig: %v", err)
	}
	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: freeUDPPort(t),
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
	return srv, token
}

// TestWebTransportDatagramPerSessionRouting verifies that two distinct
// visitors on the same WT tunnel are routed to distinct UDP source ports
// on the client side, so the local service can address them individually
// and replies do not cross-pollinate. Without per-session routing the
// local UDP listener would see both visitors via a single source port
// and replies would broadcast to every visitor.
func TestWebTransportDatagramPerSessionRouting(t *testing.T) {
	t.Parallel()

	type observation struct {
		addr    *net.UDPAddr
		payload string
	}
	observed := make(chan observation, 8)

	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { _ = udpLn.Close() })
	udpPort := uint16(udpLn.LocalAddr().(*net.UDPAddr).Port)

	// Echo prefix the sender's source port so we can assert that visitor A
	// receives an echo for A's payload and visitor B receives B's payload.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udpLn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			payload := string(buf[:n])
			observed <- observation{addr: addr, payload: payload}
			_, _ = udpLn.WriteToUDP([]byte("echo:"+payload), addr)
		}
	}()

	srv, token := startWTServer(t)

	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              srv.Addr().String(),
		Token:               token,
		Tunnels:             []rift.TunnelSpec{{LocalPort: 65535, DatagramLocalPort: udpPort, Proto: rift.ProtoWT, Name: "dgramrouting"}},
		Insecure:            true,
		AcknowledgeInsecure: true,
		Protocol:            rift.ProtocolRift,
	}, rift.WithClientLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cliCtx, cliCancel := context.WithCancel(context.Background())
	cliErr := make(chan error, 1)
	go func() { cliErr <- cli.Connect(cliCtx) }()
	t.Cleanup(func() { cliCancel(); <-cliErr })

	host := net.JoinHostPort("dgramrouting.tunnel.localhost", portOnly(srv.Addr().String()))
	wtURL := &url.URL{Scheme: "https", Host: host, Path: "/"}

	sessA := dialWT(t, wtURL.String(), 5*time.Second)
	t.Cleanup(func() { _ = sessA.CloseWithError(0, "done") })
	sessB := dialWT(t, wtURL.String(), 5*time.Second)
	t.Cleanup(func() { _ = sessB.CloseWithError(0, "done") })

	// Each visitor reads echoes in its own goroutine.
	echoA := make(chan string, 4)
	echoB := make(chan string, 4)
	go func() {
		for {
			d, err := sessA.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			echoA <- string(d)
		}
	}()
	go func() {
		for {
			d, err := sessB.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			echoB <- string(d)
		}
	}()

	// Send distinct payloads. Retry to overcome session-startup races.
	addrs := map[string]map[string]struct{}{
		"A": {},
		"B": {},
	}
	deadline := time.Now().Add(5 * time.Second)
	gotA, gotB := false, false
	for time.Now().Before(deadline) && (!gotA || !gotB) {
		_ = sessA.SendDatagram([]byte("hello-A"))
		_ = sessB.SendDatagram([]byte("hello-B"))
		select {
		case obs := <-observed:
			addrs[obs.payload[len(obs.payload)-1:]][obs.addr.String()] = struct{}{}
		case <-time.After(150 * time.Millisecond):
		}
		select {
		case msg := <-echoA:
			if msg == "echo:hello-A" {
				gotA = true
			}
		case msg := <-echoB:
			if msg == "echo:hello-B" {
				gotB = true
			}
		case <-time.After(150 * time.Millisecond):
		}
	}
	if !gotA {
		t.Error("visitor A did not receive its echo")
	}
	if !gotB {
		t.Error("visitor B did not receive its echo")
	}

	// Drain any extra observations.
	drain := time.After(200 * time.Millisecond)
collect:
	for {
		select {
		case obs := <-observed:
			suffix := obs.payload[len(obs.payload)-1:]
			addrs[suffix][obs.addr.String()] = struct{}{}
		case <-drain:
			break collect
		}
	}

	// Both visitors must have actually exercised the UDP echo path before
	// the disjointness check is meaningful — a routing bug that drops one
	// visitor entirely would otherwise produce a false pass.
	if len(addrs["A"]) == 0 {
		t.Fatal("visitor A never reached the local UDP echo")
	}
	if len(addrs["B"]) == 0 {
		t.Fatal("visitor B never reached the local UDP echo")
	}
	// Each visitor's source addr set should be disjoint from the other's.
	for a := range addrs["A"] {
		if _, dup := addrs["B"][a]; dup {
			t.Errorf("visitor A and B share UDP source port %s — routing is 1:N, not 1:1", a)
		}
	}
}

// dialWT establishes a WT session against url with a retry loop.
func dialWT(t *testing.T, url string, timeout time.Duration) *webtransport.Session {
	t.Helper()
	dialer := &webtransport.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test only
			NextProtos:         []string{"h3"},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		_, s, err := dialer.Dial(ctx, url, nil)
		cancel()
		if err == nil {
			return s
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("could not dial WT within %v — url=%s", timeout, url)
	return nil
}
