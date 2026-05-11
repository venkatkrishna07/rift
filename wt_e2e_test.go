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
