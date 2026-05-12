package rift_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/venkatkrishna07/rift"
)

func TestTokenRevokedKillsActiveTunnelImmediately(t *testing.T) {
	t.Parallel()

	storePath := t.TempDir()
	ts, err := rift.OpenBadgerStore(storePath, rift.NopLogger())
	if err != nil {
		t.Fatalf("OpenBadgerStore: %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })

	const adminSecret = "test-admin-secret"
	tok, err := rift.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := ts.Add(context.Background(), "alice", tok, time.Hour); err != nil {
		t.Fatalf("ts.Add: %v", err)
	}

	tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
	if err != nil {
		t.Fatalf("DevTLSConfig: %v", err)
	}

	issuer := rift.NewAdminSecretIssuer(adminSecret, ts, time.Hour, rift.NopLogger())

	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: freeUDPPort(t),
		Dev:        false,
	},
		rift.WithLogger(rift.NopLogger()),
		rift.WithTokenStore(ts),
		rift.WithTLSConfig(tlsCfg),
		rift.WithTokenIssuer(issuer),
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
		Token:               tok,
		Tunnels:             []rift.TunnelSpec{{LocalPort: 65535, Proto: rift.ProtoHTTP, Name: "alice-tun"}},
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
	connDone := make(chan error, 1)
	go func() { connDone <- cli.Connect(connectCtx) }()

	// Give the client time to authenticate before revoking.
	time.Sleep(500 * time.Millisecond)

	revokeReq := httptest.NewRequest(http.MethodDelete, "/_admin/tokens/alice", nil)
	revokeReq.Header.Set("Authorization", "Bearer "+adminSecret)
	revokeReq.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	issuer.ServeHTTP(rec, revokeReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke returned %d, body=%s", rec.Code, rec.Body.String())
	}

	select {
	case err := <-connDone:
		if !errors.Is(err, rift.ErrTokenRevoked) {
			t.Errorf("expected ErrTokenRevoked, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not exit within 3s of revoke")
	}

	if ok, _ := ts.Validate(context.Background(), tok); ok {
		t.Error("token should be deleted from store")
	}
}
