package rift_test

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/venkatkrishna07/rift"
)

// ExampleNewServer constructs a development tunnel server with a self-signed
// TLS config and a slog-backed Logger. In production, replace DevTLSConfig
// with ProdTLSConfig and supply a TokenStore via WithTokenStore.
func ExampleNewServer() {
	tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
	if err != nil {
		fmt.Println("dev tls:", err)
		return
	}

	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	},
		rift.WithTLSConfig(tlsCfg),
		rift.WithLogger(rift.SlogAdapter(slog.New(slog.NewTextHandler(os.Stderr, nil)))),
	)
	if err != nil {
		fmt.Println("new server:", err)
		return
	}
	_ = srv
	fmt.Println("ok")
	// Output: ok
}

// ExampleNewClient constructs a tunnel client. The returned *Client is not
// connected yet — call Connect(ctx) to dial the server and serve forwarded
// streams. Close cancels Connect and is safe to call multiple times.
func ExampleNewClient() {
	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              "tunnel.localhost:443",
		Token:               "rift_xxx",
		Tunnels:             []rift.TunnelSpec{{LocalPort: 3000, Proto: rift.ProtoHTTP, Name: "app"}},
		Insecure:            false,
		AcknowledgeInsecure: false,
		Protocol:            rift.ProtocolRift,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = cli
	fmt.Println("ready")
	// Output: ready
}

// ExampleNewAdminSecretIssuer wires the bundled admin token-issuer into a
// server via WithTokenIssuer. The issuer accepts only loopback callers; non-
// loopback peers receive HTTP 403. A real deployment supplies a non-nil
// TokenStore so issued tokens persist.
func ExampleNewAdminSecretIssuer() {
	iss := rift.NewAdminSecretIssuer("change-me", nil, time.Hour, rift.NopLogger())
	_ = iss
	fmt.Println("ok")
	// Output: ok
}
