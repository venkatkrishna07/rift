// Example: embed a rift tunnel server in your own Go program.
//
// Usage:
//
//	go run ./examples/server -domain tunnel.localhost -listen 127.0.0.1:4443
//
// The server runs in dev mode with a self-signed wildcard cert for
// *.<domain>. Token auth is disabled. Connect a client with -insecure.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/venkatkrishna07/rift"
)

func main() {
	domain := flag.String("domain", "tunnel.localhost", "base domain for HTTP tunnels")
	listen := flag.String("listen", "127.0.0.1:4443", "QUIC + HTTPS listen address")
	flag.Parse()

	logger := rift.SlogAdapter(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	tlsCfg, err := rift.DevTLSConfig(*domain)
	if err != nil {
		log.Fatalf("dev TLS: %v", err)
	}

	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     *domain,
		ListenAddr: *listen,
		Dev:        true,
	},
		rift.WithTLSConfig(tlsCfg),
		rift.WithLogger(logger),
	)
	if err != nil {
		log.Fatalf("new server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("rift server listening on %s (domain=%s)", *listen, *domain)
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("server exited: %v", err)
	}
}
