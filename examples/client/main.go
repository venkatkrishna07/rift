// Example: embed a rift tunnel client in your own Go program.
//
// Usage:
//
//	go run ./examples/client -server 127.0.0.1:4443 -token rift_xxx -local 3000 -name myapp
//
// Pair with examples/server. For dev mode against a self-signed server,
// pass -insecure (and -ack-insecure when the server is non-loopback).
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/venkatkrishna07/rift"
)

func main() {
	server := flag.String("server", "127.0.0.1:4443", "rift server host:port")
	token := flag.String("token", "", "auth token; required outside dev mode")
	local := flag.Int("local", 3000, "local TCP port to forward")
	name := flag.String("name", "app", "tunnel name (subdomain for HTTP)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (dev only)")
	ackInsecure := flag.Bool("ack-insecure", false, "acknowledge -insecure against non-loopback server")
	flag.Parse()

	logger := rift.SlogAdapter(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cli, err := rift.NewClient(rift.ClientConfig{
		Server:              *server,
		Token:               *token,
		Tunnels:             []rift.TunnelSpec{{LocalPort: uint16(*local), Proto: rift.ProtoHTTP, Name: *name}},
		Insecure:            *insecure,
		AcknowledgeInsecure: *ackInsecure,
		Protocol:            rift.ProtocolRift,
	}, rift.WithClientLogger(logger))
	if err != nil {
		log.Fatalf("new client: %v", err)
	}
	defer cli.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("rift client connecting to %s (forward localhost:%d -> %s)", *server, *local, *name)
	if err := cli.Connect(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("client exited: %v", err)
	}
}
