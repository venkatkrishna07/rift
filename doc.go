// Package rift exposes the public Go library API for the rift QUIC tunnel.
//
// rift establishes an authenticated, multiplexed tunnel from a client behind
// NAT to a public server, exposing local HTTP services as subdomains and
// local TCP services as allocated ports on the server. The wire transport is
// QUIC; HTTPS is served alongside on the same UDP port via quic-go's HTTP/3
// stack.
//
// # Choosing library vs CLI
//
// Use the CLI at cmd/rift/ when you want a one-binary solution and the
// canonical command-line surface (config files, flags, env). Use this
// package when you embed rift inside another Go process — for example, a
// product that wants to expose the tunnel server alongside its own HTTP
// stack, or an agent that brings up a tunnel on demand.
//
// # Quick start
//
// Server:
//
//	srv, err := rift.NewServer(rift.ServerConfig{
//	    Domain:     "example.com",
//	    ListenAddr: ":443",
//	    ACMEAddr:   ":80",
//	},
//	    rift.WithTLSConfig(prodTLS),
//	    rift.WithACMEHandler(acmeHandler),
//	    rift.WithTokenStore(ts),
//	    rift.WithTokenIssuer(rift.NewAdminSecretIssuer(secret, ts, time.Hour, log)),
//	    rift.WithLogger(log),
//	)
//	if err != nil { /* ... */ }
//	if err := srv.Run(ctx); err != nil { /* ... */ }
//
// Client:
//
//	cli, err := rift.NewClient(rift.ClientConfig{
//	    Server:  "example.com:443",
//	    Token:   "rift_…",
//	    Tunnels: []rift.TunnelSpec{{LocalPort: 3000, Proto: rift.ProtoHTTP, Name: "app"}},
//	}, rift.WithClientLogger(log))
//	if err != nil { /* ... */ }
//	if err := cli.Connect(ctx); err != nil { /* ... */ }
//
// # Concurrency model
//
// Server and Client values are designed for single-use lifecycles: construct,
// run/connect once, then shut down. After Shutdown (server) or Close
// (client), do not call Run/Connect again — construct a fresh value.
//
// All public methods on Server and Client are safe to call concurrently from
// multiple goroutines. Typical patterns include calling Shutdown/Close from
// a signal handler while Run/Connect blocks in the main goroutine.
//
// All exported interfaces — TokenStore, TokenIssuer, Logger — must be
// implemented in a goroutine-safe fashion. The bundled BadgerStore,
// AdminSecretIssuer, SlogAdapter, and NopLogger satisfy this contract.
//
// Run returns context.Canceled (or DeadlineExceeded) when its context
// terminates; it does not swallow ctx.Err. Connect returns nil on clean
// shutdown via Close, and an error otherwise.
//
// # TLS guarantees
//
// QUIC enforces TLS 1.3 by protocol; rift relies on quic-go to negotiate it.
// The HTTP/3 fallback served on the same port inherits the same constraint.
// HTTPS served via the legacy net/http listener accepts TLS 1.2 and above.
//
// In dev mode, NewServer auto-generates a self-signed wildcard certificate
// for the configured domain when WithTLSConfig is omitted. Do not use dev
// mode in production.
//
// On the client, ClientConfig.Insecure disables certificate verification.
// The client refuses to dial against a non-loopback server with Insecure=true
// unless ClientConfig.AcknowledgeInsecure is also set, replacing the legacy
// RIFT_FORCE_INSECURE environment variable. When the bypass is active, the
// client logs a Warn-level "TLS verification disabled" entry on each dial.
//
// # Token storage threat model
//
// Authentication uses opaque bearer tokens in the form "rift_" + 64 hex
// characters (see GenerateToken). Tokens are persisted in a BadgerDB
// directory created with mode 0700 on first use. The supplied Logger
// receives a Warn-level entry when the database directory is found with
// looser permissions, alerting operators to weaken-by-mistake scenarios.
//
// Server side: TokenStore.Add stores the SHA-256 hash of the token. The
// raw token is never written to disk by the server; Validate compares
// hashes. Compromise of the server database does not leak issued tokens —
// the attacker can read a hash list, but cannot replay against the server
// without the original tokens.
//
// Client side: TokenStore.Save (used by WithClientTokenStore) persists the
// raw token in plaintext under the key client:<server-addr>. This is
// necessary because the client must replay the token verbatim on every
// reconnect. Operators who enable the client cache must restrict access to
// the data directory accordingly. Do not enable the client cache on shared
// or world-readable filesystems.
//
// # MCP support
//
// rift can carry Model Context Protocol traffic in addition to its native
// frame format. MCP support lives in the rift/mcp subpackage and is
// gated behind the "mcp" build tag so that consumers who do not need MCP
// avoid the upstream caddy-mcp transitive dependency:
//
//	go build -tags mcp ./...
//
// The protocol selector is ClientConfig.Protocol = ProtocolMCP; ProtocolRift
// is the default. MCP enforces a single tunnel per connection.
//
// # API stability
//
// Symbols in this package form the only stable surface exposed by this module.
// Anything under internal/ — or under rift/mcp prior to its first
// tagged release — may change without notice. Pin to a tag rather than
// main, and pair upgrades with a quick read of the CHANGELOG.
//
// # See also
//
//   - The CLI binary at cmd/rift/ wraps this package with flags and config.
//   - The hardening plan at docs/superpowers/plans/2026-05-08-rift-lib-hardening.md
//     records the design decisions behind the public surface.
package rift
