// Package config holds typed configuration structs for rift server and client.
package config

import "time"

// Defaults applied when the corresponding config field is zero.
const (
	// DefaultMaxBodyBytes is the maximum HTTP request or response body proxied
	// through an HTTP tunnel. 100 MiB matches common API gateway defaults.
	DefaultMaxBodyBytes int64 = 100 * 1024 * 1024

	// DefaultStreamTimeout is the data-stream idle timeout. A stream with no
	// bytes transferred for this duration is closed by the relay watchdog.
	DefaultStreamTimeout = 5 * time.Minute

	// DefaultMaxTotalConns is the server-wide cap on concurrent QUIC connections.
	DefaultMaxTotalConns = 500

	// DefaultTokenTTL is the default lifetime for provisioned tokens.
	DefaultTokenTTL = 1 * time.Hour

	// DefaultTCPPortMin / DefaultTCPPortMax define the port range from which
	// TCP tunnel ports are randomly allocated. Override with --tcp-port-min /
	// --tcp-port-max to restrict the range your firewall needs to open.
	DefaultTCPPortMin uint16 = 10000
	DefaultTCPPortMax uint16 = 65535

	// ProtocolRift is the default wire protocol for caddy-rift servers.
	ProtocolRift = "rift"
	// ProtocolMCP is the wire protocol for caddy-mcp servers.
	ProtocolMCP = "mcp"
)

// ServerConfig holds all server-side configuration.
type ServerConfig struct {
	ListenAddr    string        // e.g. ":443" — shared by QUIC (UDP) and HTTPS (TCP)
	ACMEAddr      string        // e.g. ":80"  — HTTP-01 ACME challenge listener (prod only)
	Domain        string        // base domain, e.g. "tunnel.example.com"
	Dev           bool          // dev mode: self-signed cert, no token auth
	DBPath        string        // BadgerDB data directory
	MaxBodyBytes  int64         // max HTTP body size; 0 → DefaultMaxBodyBytes
	StreamTimeout time.Duration // data stream idle timeout; 0 → DefaultStreamTimeout
	MaxTotalConns int           // max concurrent connections server-wide; 0 → DefaultMaxTotalConns
	TCPPortMin    uint16        // lower bound of TCP tunnel port range; 0 → DefaultTCPPortMin
	TCPPortMax    uint16        // upper bound of TCP tunnel port range; 0 → DefaultTCPPortMax
	AdminSecret   string        // bearer secret for /_admin/tokens; empty = endpoint disabled
	TokenTTL      time.Duration // default token lifetime; 0 = no expiry
}

// EffectiveMaxBodyBytes returns the configured limit or the package default.
func (c ServerConfig) EffectiveMaxBodyBytes() int64 {
	if c.MaxBodyBytes > 0 {
		return c.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

// EffectiveStreamTimeout returns the configured timeout or the package default.
func (c ServerConfig) EffectiveStreamTimeout() time.Duration {
	if c.StreamTimeout > 0 {
		return c.StreamTimeout
	}
	return DefaultStreamTimeout
}

// EffectiveMaxTotalConns returns the configured limit or the package default.
func (c ServerConfig) EffectiveMaxTotalConns() int {
	if c.MaxTotalConns > 0 {
		return c.MaxTotalConns
	}
	return DefaultMaxTotalConns
}

// EffectiveTCPPortMin returns the configured lower bound or the package default.
func (c ServerConfig) EffectiveTCPPortMin() uint16 {
	if c.TCPPortMin > 0 {
		return c.TCPPortMin
	}
	return DefaultTCPPortMin
}

// EffectiveTCPPortMax returns the configured upper bound or the package default.
func (c ServerConfig) EffectiveTCPPortMax() uint16 {
	if c.TCPPortMax > 0 {
		return c.TCPPortMax
	}
	return DefaultTCPPortMax
}

// ClientConfig holds all client-side configuration.
type ClientConfig struct {
	Server        string        // host or host:port of rift server
	Token         string        // auth token (overrides DB lookup when set)
	Tunnels       []TunnelSpec  // tunnels to register
	Insecure      bool          // skip TLS cert verification (dev mode only)
	ForceInsecure bool          // allow --insecure with non-localhost servers
	DBPath        string        // BadgerDB data directory for token persistence
	StreamTimeout time.Duration // data stream idle timeout; 0 → DefaultStreamTimeout
	Protocol      string        // "rift" (default) or "mcp"
}

// EffectiveStreamTimeout returns the configured timeout or the package default.
func (c ClientConfig) EffectiveStreamTimeout() time.Duration {
	if c.StreamTimeout > 0 {
		return c.StreamTimeout
	}
	return DefaultStreamTimeout
}

// TunnelSpec describes a single tunnel the client wants to expose.
type TunnelSpec struct {
	LocalPort uint16 // local TCP port to forward to
	Proto     string // "http" or "tcp"
	Name      string // optional human name; server picks subdomain/port if empty
}
