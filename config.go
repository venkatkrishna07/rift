package rift

import (
	"time"

	"github.com/venkatkrishna07/rift/internal/config"
)

// Defaults applied when the corresponding config field is zero.
const (
	DefaultMaxBodyBytes  = config.DefaultMaxBodyBytes
	DefaultStreamTimeout = config.DefaultStreamTimeout
	DefaultMaxTotalConns = config.DefaultMaxTotalConns
	DefaultTokenTTL      = config.DefaultTokenTTL
	DefaultTCPPortMin    = config.DefaultTCPPortMin
	DefaultTCPPortMax    = config.DefaultTCPPortMax

	// DefaultMaxIncomingStreams caps QUIC streams per connection. 1000 matches
	// the upstream quic-go default and keeps memory bounded under aggressive
	// reverse-direction stream creation.
	DefaultMaxIncomingStreams int64 = 1000
)

// Wire protocols accepted in ClientConfig.Protocol.
const (
	ProtocolRift = config.ProtocolRift
	ProtocolMCP  = config.ProtocolMCP
)

// Tunnel proto values accepted in TunnelSpec.Proto.
const (
	ProtoHTTP = "http"
	ProtoTCP  = "tcp"
	// ProtoWT routes browser WebTransport sessions on a subdomain to a local
	// TCP service. Visitor traffic is HTTP/3 only (UDP/443, ALPN "h3").
	ProtoWT = "wt"
)

// ServerConfig configures a rift tunnel server. Zero values for optional
// fields fall back to package defaults; use the Effective* accessors to
// observe the resolved value.
//
// AdminSecret is intentionally not a field on the curated surface — supply
// a TokenIssuer via the WithTokenIssuer option (added in a later phase) to
// enable token-provisioning endpoints.
type ServerConfig struct {
	Domain             string
	ListenAddr         string
	ACMEAddr           string
	Dev                bool
	DBPath             string
	MaxBodyBytes       int64
	StreamTimeout      time.Duration
	MaxTotalConns      int
	TCPPortMin         uint16
	TCPPortMax         uint16
	TokenTTL           time.Duration
	MaxIncomingStreams int64
	// MaxVisitorsPerTunnel caps the number of in-flight visitors against a
	// single tunnel. Zero falls back to a built-in default (currently 50).
	MaxVisitorsPerTunnel int64
}

// EffectiveMaxBodyBytes returns MaxBodyBytes when set, else DefaultMaxBodyBytes.
func (c ServerConfig) EffectiveMaxBodyBytes() int64 {
	if c.MaxBodyBytes > 0 {
		return c.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

// EffectiveStreamTimeout returns StreamTimeout when set, else DefaultStreamTimeout.
func (c ServerConfig) EffectiveStreamTimeout() time.Duration {
	if c.StreamTimeout > 0 {
		return c.StreamTimeout
	}
	return DefaultStreamTimeout
}

// EffectiveMaxTotalConns returns MaxTotalConns when set, else DefaultMaxTotalConns.
func (c ServerConfig) EffectiveMaxTotalConns() int {
	if c.MaxTotalConns > 0 {
		return c.MaxTotalConns
	}
	return DefaultMaxTotalConns
}

// EffectiveTCPPortMin returns TCPPortMin when set, else DefaultTCPPortMin.
func (c ServerConfig) EffectiveTCPPortMin() uint16 {
	if c.TCPPortMin > 0 {
		return c.TCPPortMin
	}
	return DefaultTCPPortMin
}

// EffectiveTCPPortMax returns TCPPortMax when set, else DefaultTCPPortMax.
func (c ServerConfig) EffectiveTCPPortMax() uint16 {
	if c.TCPPortMax > 0 {
		return c.TCPPortMax
	}
	return DefaultTCPPortMax
}

// EffectiveMaxIncomingStreams returns MaxIncomingStreams when set, else
// DefaultMaxIncomingStreams.
func (c ServerConfig) EffectiveMaxIncomingStreams() int64 {
	if c.MaxIncomingStreams > 0 {
		return c.MaxIncomingStreams
	}
	return DefaultMaxIncomingStreams
}

// toInternal projects the curated ServerConfig onto the internal/config
// representation.
//
// AdminSecret is deliberately left blank — token issuance is wired via
// WithTokenIssuer, not this struct.
func (c ServerConfig) toInternal() config.ServerConfig {
	return config.ServerConfig{
		Domain:             c.Domain,
		ListenAddr:         c.ListenAddr,
		ACMEAddr:           c.ACMEAddr,
		Dev:                c.Dev,
		DBPath:             c.DBPath,
		MaxBodyBytes:       c.MaxBodyBytes,
		StreamTimeout:      c.StreamTimeout,
		MaxTotalConns:      c.MaxTotalConns,
		TCPPortMin:         c.TCPPortMin,
		TCPPortMax:         c.TCPPortMax,
		TokenTTL:           c.TokenTTL,
		MaxIncomingStreams:   c.EffectiveMaxIncomingStreams(),
		MaxVisitorsPerTunnel: c.MaxVisitorsPerTunnel,
	}
}

// ClientConfig configures a rift tunnel client.
//
// Insecure disables TLS certificate verification. AcknowledgeInsecure must
// also be true to use Insecure=true against a non-loopback Server; the
// client otherwise refuses to dial. This replaces the historical
// RIFT_FORCE_INSECURE environment variable, so the opt-in lives on the
// config object instead of process state.
type ClientConfig struct {
	Server              string
	Token               string
	Tunnels             []TunnelSpec
	Insecure            bool
	AcknowledgeInsecure bool
	DBPath              string
	StreamTimeout       time.Duration
	Protocol            string
}

func (c ClientConfig) EffectiveStreamTimeout() time.Duration {
	if c.StreamTimeout > 0 {
		return c.StreamTimeout
	}
	return DefaultStreamTimeout
}

func (c ClientConfig) toInternal() config.ClientConfig {
	internal := config.ClientConfig{
		Server:        c.Server,
		Token:         c.Token,
		Insecure:      c.Insecure,
		ForceInsecure: c.AcknowledgeInsecure,
		DBPath:        c.DBPath,
		StreamTimeout: c.StreamTimeout,
		Protocol:      c.Protocol,
	}
	internal.Tunnels = make([]config.TunnelSpec, len(c.Tunnels))
	for i, t := range c.Tunnels {
		internal.Tunnels[i] = config.TunnelSpec{
			LocalPort:          t.LocalPort,
			DatagramLocalPort:  t.DatagramLocalPort,
			Proto:              t.Proto,
			Name:               t.Name,
			AllowedOrigins:     append([]string(nil), t.AllowedOrigins...),
			AllowedWTProtocols: append([]string(nil), t.AllowedWTProtocols...),
		}
	}
	return internal
}

// TunnelSpec describes one tunnel registration on the client side.
type TunnelSpec struct {
	// LocalPort is the loopback TCP port the client forwards to.
	LocalPort uint16
	// DatagramLocalPort is the loopback UDP port the client forwards
	// WebTransport datagrams to. Only honoured when Proto == ProtoWT;
	// zero disables datagram forwarding entirely.
	DatagramLocalPort uint16
	// Proto is the tunnel transport. Must be ProtoHTTP, ProtoTCP, or ProtoWT;
	// other values are rejected by the server at registration time.
	Proto string
	// Name is an optional subdomain (HTTP/WT) or label (TCP). When empty the
	// server allocates one — a random subdomain or a free port.
	Name string
	// AllowedOrigins gates cross-origin browser access for WT tunnels. Empty
	// rejects every cross-origin request (only same-origin allowed); "*"
	// matches any origin. Ignored for non-WT tunnels.
	AllowedOrigins []string
	// AllowedWTProtocols enumerates the WebTransport subprotocols the
	// tunnel is willing to negotiate. Browsers request via
	// `new WebTransport(url, {protocols: [...]})`; rift echoes the chosen
	// value via the WT-Protocol response header. Empty accepts whatever
	// the browser sends (or none). Ignored for non-WT tunnels.
	AllowedWTProtocols []string
}
