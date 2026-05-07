package rift

import (
	"github.com/venkatkrishna07/rift/internal/config"
	"github.com/venkatkrishna07/rift/internal/proto"
	"github.com/venkatkrishna07/rift/internal/server"
	"github.com/venkatkrishna07/rift/internal/store"
)

// ServerConfig configures a tunnel server.
type ServerConfig = config.ServerConfig

// ClientConfig configures a tunnel client.
type ClientConfig = config.ClientConfig

// TunnelSpec describes one tunnel registration on the client side.
type TunnelSpec = config.TunnelSpec

// TokenStore is the persistence interface required by NewServer (auth)
// and optionally by NewClient (token caching).
type TokenStore = store.TokenStore

// TokenIssuer is the HTTP-route interface for token provisioning endpoints
// such as /_admin/tokens. Implement to add custom auth flows.
type TokenIssuer = server.TokenIssuer

// Default values applied when the corresponding config field is zero.
const (
	DefaultMaxBodyBytes  = config.DefaultMaxBodyBytes
	DefaultStreamTimeout = config.DefaultStreamTimeout
	DefaultMaxTotalConns = config.DefaultMaxTotalConns
	DefaultTokenTTL      = config.DefaultTokenTTL
	DefaultTCPPortMin    = config.DefaultTCPPortMin
	DefaultTCPPortMax    = config.DefaultTCPPortMax
)

// Wire protocols accepted in ClientConfig.Protocol.
const (
	ProtocolRift = config.ProtocolRift
	ProtocolMCP  = config.ProtocolMCP
)

// Tunnel proto values accepted in TunnelSpec.Proto.
const (
	ProtoHTTP = proto.ProtoHTTP
	ProtoTCP  = proto.ProtoTCP
)
