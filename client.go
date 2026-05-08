package rift

import (
	"context"
	"errors"

	"github.com/venkatkrishna07/rift/internal/client"
)

// Client is a tunnel client. Construct with NewClient; call Connect to dial
// and serve, and Close to shut down.
//
// A Client is single-use: after Close it must not be reused. Construct a
// fresh Client for each lifecycle.
//
// All exported methods (Connect, Close) are safe for concurrent use from
// multiple goroutines. The typical pattern is to call Connect from one
// goroutine and Close from a signal handler.
type Client struct {
	inner *client.Client
}

// NewClient constructs a tunnel client.
//
// Required:
//   - cfg.Server
//   - cfg.Tunnels (at least one entry)
//
// Defaults:
//   - When WithClientLogger is omitted, NopLogger is used.
//
// Returns an error for misconfiguration; never panics.
func NewClient(cfg ClientConfig, opts ...ClientOption) (*Client, error) {
	if cfg.Server == "" {
		return nil, errors.New("rift: ClientConfig.Server is required")
	}
	if len(cfg.Tunnels) == 0 {
		return nil, errors.New("rift: ClientConfig.Tunnels must contain at least one tunnel")
	}
	if cfg.Protocol == ProtocolMCP && len(cfg.Tunnels) > 1 {
		return nil, errors.New("rift: MCP protocol supports a single tunnel per connection")
	}

	o := clientOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	if o.logger == nil {
		o.logger = NopLogger()
	}

	inner := client.New(cfg.toInternal(), o.tokenStore, zapFromLogger(o.logger))
	return &Client{inner: inner}, nil
}

// Connect dials the server and reconnects with exponential backoff. Blocks
// until ctx is cancelled, Close is called, or a permanent server error is
// returned. Returns nil on clean shutdown.
func (c *Client) Connect(ctx context.Context) error { return c.inner.Connect(ctx) }

// Close cancels an in-flight Connect and waits for it to return. Returns
// nil on clean shutdown or a timeout error if Connect does not return within
// 5 seconds. Idempotent: subsequent calls return nil.
//
// A Client is single-use: do not call Connect again after Close. Construct
// a fresh Client for each lifecycle. Safe to call before Connect (no-op,
// returns nil).
func (c *Client) Close() error { return c.inner.Close() }
