package rift

import (
	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/client"
)

// Client is a tunnel client; call (*Client).Connect(ctx) to dial and serve.
type Client = client.Client

// NewClient constructs a tunnel client.
//
//   - ts may be nil if the consumer supplies cfg.Token directly and does not
//     want token persistence.
//   - log is required (use zap.NewNop() if you don't want logging).
//
// Connect blocks. It reconnects with exponential backoff on transient errors
// and returns a non-nil error only for permanent failures (invalid token,
// expired token, blocked IP, context cancelled).
func NewClient(cfg ClientConfig, ts TokenStore, log *zap.Logger) *Client {
	return client.New(cfg, ts, log)
}
