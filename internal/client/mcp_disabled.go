//go:build !mcp

package client

import (
	"context"
	"errors"
)

// ErrMCPNotCompiled is returned when the binary was built without the `mcp`
// build tag and the user requests Protocol=mcp at runtime. Rebuild with
// `go build -tags mcp` to enable the MCP wire protocol.
var ErrMCPNotCompiled = errors.New("MCP support not compiled in; rebuild with -tags mcp")

// connectMCP is the no-op stub used when the `mcp` build tag is absent.
// The dispatch site in client.go calls this; it returns immediately so the
// caddy-mcp package is never imported by default builds.
func (c *Client) connectMCP(_ context.Context, _, _ string) error {
	return ErrMCPNotCompiled
}
