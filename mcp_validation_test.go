package rift_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/venkatkrishna07/rift"
)

func TestNewClientRejectsMCPMultiTunnel(t *testing.T) {
	_, err := rift.NewClient(rift.ClientConfig{
		Server: "x:1",
		Token:  "t",
		Tunnels: []rift.TunnelSpec{
			{LocalPort: 3000, Proto: rift.ProtoHTTP, Name: "a"},
			{LocalPort: 3001, Proto: rift.ProtoHTTP, Name: "b"},
		},
		Protocol: rift.ProtocolMCP,
	})
	if err == nil {
		t.Fatal("expected error for MCP + multi-tunnel, got nil")
	}
	if !strings.Contains(err.Error(), "MCP") && !strings.Contains(err.Error(), "mcp") {
		t.Fatalf("expected MCP-specific error, got %v", err)
	}
	_ = errors.Is // suppress unused if test compiles
}

// TestNewClientAcceptsMCPSingleTunnel exercises rift.NewClient validation
// only — it does not Connect. The success path is therefore identical on
// default builds and `-tags mcp` builds. On default builds, calling Connect()
// on the returned client would fail with ErrMCPNotCompiled (see
// internal/client/mcp_disabled.go); this test never reaches that point.
func TestNewClientAcceptsMCPSingleTunnel(t *testing.T) {
	cli, err := rift.NewClient(rift.ClientConfig{
		Server: "x:1",
		Token:  "t",
		Tunnels: []rift.TunnelSpec{
			{LocalPort: 3000, Proto: rift.ProtoHTTP, Name: "a"},
		},
		Protocol: rift.ProtocolMCP,
	})
	if err != nil {
		t.Fatalf("expected MCP+single-tunnel to succeed, got %v", err)
	}
	if cli == nil {
		t.Fatal("nil client")
	}
}
