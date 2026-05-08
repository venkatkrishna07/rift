//go:build !mcp

package rift_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDefaultBuildExcludesCaddyMCP asserts that a default build of the
// rift package (without -tags mcp) does NOT pull github.com/venkatkrishna07/caddy-mcp
// into the dependency graph. This is the contract for non-MCP consumers of the
// rift library: they should not transitively depend on caddy-mcp.
func TestDefaultBuildExcludesCaddyMCP(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/venkatkrishna07/rift").Output()
	if err != nil {
		t.Skipf("go list failed (likely sandboxed env): %v", err)
	}
	if strings.Contains(string(out), "venkatkrishna07/caddy-mcp") {
		t.Fatal("default build pulls in caddy-mcp; should require -tags mcp")
	}
}
