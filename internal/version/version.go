// Package version exposes build-time version metadata injected via -ldflags.
package version

import "fmt"

// These variables are overridden at link time:
//
//	go build -ldflags "-X github.com/venkatkrishna07/rift/internal/version.Version=v1.0.0 \
//	                   -X github.com/venkatkrishna07/rift/internal/version.Commit=abc1234  \
//	                   -X github.com/venkatkrishna07/rift/internal/version.Date=2026-04-15"
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns the full human-readable version string.
func String() string {
	return fmt.Sprintf("rift %s (commit %s, built %s)", Version, Commit, Date)
}
