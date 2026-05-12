// Package version exposes build-time version metadata injected via -ldflags.
package version

import (
	"fmt"
	"runtime"
)

// These variables are overridden at link time:
//
//	go build -ldflags "-X github.com/venkatkrishna07/rift/cmd/rift/internal/version.Version=v1.0.0 \
//	                   -X github.com/venkatkrishna07/rift/cmd/rift/internal/version.Date=2026-04-15"
var (
	Version = "dev"
	Date    = "unknown"
)

// String returns the full human-readable version string.
func String() string {
	return fmt.Sprintf("rift %s (built %s, %s/%s, %s)",
		Version, Date, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
