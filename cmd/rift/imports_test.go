package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoInternalImportsInMain enforces the architectural invariant that the
// CLI consumes the rift library through the public rift package only. The
// single allowed internal import is internal/version, which holds CLI-only
// build metadata.
func TestNoInternalImportsInMain(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	banned := regexp.MustCompile(`^"github\.com/venkatkrishna07/rift/internal/(client|server|config|proto|store)"$`)
	for _, imp := range f.Imports {
		if banned.MatchString(imp.Path.Value) {
			t.Errorf("forbidden internal import: %s", imp.Path.Value)
		}
	}
}

// TestNoEnvReadInInternalClient asserts the library no longer reads
// RIFT_FORCE_INSECURE from the process environment. CLI-only concern.
func TestNoEnvReadInInternalClient(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "client", "client.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if strings.Contains(string(b), `os.Getenv("RIFT_FORCE_INSECURE")`) {
		t.Errorf("internal/client/client.go still reads RIFT_FORCE_INSECURE from env")
	}
}

// TestNoStderrWriteInInternalStore asserts the badger store no longer writes
// to os.Stderr. Library code must use the supplied logger.
func TestNoStderrWriteInInternalStore(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "store", "badger.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if strings.Contains(string(b), "os.Stderr") {
		t.Errorf("internal/store/badger.go still references os.Stderr")
	}
}
