package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestOpenBadgerWarnsThroughLogger(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rift-loose-perm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	core, recorded := observer.New(zap.WarnLevel)
	log := zap.New(core)

	bs, err := OpenBadger(dir, log)
	if err != nil {
		t.Fatalf("OpenBadger: %v", err)
	}
	defer bs.Close()

	entries := recorded.All()
	if len(entries) == 0 {
		t.Fatal("expected at least one warn-level log entry, got none")
	}
	found := false
	for _, e := range entries {
		if strings.Contains(e.Message, "permissions") && strings.Contains(e.Message, "0700") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected permission warning, got entries: %+v", entries)
	}
}

func TestOpenBadgerNilLoggerNoPanic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rift-nil-logger")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bs, err := OpenBadger(dir, nil)
	if err != nil {
		t.Fatalf("OpenBadger nil logger: %v", err)
	}
	defer bs.Close()
}

func TestOpenBadgerReadOnlyAcceptsLogger(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rift-ro")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bs, err := OpenBadger(dir, zap.NewNop())
	if err != nil {
		t.Fatalf("OpenBadger: %v", err)
	}
	bs.Close()

	ro, err := OpenBadgerReadOnly(dir, zap.NewNop())
	if err != nil {
		t.Fatalf("OpenBadgerReadOnly: %v", err)
	}
	if ro != nil {
		ro.Close()
	}
}
