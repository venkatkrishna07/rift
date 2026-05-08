package rift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenBadgerStoreUsesLogger(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rift-pkg-loose")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cap := &captureLogger{}

	ts, err := OpenBadgerStore(dir, cap)
	if err != nil {
		t.Fatalf("OpenBadgerStore: %v", err)
	}
	defer ts.Close()

	cap.mu.Lock()
	entries := append([]capturedEntry(nil), cap.entries...)
	cap.mu.Unlock()

	found := false
	for _, e := range entries {
		if e.level == "warn" && strings.Contains(e.msg, "permissions") && strings.Contains(e.msg, "0700") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected warn-level permission log via Logger; got %+v", entries)
	}
}

func TestOpenBadgerStoreNilLogger(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rift-pkg-nil")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ts, err := OpenBadgerStore(dir, nil)
	if err != nil {
		t.Fatalf("OpenBadgerStore nil logger: %v", err)
	}
	ts.Close()
}

func TestOpenBadgerReadOnlyStoreAcceptsLogger(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rift-pkg-ro")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ts, err := OpenBadgerStore(dir, NopLogger())
	if err != nil {
		t.Fatalf("OpenBadgerStore: %v", err)
	}
	ts.Close()

	ro, err := OpenBadgerReadOnlyStore(dir, NopLogger())
	if err != nil {
		t.Fatalf("OpenBadgerReadOnlyStore: %v", err)
	}
	if ro != nil {
		ro.Close()
	}
}
