package server

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestProdTLSConfig_CreatesCacheDirWith0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	cfg, h := ProdTLSConfig("tunnel.example.com", dir, zap.NewNop())
	if cfg == nil || h == nil {
		t.Fatalf("nil components")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("cache dir perms = %04o, want 0700", mode)
	}
}

func TestProdTLSConfig_WarnsOnLoosePerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "loose-certs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	core, recorded := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	ProdTLSConfig("tunnel.example.com", dir, logger)

	entries := recorded.All()
	if len(entries) == 0 {
		t.Fatal("expected at least one warn entry")
	}
	found := false
	for _, e := range entries {
		if strings.Contains(e.Message, "loose permissions") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("did not see loose-permissions warning; got: %+v", entries)
	}
}

func TestProdTLSConfig_NilLoggerNoPanic(t *testing.T) {
	dir := t.TempDir()
	cfg, h := ProdTLSConfig("tunnel.example.com", dir, nil)
	if cfg == nil || h == nil {
		t.Fatal("nil components with nil logger")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want TLS13", cfg.MinVersion)
	}
}
