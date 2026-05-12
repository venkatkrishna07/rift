package cliconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveConfigPath(t *testing.T) {
	t.Setenv("RIFT_CONFIG", "")

	if got := ResolveConfigPath("/explicit/path"); got != "/explicit/path" {
		t.Errorf("flag should win, got %q", got)
	}

	t.Setenv("RIFT_CONFIG", "/from/env")
	if got := ResolveConfigPath(""); got != "/from/env" {
		t.Errorf("env should be used when flag empty, got %q", got)
	}
	if got := ResolveConfigPath("/explicit/path"); got != "/explicit/path" {
		t.Errorf("flag should override env, got %q", got)
	}

	t.Setenv("RIFT_CONFIG", "")
	if got := ResolveConfigPath(""); got != "" {
		t.Errorf("expected empty when neither set, got %q", got)
	}
}

func TestLoadServerFile_EmptyPath(t *testing.T) {
	got, err := LoadServerFile("")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result, got %#v", got)
	}
}

func TestLoadServerFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.toml")
	body := `
[server]
domain = "tunnel.example.com"
listen = ":4443"
max-body-bytes = 1048576
stream-timeout = "10m"
max-conns = 50
tcp-port-min = 20000
tcp-port-max = 30000
token-ttl = "12h"

[tls]
cert = "/etc/ssl/cert.pem"
key  = "/etc/ssl/key.pem"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadServerFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Server.Domain != "tunnel.example.com" {
		t.Errorf("domain mismatch: %q", got.Server.Domain)
	}
	if got.Server.MaxBodyBytes != 1048576 {
		t.Errorf("max-body-bytes mismatch: %d", got.Server.MaxBodyBytes)
	}
	if got.Server.TCPPortMin != 20000 || got.Server.TCPPortMax != 30000 {
		t.Errorf("port range mismatch: %d-%d", got.Server.TCPPortMin, got.Server.TCPPortMax)
	}
	if got.TLS.Cert != "/etc/ssl/cert.pem" || got.TLS.Key != "/etc/ssl/key.pem" {
		t.Errorf("tls mismatch: %#v", got.TLS)
	}
}

func TestLoadServerFile_UnknownKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.toml")
	body := `
[server]
domian = "typo"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadServerFile(path)
	if err == nil {
		t.Fatal("expected error for unknown key, got nil")
	}
	if !strings.Contains(err.Error(), "domian") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

func TestLoadClientFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.toml")
	body := `
[client]
server   = "tunnel.example.com:4443"
insecure = true
protocol = "rift"

[[tunnels]]
local-port = 3000
proto      = "http"
name       = "myapp"

[[tunnels]]
local-port = 5432
proto      = "tcp"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadClientFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Client.Server != "tunnel.example.com:4443" {
		t.Errorf("server mismatch: %q", got.Client.Server)
	}
	if got.Client.Insecure == nil || *got.Client.Insecure != true {
		t.Errorf("insecure mismatch: %#v", got.Client.Insecure)
	}
	if len(got.Tunnels) != 2 {
		t.Fatalf("expected 2 tunnels, got %d", len(got.Tunnels))
	}
	if got.Tunnels[0].LocalPort != 3000 || got.Tunnels[0].Proto != "http" {
		t.Errorf("tunnel[0] mismatch: %#v", got.Tunnels[0])
	}
}

func TestParseDurationStr(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"5m", 5 * time.Minute, false},
		{"1h30m", 90 * time.Minute, false},
		{"500ms", 500 * time.Millisecond, false},
		{"not-a-duration", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseDurationStr(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseDurationStr(%q) expected error, got nil", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseDurationStr(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseDurationStr(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("UserHomeDir unavailable: %v", err)
	}
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
		{"~", home},
		{"~/sub/dir", filepath.Join(home, "sub/dir")},
		{"~user/x", "~user/x"},
	}
	for _, tt := range tests {
		if got := ExpandHome(tt.in); got != tt.want {
			t.Errorf("ExpandHome(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
