package cliconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// FileServer mirrors the TOML schema for server config files.
type FileServer struct {
	Server FileServerSection `toml:"server"`
	TLS    FileTLSSection    `toml:"tls"`
}

type FileServerSection struct {
	Domain        string `toml:"domain"`
	Listen        string `toml:"listen"`
	HTTP          string `toml:"http"`
	DB            string `toml:"db"`
	MaxBodyBytes  int64  `toml:"max-body-bytes"`
	StreamTimeout string `toml:"stream-timeout"`
	MaxConns      int    `toml:"max-conns"`
	TCPPortMin    uint16 `toml:"tcp-port-min"`
	TCPPortMax    uint16 `toml:"tcp-port-max"`
	TokenTTL      string `toml:"token-ttl"`
	AdminSecret   string `toml:"admin-secret"`
}

type FileTLSSection struct {
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

// FileClient mirrors the TOML schema for client config files.
type FileClient struct {
	Client  FileClientSection `toml:"client"`
	Tunnels []FileTunnel      `toml:"tunnels"`
}

type FileClientSection struct {
	Server        string `toml:"server"`
	Token         string `toml:"token"`
	DB            string `toml:"db"`
	Insecure      *bool  `toml:"insecure"`
	ForceInsecure *bool  `toml:"force-insecure"`
	StreamTimeout string `toml:"stream-timeout"`
	Protocol      string `toml:"protocol"`
}

type FileTunnel struct {
	LocalPort uint16 `toml:"local-port"`
	Proto     string `toml:"proto"`
	Name      string `toml:"name"`
}

// ResolveConfigPath returns the path to load. Precedence: --config flag,
// then $RIFT_CONFIG env var. Empty result means "no config file".
func ResolveConfigPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	return os.Getenv("RIFT_CONFIG")
}

// LoadServerFile decodes a server TOML file. Returns nil if path is empty.
// Unknown TOML keys are rejected to catch typos early.
func LoadServerFile(path string) (*FileServer, error) {
	if path == "" {
		return nil, nil
	}
	var f FileServer
	md, err := toml.DecodeFile(path, &f)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown keys in %s: %v", path, undecoded)
	}
	return &f, nil
}

// LoadClientFile decodes a client TOML file. Returns nil if path is empty.
// Unknown TOML keys are rejected to catch typos early.
func LoadClientFile(path string) (*FileClient, error) {
	if path == "" {
		return nil, nil
	}
	var f FileClient
	md, err := toml.DecodeFile(path, &f)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown keys in %s: %v", path, undecoded)
	}
	return &f, nil
}

// ParseDurationStr returns 0 if s is empty, else time.ParseDuration(s).
func ParseDurationStr(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("parse duration %q: %w", s, err)
	}
	return d, nil
}

// ExpandHome expands a leading "~" or "~/" in p to the user's home directory.
func ExpandHome(p string) string {
	if p == "" || !strings.HasPrefix(p, "~") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}
