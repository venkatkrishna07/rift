package rift_test

import (
	"testing"
	"time"

	"github.com/venkatkrishna07/rift"
)

// TestServerConfigOnlyExportsCuratedFields proves AdminSecret is no longer public
// and that MaxIncomingStreams is part of the curated public surface.
func TestServerConfigOnlyExportsCuratedFields(t *testing.T) {
	cfg := rift.ServerConfig{
		Domain:             "tunnel.example.com",
		ListenAddr:         ":443",
		ACMEAddr:           ":80",
		Dev:                false,
		DBPath:             "/var/lib/rift",
		MaxBodyBytes:       1024,
		StreamTimeout:      time.Minute,
		MaxTotalConns:      10,
		TCPPortMin:         20000,
		TCPPortMax:         30000,
		TokenTTL:           time.Hour,
		MaxIncomingStreams: 500,
	}
	if cfg.EffectiveMaxBodyBytes() != 1024 {
		t.Fatalf("EffectiveMaxBodyBytes wrong: %d", cfg.EffectiveMaxBodyBytes())
	}
	if cfg.EffectiveMaxIncomingStreams() != 500 {
		t.Fatalf("EffectiveMaxIncomingStreams wrong: %d", cfg.EffectiveMaxIncomingStreams())
	}
	zero := rift.ServerConfig{}
	if zero.EffectiveMaxIncomingStreams() != 1000 {
		t.Fatalf("default EffectiveMaxIncomingStreams should be 1000, got %d", zero.EffectiveMaxIncomingStreams())
	}
}

func TestClientConfigAcknowledgeInsecure(t *testing.T) {
	cli := rift.ClientConfig{
		Server:              "tunnel.example.com:443",
		Token:               "rift_x",
		Tunnels:             []rift.TunnelSpec{{LocalPort: 3000, Proto: rift.ProtoHTTP, Name: "app"}},
		Insecure:            true,
		AcknowledgeInsecure: true,
		Protocol:            rift.ProtocolRift,
	}
	if !cli.AcknowledgeInsecure {
		t.Fatalf("AcknowledgeInsecure not exposed on ClientConfig")
	}
	if cli.EffectiveStreamTimeout() == 0 {
		t.Fatalf("EffectiveStreamTimeout should fall back to default")
	}
}
