package rift

import "testing"

func TestServerConfigToInternalMaxIncomingStreams(t *testing.T) {
	cfg := ServerConfig{Domain: "x", ListenAddr: "y", MaxIncomingStreams: 500}
	if got := cfg.toInternal().MaxIncomingStreams; got != 500 {
		t.Fatalf("explicit: got %d want 500", got)
	}
	zero := ServerConfig{Domain: "x", ListenAddr: "y"}
	if got := zero.toInternal().MaxIncomingStreams; got != 1000 {
		t.Fatalf("default: got %d want 1000", got)
	}
}
