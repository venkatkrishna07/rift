package rift_test

import (
	"testing"

	"github.com/venkatkrishna07/rift"
)

func TestNewClientErrorsOnEmptyTunnels(t *testing.T) {
	_, err := rift.NewClient(rift.ClientConfig{
		Server: "localhost:4443",
		Token:  "rift_test",
	})
	if err == nil {
		t.Fatal("expected error for empty Tunnels, got nil")
	}
}

func TestNewClientErrorsOnMissingServer(t *testing.T) {
	_, err := rift.NewClient(rift.ClientConfig{
		Token: "rift_test",
		Tunnels: []rift.TunnelSpec{
			{LocalPort: 3000, Proto: rift.ProtoHTTP, Name: "app"},
		},
	})
	if err == nil {
		t.Fatal("expected error for missing Server, got nil")
	}
}

func TestClientCloseIdempotent(t *testing.T) {
	cli, err := rift.NewClient(rift.ClientConfig{
		Server: "localhost:4443",
		Token:  "rift_test",
		Tunnels: []rift.TunnelSpec{
			{LocalPort: 3000, Proto: rift.ProtoHTTP, Name: "app"},
		},
		Insecure: true,
		Protocol: rift.ProtocolRift,
	}, rift.WithClientLogger(rift.NopLogger()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := cli.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
