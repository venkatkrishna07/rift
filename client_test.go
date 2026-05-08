package rift_test

import (
	"testing"

	"github.com/venkatkrishna07/rift"
)

func TestNewClient(t *testing.T) {
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
	if cli == nil {
		t.Fatal("NewClient returned nil")
	}
}
