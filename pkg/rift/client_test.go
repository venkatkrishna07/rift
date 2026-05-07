package rift_test

import (
	"testing"

	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/pkg/rift"
)

func TestNewClient(t *testing.T) {
	cli := rift.NewClient(rift.ClientConfig{
		Server: "localhost:4443",
		Token:  "rift_test",
		Tunnels: []rift.TunnelSpec{
			{LocalPort: 3000, Proto: rift.ProtoHTTP, Name: "app"},
		},
		Insecure: true,
		Protocol: rift.ProtocolRift,
	}, nil, zap.NewNop())

	if cli == nil {
		t.Fatal("NewClient returned nil")
	}
}
