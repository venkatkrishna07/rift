package rift_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/venkatkrishna07/rift"
)

// TestServerConfigHasNoAdminSecret is a compile-time/runtime guard that
// AdminSecret is not exposed on the curated ServerConfig. Token issuance must
// be wired via WithTokenIssuer + NewAdminSecretIssuer.
func TestServerConfigHasNoAdminSecret(t *testing.T) {
	t.Parallel()
	rt := reflect.TypeOf(rift.ServerConfig{})
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).Name == "AdminSecret" {
			t.Fatalf("rift.ServerConfig must not expose AdminSecret; use WithTokenIssuer")
		}
	}
}

// TestWithTokenIssuerIsAccepted verifies WithTokenIssuer composes with the
// other options on a dev-mode server without error. This is the only public
// path to enable token issuance.
func TestWithTokenIssuerIsAccepted(t *testing.T) {
	t.Parallel()
	tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
	if err != nil {
		t.Fatalf("DevTLSConfig: %v", err)
	}
	iss := rift.NewAdminSecretIssuer("s3cret", stubTokenStore{}, time.Hour, rift.NopLogger())
	if iss == nil {
		t.Fatal("NewAdminSecretIssuer returned nil")
	}

	srv, err := rift.NewServer(rift.ServerConfig{
		Domain:     "tunnel.localhost",
		ListenAddr: "127.0.0.1:0",
		Dev:        true,
	},
		rift.WithTLSConfig(tlsCfg),
		rift.WithLogger(rift.NopLogger()),
		rift.WithTokenStore(stubTokenStore{}),
		rift.WithTokenIssuer(iss),
	)
	if err != nil {
		t.Fatalf("NewServer with WithTokenIssuer: %v", err)
	}
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
}
