package client

import (
	"testing"
)

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"127.0.0.2", true},
		{"192.168.1.1", false},
		{"example.com", false},
		{"10.0.0.1", false},
	}
	for _, tc := range tests {
		if got := isLocalhost(tc.host); got != tc.want {
			t.Errorf("isLocalhost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestCheckInsecureFlagsForceInsecureNoEnv(t *testing.T) {
	t.Setenv("RIFT_FORCE_INSECURE", "")
	err := checkInsecureFlags(true, true, "external.example.com")
	if err == nil {
		t.Error("expected error when RIFT_FORCE_INSECURE unset, got nil")
	}
}

func TestCheckInsecureFlagsForceInsecureWithEnv(t *testing.T) {
	t.Setenv("RIFT_FORCE_INSECURE", "yes")
	err := checkInsecureFlags(true, true, "external.example.com")
	if err != nil {
		t.Errorf("expected nil with RIFT_FORCE_INSECURE=yes, got: %v", err)
	}
}

func TestCheckInsecureFlagsLocalhostNoForce(t *testing.T) {
	t.Setenv("RIFT_FORCE_INSECURE", "")
	err := checkInsecureFlags(true, false, "localhost")
	if err != nil {
		t.Errorf("localhost+insecure should not require env var, got: %v", err)
	}
}

func TestCheckInsecureFlagsNonLocalhostNoForce(t *testing.T) {
	t.Setenv("RIFT_FORCE_INSECURE", "")
	err := checkInsecureFlags(true, false, "external.example.com")
	if err == nil {
		t.Error("expected error for non-localhost without --force-insecure")
	}
}

func TestCheckInsecureFlagsNotInsecure(t *testing.T) {
	err := checkInsecureFlags(false, false, "any.host.com")
	if err != nil {
		t.Errorf("insecure=false should always pass, got: %v", err)
	}
}
