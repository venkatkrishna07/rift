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

func TestCheckInsecureFlagsForceInsecureAccepted(t *testing.T) {
	err := checkInsecureFlags(true, true, "external.example.com")
	if err != nil {
		t.Errorf("expected nil with forceInsecure=true, got: %v", err)
	}
}

func TestCheckInsecureFlagsLocalhostNoForce(t *testing.T) {
	err := checkInsecureFlags(true, false, "localhost")
	if err != nil {
		t.Errorf("localhost+insecure should pass without forceInsecure, got: %v", err)
	}
}

func TestCheckInsecureFlagsNonLocalhostNoForce(t *testing.T) {
	err := checkInsecureFlags(true, false, "external.example.com")
	if err == nil {
		t.Error("expected error for non-localhost without forceInsecure")
	}
}

func TestCheckInsecureFlagsNotInsecure(t *testing.T) {
	err := checkInsecureFlags(false, false, "any.host.com")
	if err != nil {
		t.Errorf("insecure=false should always pass, got: %v", err)
	}
}
