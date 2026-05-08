package server

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelsWrapWithErrorsIs(t *testing.T) {
	cases := []struct {
		name     string
		sentinel error
	}{
		{"ErrAuthFailed", ErrAuthFailed},
		{"ErrTokenExpired", ErrTokenExpired},
		{"ErrIPBlocked", ErrIPBlocked},
		{"ErrSubdomainTaken", ErrSubdomainTaken},
		{"ErrPortsExhausted", ErrPortsExhausted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := fmt.Errorf("%w: server-side context", tc.sentinel)
			if !errors.Is(wrapped, tc.sentinel) {
				t.Fatalf("errors.Is(%q, %v) = false; want true", wrapped.Error(), tc.sentinel)
			}
		})
	}
}

func TestSentinelsAreDistinct(t *testing.T) {
	all := []error{ErrAuthFailed, ErrTokenExpired, ErrIPBlocked, ErrSubdomainTaken, ErrPortsExhausted}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if errors.Is(all[i], all[j]) {
				t.Fatalf("internal sentinels collide: %v ↔ %v", all[i], all[j])
			}
		}
	}
}
