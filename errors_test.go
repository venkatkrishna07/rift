package rift_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/venkatkrishna07/rift"
)

func TestSentinelsAreErrors(t *testing.T) {
	var _ error = rift.ErrSubdomainTaken
	var _ error = rift.ErrPortsExhausted
	var _ error = rift.ErrAuthFailed
	var _ error = rift.ErrTokenExpired
	var _ error = rift.ErrIPBlocked
}

func TestSentinelsHaveDistinctIdentities(t *testing.T) {
	all := []error{
		rift.ErrSubdomainTaken,
		rift.ErrPortsExhausted,
		rift.ErrAuthFailed,
		rift.ErrTokenExpired,
		rift.ErrIPBlocked,
	}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if errors.Is(all[i], all[j]) {
				t.Fatalf("sentinels %v and %v collide", all[i], all[j])
			}
		}
	}
}

func TestWrappedAuthFailedMatchesPublicSentinel(t *testing.T) {
	wrapped := fmt.Errorf("%w: bad token", rift.ErrAuthFailed)
	if !errors.Is(wrapped, rift.ErrAuthFailed) {
		t.Fatalf("errors.Is should match wrapped ErrAuthFailed")
	}
}
