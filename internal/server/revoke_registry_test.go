package server

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestRevokeRegistry_RegisterFiresCallbackOnRevoke(t *testing.T) {
	r := NewRevokeRegistry()
	var fired atomic.Int32
	r.Register("alice", func() { fired.Add(1) })
	if n := r.Revoke("alice"); n != 1 {
		t.Errorf("Revoke returned %d, want 1", n)
	}
	if fired.Load() != 1 {
		t.Errorf("callback fired %d times, want 1", fired.Load())
	}
}

func TestRevokeRegistry_RevokeUnknownReturnsZero(t *testing.T) {
	r := NewRevokeRegistry()
	if n := r.Revoke("ghost"); n != 0 {
		t.Errorf("Revoke ghost returned %d, want 0", n)
	}
}

func TestRevokeRegistry_UnregisterRemovesCallback(t *testing.T) {
	r := NewRevokeRegistry()
	var fired atomic.Int32
	unreg := r.Register("alice", func() { fired.Add(1) })
	unreg()
	if r.Count("alice") != 0 {
		t.Errorf("Count after unregister = %d, want 0", r.Count("alice"))
	}
	if n := r.Revoke("alice"); n != 0 {
		t.Errorf("Revoke after unregister returned %d, want 0", n)
	}
	if fired.Load() != 0 {
		t.Errorf("callback fired after unregister")
	}
}

func TestRevokeRegistry_UnregisterIdempotent(t *testing.T) {
	r := NewRevokeRegistry()
	unreg := r.Register("alice", func() {})
	unreg()
	unreg()
}

func TestRevokeRegistry_MultipleCallbacksPerName(t *testing.T) {
	r := NewRevokeRegistry()
	var fired atomic.Int32
	for i := 0; i < 5; i++ {
		r.Register("alice", func() { fired.Add(1) })
	}
	if n := r.Revoke("alice"); n != 5 {
		t.Errorf("Revoke returned %d, want 5", n)
	}
	if fired.Load() != 5 {
		t.Errorf("callbacks fired %d times, want 5", fired.Load())
	}
}

func TestRevokeRegistry_ConcurrentRegisterAndRevoke(t *testing.T) {
	r := NewRevokeRegistry()
	var fired atomic.Int32
	const N = 200

	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			unreg := r.Register("alice", func() { fired.Add(1) })
			_ = unreg
		}()
	}
	wg.Wait()

	got := r.Revoke("alice")
	if got != N {
		t.Errorf("Revoke returned %d, want %d", got, N)
	}
	if fired.Load() != int32(N) {
		t.Errorf("fired = %d, want %d", fired.Load(), N)
	}
}
