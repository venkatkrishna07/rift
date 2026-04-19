package server

import (
	"errors"
	"testing"
)

func TestRegisterHTTPCollision(t *testing.T) {
	r := NewRegistry(0, 0)

	tun, err := r.RegisterHTTP("myapp", nil)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	if tun == nil {
		t.Fatal("expected non-nil tunnel on first registration")
	}

	_, err = r.RegisterHTTP("myapp", nil)
	if !errors.Is(err, ErrSubdomainTaken) {
		t.Fatalf("expected ErrSubdomainTaken on collision, got: %v", err)
	}
}

func TestRegisterHTTPDifferentSubdomains(t *testing.T) {
	r := NewRegistry(0, 0)
	if _, err := r.RegisterHTTP("app1", nil); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if _, err := r.RegisterHTTP("app2", nil); err != nil {
		t.Fatalf("second registration: %v", err)
	}
}

func TestUnregisterFreesSubdomain(t *testing.T) {
	r := NewRegistry(0, 0)
	tun, err := r.RegisterHTTP("myapp", nil)
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	r.Unregister(tun.ID)

	if _, err := r.RegisterHTTP("myapp", nil); err != nil {
		t.Fatalf("re-registration after unregister failed: %v", err)
	}
}

func TestNextIDNonZeroAndUnique(t *testing.T) {
	r := NewRegistry(0, 0)
	seen := make(map[uint32]struct{}, 1000)
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < 1000; i++ {
		id := r.nextID()
		if id == 0 {
			t.Fatalf("nextID returned 0 at iteration %d", i)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("nextID returned duplicate %d at iteration %d", id, i)
		}
		seen[id] = struct{}{}
		r.byID[id] = &Tunnel{ID: id} // mark used so nextID won't re-pick it
	}
}
