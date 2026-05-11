package server

import "testing"

// minimalServerForPerIP returns a Server with only the fields needed to drive
// the per-IP allow/release counter. Avoids standing up a real listener.
func minimalServerForPerIP() *Server {
	return &Server{connByIP: make(map[string]int)}
}

func TestAllowConnRespectsLimit(t *testing.T) {
	s := minimalServerForPerIP()
	const ip = "10.0.0.1"
	for i := 0; i < maxConnsPerIP; i++ {
		if !s.allowConn(ip) {
			t.Fatalf("expected allow at slot %d", i)
		}
	}
	if s.allowConn(ip) {
		t.Fatal("expected deny once limit reached")
	}
}

// TestPerIPCounterReleasedOnHandlerError simulates the contract used in
// acceptLoop: allow, then a handler that defers releaseConn and returns
// early via an error path. Counter must return to zero and the map entry
// must be removed.
func TestPerIPCounterReleasedOnHandlerError(t *testing.T) {
	s := minimalServerForPerIP()
	const ip = "10.0.0.1"
	if !s.allowConn(ip) {
		t.Fatal("expected initial allow")
	}
	func() {
		defer s.releaseConn(ip)
		// simulate a handshake failure path that returns immediately.
	}()
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if got, ok := s.connByIP[ip]; ok {
		t.Fatalf("expected map entry removed, got %d", got)
	}
}

// TestClearConnByIPEmptiesMap verifies the cleanup invoked on Run exit drops
// every entry, even if a slot somehow leaked.
func TestClearConnByIPEmptiesMap(t *testing.T) {
	s := minimalServerForPerIP()
	if !s.allowConn("10.0.0.1") {
		t.Fatal("expected allow")
	}
	if !s.allowConn("10.0.0.2") {
		t.Fatal("expected allow")
	}
	s.clearConnByIP()
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if len(s.connByIP) != 0 {
		t.Fatalf("expected empty map, got %d entries", len(s.connByIP))
	}
}

// TestPerIPCounterParallelReleases ensures repeated allow/release cycles
// keep the counter at zero with no residue.
func TestPerIPCounterParallelReleases(t *testing.T) {
	s := minimalServerForPerIP()
	const ip = "10.0.0.2"
	for i := 0; i < 100; i++ {
		if !s.allowConn(ip) {
			t.Fatalf("iter %d: unexpected deny", i)
		}
		s.releaseConn(ip)
	}
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if v, ok := s.connByIP[ip]; ok {
		t.Fatalf("counter leaked: %d", v)
	}
}
