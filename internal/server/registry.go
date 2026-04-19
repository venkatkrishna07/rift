package server

import (
	crand    "crypto/rand"
	"encoding/binary"
	"errors"
	mathrand "math/rand"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"github.com/venkatkrishna07/rift/internal/proto"
)

// ErrSubdomainTaken is returned by RegisterHTTP when the subdomain is already
// claimed by an active tunnel.
var ErrSubdomainTaken = errors.New("subdomain already in use")

// ErrPortsExhausted is returned by RegisterTCP when no free port can be found
// in the configured TCP port range.
var ErrPortsExhausted = errors.New("no TCP ports available in configured range")

const maxVisitors = 50

// Tunnel holds the metadata for a registered tunnel.
type Tunnel struct {
	ID        uint32
	Subdomain string // set for HTTP tunnels
	Port      uint16 // set for TCP tunnels
	Proto     string // "http" or "tcp"
	Conn      *quic.Conn
	visitors  atomic.Int64
}

// TryAddVisitor increments the visitor count if below maxVisitors.
// Returns false if the tunnel is at capacity — caller must NOT call VisitorDone.
func (t *Tunnel) TryAddVisitor() bool {
	if t.visitors.Add(1) > maxVisitors {
		t.visitors.Add(-1)
		return false
	}
	return true
}

// VisitorDone decrements the visitor count. Must be called exactly once per
// successful TryAddVisitor call, typically via defer.
func (t *Tunnel) VisitorDone() { t.visitors.Add(-1) }

// Registry is a thread-safe store of active tunnels.
type Registry struct {
	mu       sync.RWMutex
	byID     map[uint32]*Tunnel
	bySubdom map[string]*Tunnel
	byPort   map[uint16]*Tunnel
	portMin  uint16
	portMax  uint16
}

// NewRegistry returns an empty Registry using the given TCP port range.
// portMin and portMax are inclusive. Pass 0 for both to use the defaults
// (10000–65535).
func NewRegistry(portMin, portMax uint16) *Registry {
	if portMin == 0 {
		portMin = 10000
	}
	if portMax == 0 {
		portMax = 65535
	}
	return &Registry{
		byID:     make(map[uint32]*Tunnel),
		bySubdom: make(map[string]*Tunnel),
		byPort:   make(map[uint16]*Tunnel),
		portMin:  portMin,
		portMax:  portMax,
	}
}

// RegisterHTTP registers an HTTP tunnel. Returns ErrSubdomainTaken if the
// subdomain is already active, preventing tunnel hijacking by re-registration.
func (r *Registry) RegisterHTTP(subdomain string, conn *quic.Conn) (*Tunnel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.bySubdom[subdomain]; exists {
		return nil, ErrSubdomainTaken
	}
	t := &Tunnel{ID: r.nextID(), Subdomain: subdomain, Proto: proto.ProtoHTTP, Conn: conn}
	r.byID[t.ID] = t
	r.bySubdom[subdomain] = t
	return t, nil
}

// RegisterTCP registers a TCP tunnel with a unique random port in [10000, 65535].
// Returns ErrPortsExhausted if no free port can be found.
func (r *Registry) RegisterTCP(conn *quic.Conn) (*Tunnel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	rangeSize := int(r.portMax-r.portMin) + 1
	if len(r.byPort) >= rangeSize {
		return nil, ErrPortsExhausted
	}

	for i := 0; i < 100; i++ {
		p := r.portMin + uint16(mathrand.Intn(rangeSize)) //nolint:gosec // random port selection, not security-sensitive
		if _, used := r.byPort[p]; !used {
			t := &Tunnel{ID: r.nextID(), Port: p, Proto: proto.ProtoTCP, Conn: conn}
			r.byID[t.ID] = t
			r.byPort[p] = t
			return t, nil
		}
	}
	return nil, ErrPortsExhausted
}

// BySubdomain returns the tunnel for subdomain, or nil.
func (r *Registry) BySubdomain(subdomain string) *Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bySubdom[subdomain]
}

// ByID returns the tunnel with id, or nil.
func (r *Registry) ByID(id uint32) *Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

// Unregister removes the tunnel with id.
func (r *Registry) Unregister(id uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.byID[id]
	if !ok {
		return
	}
	delete(r.byID, id)
	if t.Subdomain != "" {
		delete(r.bySubdom, t.Subdomain)
	}
	if t.Port != 0 {
		delete(r.byPort, t.Port)
	}
}

// nextID returns a non-zero uint32 not currently in use, generated via
// crypto/rand. Must be called with mu held.
func (r *Registry) nextID() uint32 {
	var b [4]byte
	for {
		if _, err := crand.Read(b[:]); err != nil {
			// crypto/rand is a kernel interface; failure is unrecoverable.
			panic("crypto/rand unavailable: " + err.Error())
		}
		id := binary.BigEndian.Uint32(b[:])
		if id == 0 {
			continue
		}
		if _, exists := r.byID[id]; !exists {
			return id
		}
	}
}
