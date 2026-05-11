package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"github.com/venkatkrishna07/rift/internal/proto"
)

// ErrSubdomainTaken is returned by RegisterHTTP when the subdomain is already
// claimed by an active tunnel.
var ErrSubdomainTaken = errors.New("rift: subdomain already in use")

// ErrPortsExhausted is returned by RegisterTCP when no free port can be found
// in the configured TCP port range.
var ErrPortsExhausted = errors.New("rift: no TCP ports available in configured range")

// ErrTunnelGone is returned by Tunnel.OpenDataStream when the underlying
// rift-client QUIC connection has already closed.
var ErrTunnelGone = errors.New("rift: tunnel connection closed")

// DefaultMaxVisitorsPerTunnel is the fallback when ServerConfig leaves the
// limit at zero. Picked to bound per-tunnel goroutines without choking on
// typical short-lived HTTP storms.
const DefaultMaxVisitorsPerTunnel int64 = 50

// Tunnel holds the metadata for a registered tunnel.
type Tunnel struct {
	ID             uint32
	Subdomain      string // set for HTTP tunnels
	Port           uint16 // set for TCP tunnels
	Proto          string // "http", "tcp", or "wt"
	Conn           *quic.Conn
	AllowedOrigins []string // WT tunnels: permitted Origin header values; "*" = any
	maxVisitors    int64
	visitors       atomic.Int64
}

// TryAddVisitor increments the visitor count if below the per-tunnel cap.
// Returns false if the tunnel is at capacity — caller must NOT call VisitorDone.
func (t *Tunnel) TryAddVisitor() bool {
	limit := t.maxVisitors
	if limit <= 0 {
		limit = DefaultMaxVisitorsPerTunnel
	}
	if t.visitors.Add(1) > limit {
		t.visitors.Add(-1)
		return false
	}
	return true
}

// VisitorDone decrements the visitor count. Must be called exactly once per
// successful TryAddVisitor call, typically via defer.
func (t *Tunnel) VisitorDone() { t.visitors.Add(-1) }

// OpenDataStream opens a QUIC stream on the rift-client side of the tunnel.
// Returns ErrTunnelGone if the underlying connection has already been closed
// — callers should treat this as a recoverable "tunnel unregistered" case
// rather than a generic stream-open failure.
func (t *Tunnel) OpenDataStream(ctx context.Context) (*quic.Stream, error) {
	if err := t.Conn.Context().Err(); err != nil {
		return nil, ErrTunnelGone
	}
	stream, err := t.Conn.OpenStreamSync(ctx)
	if err != nil {
		if errors.Is(t.Conn.Context().Err(), context.Canceled) {
			return nil, ErrTunnelGone
		}
		return nil, err
	}
	return stream, nil
}

// Registry is a thread-safe store of active tunnels.
type Registry struct {
	mu          sync.RWMutex
	byID        map[uint32]*Tunnel
	bySubdom    map[string]*Tunnel
	byPort      map[uint16]*Tunnel
	portMin     uint16
	portMax     uint16
	maxVisitors int64
}

// NewRegistry returns an empty Registry using the given TCP port range and
// per-tunnel visitor cap. portMin and portMax are inclusive (0 → 10000/65535
// defaults). maxVisitors of 0 falls back to DefaultMaxVisitorsPerTunnel.
func NewRegistry(portMin, portMax uint16, maxVisitors int64) *Registry {
	if portMin == 0 {
		portMin = 10000
	}
	if portMax == 0 {
		portMax = 65535
	}
	return &Registry{
		byID:        make(map[uint32]*Tunnel),
		bySubdom:    make(map[string]*Tunnel),
		byPort:      make(map[uint16]*Tunnel),
		portMin:     portMin,
		portMax:     portMax,
		maxVisitors: maxVisitors,
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
	t := &Tunnel{ID: r.nextID(), Subdomain: subdomain, Proto: proto.ProtoHTTP, Conn: conn, maxVisitors: r.maxVisitors}
	r.byID[t.ID] = t
	r.bySubdom[subdomain] = t
	return t, nil
}

// RegisterWT registers a WebTransport tunnel under subdomain. Shares the
// subdomain namespace with HTTP tunnels — ErrSubdomainTaken on collision.
// allowedOrigins is the per-tunnel cross-origin allow-list; empty means
// reject all cross-origin requests, "*" matches any.
func (r *Registry) RegisterWT(subdomain string, conn *quic.Conn, allowedOrigins []string) (*Tunnel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.bySubdom[subdomain]; exists {
		return nil, ErrSubdomainTaken
	}
	t := &Tunnel{
		ID:             r.nextID(),
		Subdomain:      subdomain,
		Proto:          proto.ProtoWT,
		Conn:           conn,
		AllowedOrigins: append([]string(nil), allowedOrigins...),
		maxVisitors:    r.maxVisitors,
	}
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
		n, err := rand.Int(rand.Reader, big.NewInt(int64(rangeSize)))
		if err != nil {
			panic("crypto/rand unavailable: " + err.Error())
		}
		p := r.portMin + uint16(n.Int64())
		if _, used := r.byPort[p]; !used {
			t := &Tunnel{ID: r.nextID(), Port: p, Proto: proto.ProtoTCP, Conn: conn, maxVisitors: r.maxVisitors}
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
		if _, err := rand.Read(b[:]); err != nil {
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
