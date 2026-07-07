package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/worker"
)

// defaultDgramIdleTimeout is how long a per-session UDP forwarder may sit
// without any activity before the sweeper closes it. Generous so realistic
// long-poll style WT visitors are not evicted; bounded so a fast-reconnect
// attacker cannot leak FDs forever.
const defaultDgramIdleTimeout = 5 * time.Minute

// dgramKey identifies a single visitor session on a tunnel. The pair
// (tunnel, session) is sufficient because session IDs are allocated
// per-tunnel on the server side.
type dgramKey struct {
	tunnel  uint32
	session uint32
}

// dgramForwarder pairs a UDP socket with the tunnel + session it serves.
// A goroutine reads datagrams from the socket and forwards each one back
// to the server, prefixed with the same envelope used by the server's
// outbound path so the visitor receives the bytes on the same session.
type dgramForwarder struct {
	tunnelID  uint32
	sessionID uint32
	udp       *net.UDPConn
	once      sync.Once
	// lastActive is the most recent nanosecond timestamp at which a
	// datagram flowed in either direction through this forwarder. The
	// sweeper uses it to evict idle entries so a fast disconnect-
	// reconnect attacker cannot leak FDs.
	lastActive atomic.Int64
}

func (f *dgramForwarder) touch() {
	f.lastActive.Store(time.Now().UnixNano())
}

// datagramRouter owns the per-session UDP forwarder map for one rift-client
// connection. Visitor sessions allocate forwarders lazily on first inbound
// datagram. Forwarders are closed when the router itself is closed; idle
// eviction is not implemented in v0.1.1 — sessions naturally drop their
// forwarder when the visitor session ends and the UDP write target
// disappears, at which point read errors close the socket.
type datagramRouter struct {
	log         *zap.Logger
	idleTimeout time.Duration

	mu       sync.Mutex
	tunnels  map[uint32]uint16 // tunnelID -> local UDP port for that tunnel
	sessions map[dgramKey]*dgramForwarder
	closed   bool

	stopSweeper chan struct{}
	stopOnce    sync.Once
}

func newDatagramRouter(log *zap.Logger) *datagramRouter {
	r := &datagramRouter{
		log:         log,
		idleTimeout: defaultDgramIdleTimeout,
		tunnels:     make(map[uint32]uint16),
		sessions:    make(map[dgramKey]*dgramForwarder),
		stopSweeper: make(chan struct{}),
	}
	go r.sweep()
	return r
}

// sweep periodically evicts forwarders idle for longer than idleTimeout.
// Exits when Close() closes stopSweeper.
func (r *datagramRouter) sweep() {
	interval := r.idleTimeout / 5
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopSweeper:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-r.idleTimeout).UnixNano()
			r.mu.Lock()
			for key, f := range r.sessions {
				if f.lastActive.Load() < cutoff {
					f.once.Do(func() { _ = f.udp.Close() })
					delete(r.sessions, key)
				}
			}
			r.mu.Unlock()
		}
	}
}

// RegisterTunnel records that tunnelID forwards datagrams to localhost:port.
// Sessions allocate a private UDP socket each, all pointing at the same
// target port.
func (r *datagramRouter) RegisterTunnel(tunnelID uint32, port uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tunnels[tunnelID] = port
}

// getOrOpen looks up the forwarder for (tunnelID, sessionID) and returns it.
// On miss, the router opens a fresh UDP socket, spawns the upstream copy
// goroutine, and remembers the entry. Returns nil if the tunnel is unknown
// or if the router has been closed.
func (r *datagramRouter) getOrOpen(ctx context.Context, conn *quic.Conn, tunnelID, sessionID uint32, workers *worker.Group) *dgramForwarder {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	port, ok := r.tunnels[tunnelID]
	if !ok {
		r.mu.Unlock()
		return nil
	}
	key := dgramKey{tunnel: tunnelID, session: sessionID}
	if f, ok := r.sessions[key]; ok {
		r.mu.Unlock()
		return f
	}
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		r.mu.Unlock()
		r.log.Error("dial local UDP for WT datagrams",
			zap.Uint32("tunnel_id", tunnelID),
			zap.Uint32("session_id", sessionID),
			zap.Uint16("port", port),
			zap.Error(err),
		)
		return nil
	}
	f := &dgramForwarder{tunnelID: tunnelID, sessionID: sessionID, udp: udpConn}
	f.touch()
	r.sessions[key] = f
	r.mu.Unlock()

	workers.Go(fmt.Sprintf("udp-to-quic-%d-%d", tunnelID, sessionID), func() {
		r.udpToQUIC(ctx, conn, f)
	})
	return f
}

// udpToQUIC reads packets from the per-session UDP socket and forwards
// each as a QUIC datagram tagged with [tunnelID:4][sessionID:4][payload].
// Returns when ctx is cancelled, the socket closes, or the QUIC connection
// fails to accept a datagram.
func (r *datagramRouter) udpToQUIC(ctx context.Context, conn *quic.Conn, f *dgramForwarder) {
	defer r.closeSession(f)
	// Reused across reads: SendDatagram copies the slice before queueing.
	frame := make([]byte, 8+1500)
	binary.BigEndian.PutUint32(frame[:4], f.tunnelID)
	binary.BigEndian.PutUint32(frame[4:8], f.sessionID)
	for ctx.Err() == nil {
		n, err := f.udp.Read(frame[8:])
		if err != nil {
			return
		}
		f.touch()
		if err := conn.SendDatagram(frame[:8+n]); err != nil {
			r.log.Debug("send datagram",
				zap.Uint32("tunnel_id", f.tunnelID),
				zap.Uint32("session_id", f.sessionID),
				zap.Int("len", 8+n),
				zap.Error(err),
			)
			return
		}
	}
}

// closeSession closes the per-session UDP socket and removes the entry
// from the router. Safe to call multiple times.
func (r *datagramRouter) closeSession(f *dgramForwarder) {
	f.once.Do(func() {
		_ = f.udp.Close()
	})
	r.mu.Lock()
	delete(r.sessions, dgramKey{tunnel: f.tunnelID, session: f.sessionID})
	r.mu.Unlock()
}

// Close shuts down every forwarder, stops the idle sweeper, and prevents
// new allocations. Safe to call multiple times.
func (r *datagramRouter) Close() {
	r.stopOnce.Do(func() { close(r.stopSweeper) })
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	sessions := r.sessions
	r.sessions = nil
	r.mu.Unlock()
	for _, f := range sessions {
		f.once.Do(func() {
			_ = f.udp.Close()
		})
	}
}
