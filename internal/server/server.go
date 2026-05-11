// Package server implements the rift QUIC tunnel server.
package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
	"golang.org/x/time/rate"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/venkatkrishna07/rift/internal/config"
	"github.com/venkatkrishna07/rift/internal/store"
	"github.com/venkatkrishna07/rift/internal/worker"
)

const maxConnsPerIP = 5

// Server is the rift tunnel server.
type Server struct {
	cfg         config.ServerConfig
	ts          store.TokenStore // nil in dev mode
	reg         *Registry
	revokes     *RevokeRegistry
	tlsCfg      *tls.Config
	acmeHandler http.Handler // non-nil in prod mode; serves HTTP-01 ACME challenges on :80
	log         *zap.Logger
	wg          *worker.Group
	rl          *rateLimiter
	connMu      sync.Mutex
	connByIP    map[string]int // IP -> active connection count; guarded by connMu
	totalConns  atomic.Int64

	// Lifecycle plumbing. cancel and done are populated by Run; Shutdown
	// reads them. shutdownInvoked distinguishes a Shutdown-triggered exit from
	// a parent-ctx-triggered exit so Run can return the correct error.
	// issuer can be set with SetTokenIssuer at construction time before Run;
	// serveHTTPS reads it via tokenIssuer() and dispatches matching requests.
	lifecycleMu     sync.Mutex
	cancel          context.CancelFunc
	done            chan struct{}
	runCtx          context.Context
	shutdownInvoked bool

	addrMu    sync.RWMutex
	boundAddr net.Addr

	issuerMu sync.RWMutex
	issuer   TokenIssuer

	regRL *perIPLimiter // per-token-name registration rate limiter

	wtOnce sync.Once
	wt     *wtServer

	// wtVisitorsByIP caps concurrent WT sessions per source IP. Mirrors
	// the per-IP QUIC connection cap, applied at the WT layer where a
	// single QUIC conn can multiplex many WT sessions.
	wtVisitorsMu   sync.Mutex
	wtVisitorsByIP map[string]int
}

// maxWTSessionsPerIP caps concurrent WebTransport sessions a single source
// IP may open against this server. Picked to be lenient for legitimate
// reload-heavy development while bounding a single attacker.
const maxWTSessionsPerIP = 20

// allowWTVisitor increments the per-IP WT visitor count for ip and reports
// whether the new total is within the cap. Mirrors allowConn's semantics
// for ordinary QUIC connections.
func (s *Server) allowWTVisitor(ip string) bool {
	s.wtVisitorsMu.Lock()
	defer s.wtVisitorsMu.Unlock()
	if s.wtVisitorsByIP == nil {
		s.wtVisitorsByIP = make(map[string]int)
	}
	if s.wtVisitorsByIP[ip] >= maxWTSessionsPerIP {
		return false
	}
	s.wtVisitorsByIP[ip]++
	return true
}

// releaseWTVisitor decrements the per-IP WT visitor count and removes the
// entry when it reaches zero so the map does not grow unbounded.
func (s *Server) releaseWTVisitor(ip string) {
	s.wtVisitorsMu.Lock()
	defer s.wtVisitorsMu.Unlock()
	if s.wtVisitorsByIP == nil {
		return
	}
	s.wtVisitorsByIP[ip]--
	if s.wtVisitorsByIP[ip] <= 0 {
		delete(s.wtVisitorsByIP, ip)
	}
}

// New constructs a Server. ts may be nil when cfg.Dev is true.
// acmeHandler may be nil; when set it is served on cfg.ACMEAddr for HTTP-01 challenges.
func New(cfg config.ServerConfig, ts store.TokenStore, tlsCfg *tls.Config, acmeHandler http.Handler, log *zap.Logger) *Server {
	l := log.With(zap.String("component", "server"))
	return &Server{
		cfg:         cfg,
		ts:          ts,
		reg:         NewRegistry(cfg.EffectiveTCPPortMin(), cfg.EffectiveTCPPortMax(), cfg.EffectiveMaxVisitorsPerTunnel()),
		revokes:     NewRevokeRegistry(),
		regRL:       newPerIPLimiter(rate.Every(12*time.Second), 5, time.Hour),
		tlsCfg:      tlsCfg,
		acmeHandler: acmeHandler,
		log:         l,
		wg:          worker.New(l),
		rl:          newRateLimiter(),
		connByIP:    make(map[string]int),
	}
}

// Revokes returns the revocation registry. The admin handler uses this to
// fire revoke callbacks for connections currently using a deleted token.
func (s *Server) Revokes() *RevokeRegistry { return s.revokes }

// startWTDispatcher spawns the per-conn datagram demuxer the first time
// this rift-client connection registers a WT tunnel. Subsequent calls are
// no-ops thanks to sync.Once.
func (h *connHandler) startWTDispatcher() {
	h.dgramOnce.Do(func() {
		conn := h.conn
		ctx := h.connCtx
		log := h.log
		reg := h.reg
		h.workers.Go(fmt.Sprintf("dispatch-dgrams-%s", conn.RemoteAddr()), func() {
			dispatchClientDatagrams(ctx, conn, reg, log)
		})
	})
}

// runCtxDone returns the channel that fires when Server.Run's supervisor
// context is cancelled. nil before Run starts and after Run exits.
func (s *Server) runCtxDone() <-chan struct{} {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.runCtx == nil {
		return nil
	}
	return s.runCtx.Done()
}

// Run starts the QUIC listener and HTTPS server, blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{})
	s.lifecycleMu.Lock()
	s.cancel = cancel
	s.done = done
	s.runCtx = runCtx
	s.shutdownInvoked = false
	s.lifecycleMu.Unlock()
	defer func() {
		s.lifecycleMu.Lock()
		s.runCtx = nil
		s.lifecycleMu.Unlock()
		close(done)
	}()

	// QUIC TLS advertises both rift's tunnel protocol and HTTP/3 so a single
	// UDP socket carries rift clients and WebTransport visitors. The
	// negotiated ALPN is inspected after the handshake to dispatch.
	quicTLS := s.tlsCfg.Clone()
	quicTLS.NextProtos = []string{"rift-v1", "h3"}

	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("bind UDP %s: %w", s.cfg.ListenAddr, err)
	}
	s.addrMu.Lock()
	s.boundAddr = udpConn.LocalAddr()
	s.addrMu.Unlock()
	defer func() {
		s.addrMu.Lock()
		s.boundAddr = nil
		s.addrMu.Unlock()
	}()

	// quic.Transport gives us direct control over the UDP socket.
	// VerifySourceAddress enables QUIC Retry for every new connection —
	// adds one round-trip but prevents UDP amplification attacks.
	tr := &quic.Transport{
		Conn:                 udpConn,
		VerifySourceAddress:  func(net.Addr) bool { return true },
	}
	ln, err := tr.Listen(quicTLS, &quic.Config{
		MaxIdleTimeout:                   30 * time.Second,
		KeepAlivePeriod:                  15 * time.Second,
		MaxIncomingStreams:               s.cfg.MaxIncomingStreams,
		Allow0RTT:                        false,
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
	})
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("QUIC listen: %w", err)
	}
	s.log.Info("QUIC listener started", zap.String("addr", s.cfg.ListenAddr))

	httpsTLS := s.tlsCfg.Clone()
	httpsTLS.NextProtos = append([]string{"h2", "http/1.1"}, httpsTLS.NextProtos...)
	httpsTLS.MinVersion = tls.VersionTLS12 // HTTPS accepts TLS 1.2+; QUIC enforces 1.3 via quicTLS

	eg, egCtx := errgroup.WithContext(runCtx)
	eg.Go(func() error { return s.acceptLoop(egCtx, ln) })
	eg.Go(func() error { return s.serveHTTPS(egCtx, httpsTLS) })
	if s.acmeHandler != nil {
		eg.Go(func() error { return s.serveACMEHTTP(egCtx) })
	}
	eg.Go(func() error {
		<-egCtx.Done()
		_ = ln.Close()
		_ = udpConn.Close()
		return nil
	})

	waitErr := eg.Wait()
	s.wg.Wait()  // drain per-connection goroutines first
	s.rl.Stop()  // then stop rate-limiter cleanup (no handlers can call RecordFailure after this)

	// All connection handlers have returned, so every counter should already
	// be zero. Clear explicitly to drop residual map entries and harden against
	// any future code path that might leak a slot.
	s.clearConnByIP()

	if waitErr != nil && runCtx.Err() == nil {
		// runCtx is the local supervisor context — if it's not cancelled, the
		// error came from a component failure rather than a graceful shutdown.
		return waitErr
	}
	// runCtx cancelled. Distinguish a Shutdown-triggered exit (return nil)
	// from a parent-ctx-triggered exit (surface ctx.Err so callers can
	// detect clean shutdown vs a real failure).
	s.lifecycleMu.Lock()
	shutdown := s.shutdownInvoked
	s.lifecycleMu.Unlock()
	if shutdown {
		return nil
	}
	return ctx.Err()
}

// Shutdown cancels Run's supervisor context and waits for it to exit.
// Returns ctx.Err() if the supplied context expires before Run returns.
// Calling Shutdown before Run is safe — it is a no-op until Run populates
// the lifecycle channels.
func (s *Server) Shutdown(ctx context.Context) error {
	s.lifecycleMu.Lock()
	cancel := s.cancel
	done := s.done
	if cancel != nil && done != nil {
		s.shutdownInvoked = true
	}
	s.lifecycleMu.Unlock()
	if cancel == nil || done == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Addr returns the bound UDP listener address, or nil before Run binds it.
// Safe to call concurrently.
func (s *Server) Addr() net.Addr {
	s.addrMu.RLock()
	defer s.addrMu.RUnlock()
	return s.boundAddr
}

// SetTokenIssuer stores the issuer that will be served before tunnel routing
// once Run starts the HTTPS listener. Must be called before Run; later calls
// take effect on the next Run cycle.
//
// When iss is an *AdminSecretIssuer, the server's revoke registry is wired
// into it so DELETE /_admin/tokens/:name fires active-connection callbacks.
func (s *Server) SetTokenIssuer(iss TokenIssuer) {
	s.issuerMu.Lock()
	s.issuer = iss
	s.issuerMu.Unlock()
	if a, ok := iss.(*AdminSecretIssuer); ok {
		a.SetRevokes(s.revokes)
		a.SetAuthRL(s.rl)
		a.SetTrustProxyHeaders(s.cfg.TrustProxyHeaders)
	}
}

func (s *Server) tokenIssuer() TokenIssuer {
	s.issuerMu.RLock()
	defer s.issuerMu.RUnlock()
	return s.issuer
}

// acceptLoop accepts QUIC connections and dispatches a connHandler per connection.
func (s *Server) acceptLoop(ctx context.Context, ln *quic.Listener) error {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Error("QUIC accept error", zap.Error(err))
			return fmt.Errorf("accept: %w", err)
		}
		ip := extractIP(conn.RemoteAddr())
		maxTotal := int64(s.cfg.EffectiveMaxTotalConns())
		if s.totalConns.Load() >= maxTotal {
			s.log.Warn("global connection limit reached — rejecting connection",
				zap.String("ip", ip),
				zap.Int64("current", s.totalConns.Load()),
				zap.Int64("max", maxTotal),
			)
			_ = conn.CloseWithError(1, "server at capacity")
			continue
		}
		if !s.allowConn(ip) {
			s.log.Warn("per-IP connection limit reached",
				zap.String("ip", ip),
				zap.Int("max", maxConnsPerIP),
				zap.Error(fmt.Errorf("%w: %s exceeded %d concurrent conns", ErrIPBlocked, ip, maxConnsPerIP)),
			)
			_ = conn.CloseWithError(1, "too many connections from your IP")
			continue
		}
		h := &connHandler{
			conn:          conn,
			ts:            s.ts,
			reg:           s.reg,
			revokes:       s.revokes,
			regRL:         s.regRL,
			dev:           s.cfg.Dev,
			domain:        s.cfg.Domain,
			workers:       s.wg,
			log:           s.log,
			rl:            s.rl,
			streamTimeout: s.cfg.EffectiveStreamTimeout(),
			allowLowPorts: s.cfg.AllowLowLocalPorts,
		}
		s.totalConns.Add(1)
		s.wg.Go(fmt.Sprintf("conn-%s", conn.RemoteAddr()), func() {
			defer s.totalConns.Add(-1)
			defer s.releaseConn(ip)
			// Defence-in-depth: don't process any stream before 1-RTT handshake confirms
			// client liveness. Guards against replayed 0-RTT control streams.
			select {
			case <-conn.HandshakeComplete():
			case <-ctx.Done():
				return
			}
			// Dispatch by negotiated ALPN: "rift-v1" is the tunnel protocol;
			// "h3" hands the connection to the WebTransport server.
			alpn := conn.ConnectionState().TLS.NegotiatedProtocol
			if alpn == "h3" {
				s.serveWebTransport(ctx, conn)
				return
			}
			connCtx, connCancel := context.WithCancel(ctx)
			defer connCancel()
			context.AfterFunc(conn.Context(), connCancel)
			// The WT datagram dispatcher is started lazily on the first
			// `register wt` from this connection (see conn.go). Skipping the
			// spawn for non-WT clients avoids an idle goroutine on every
			// HTTP/TCP-only connection.
			h.connCtx = connCtx
			h.run(connCtx)
		})
	}
}


// dispatchClientDatagrams reads QUIC datagrams from a rift-client connection
// and routes each one to the exact WebTransport session whose ID is carried
// in bytes [4:8] of the wire envelope. The tunnel must be owned by this
// QUIC connection — cross-connection injection is rejected. Frames too
// short, with an unknown tunnel, an unknown session, or a non-WT tunnel
// are dropped silently — quic-go's per-conn queue stays drained either way.
//
// Wire format: [tunnelID:4 BE][sessionID:4 BE][payload...].
func dispatchClientDatagrams(ctx context.Context, conn *quic.Conn, reg *Registry, log *zap.Logger) {
	for ctx.Err() == nil {
		msg, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(msg) < 8 {
			continue
		}
		tunnelID := binary.BigEndian.Uint32(msg[:4])
		sessionID := binary.BigEndian.Uint32(msg[4:8])
		payload := msg[8:]
		tun := reg.ByID(tunnelID)
		if tun == nil || tun.Proto != "wt" || tun.Conn != conn {
			// Tunnel-ownership check: only the rift-client that owns the
			// tunnel may send datagrams targeting it. Closes the cross-
			// tunnel injection vector.
			continue
		}
		v := tun.GetWTSession(sessionID)
		if v == nil {
			continue
		}
		sess, ok := v.(*webtransport.Session)
		if !ok {
			continue
		}
		if err := sess.SendDatagram(payload); err != nil {
			log.Debug("wt session datagram dropped",
				zap.Uint32("tunnel_id", tunnelID),
				zap.Uint32("session_id", sessionID),
				zap.Int("len", len(payload)),
				zap.Error(err),
			)
		}
	}
}

// allowConn increments the connection count for ip and returns true if below the limit.
func (s *Server) allowConn(ip string) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.connByIP[ip] >= maxConnsPerIP {
		return false
	}
	s.connByIP[ip]++
	return true
}

// releaseConn decrements the connection count for ip and removes the map entry when it hits zero.
func (s *Server) releaseConn(ip string) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.connByIP[ip]--
	if s.connByIP[ip] <= 0 {
		delete(s.connByIP, ip)
	}
}

// clearConnByIP resets the per-IP counter map. Called from Run after all
// connection handlers have returned.
func (s *Server) clearConnByIP() {
	s.connMu.Lock()
	s.connByIP = make(map[string]int)
	s.connMu.Unlock()
}

// extractIP returns just the host portion of a net.Addr.
func extractIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
