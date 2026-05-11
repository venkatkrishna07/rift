// Package server implements the rift QUIC tunnel server.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
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
	shutdownInvoked bool

	addrMu    sync.RWMutex
	boundAddr net.Addr

	issuerMu sync.RWMutex
	issuer   TokenIssuer

	regRL *perIPLimiter // per-token-name registration rate limiter

	wtOnce sync.Once
	wt     *wtServer
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

// Run starts the QUIC listener and HTTPS server, blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{})
	s.lifecycleMu.Lock()
	s.cancel = cancel
	s.done = done
	s.shutdownInvoked = false
	s.lifecycleMu.Unlock()
	defer close(done)

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
			// Datagrams are enabled for the WT path but the rift-v1 protocol
			// does not consume them. Drain unconditionally so an authenticated
			// client cannot flood unread datagrams into quic-go's per-conn
			// queue.
			go drainDatagrams(connCtx, conn)
			h.run(connCtx)
		})
	}
}


// drainDatagrams silently discards QUIC datagrams on a rift-v1 connection so
// they cannot accumulate in quic-go's per-connection queue. The rift-v1
// protocol never sends or expects datagrams; we keep them enabled at the
// transport level only because the WebTransport server requires them.
func drainDatagrams(ctx context.Context, conn *quic.Conn) {
	for ctx.Err() == nil {
		if _, err := conn.ReceiveDatagram(ctx); err != nil {
			return
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
