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
	tlsCfg      *tls.Config
	acmeHandler http.Handler // non-nil in prod mode; serves HTTP-01 ACME challenges on :80
	log         *zap.Logger
	wg          *worker.Group
	rl          *rateLimiter
	connByIP    sync.Map // string(IP) -> *atomic.Int64
	totalConns  atomic.Int64
}

// New constructs a Server. ts may be nil when cfg.Dev is true.
// acmeHandler may be nil; when set it is served on cfg.ACMEAddr for HTTP-01 challenges.
func New(cfg config.ServerConfig, ts store.TokenStore, tlsCfg *tls.Config, acmeHandler http.Handler, log *zap.Logger) *Server {
	l := log.With(zap.String("component", "server"))
	return &Server{
		cfg:         cfg,
		ts:          ts,
		reg:         NewRegistry(cfg.EffectiveTCPPortMin(), cfg.EffectiveTCPPortMax()),
		tlsCfg:      tlsCfg,
		acmeHandler: acmeHandler,
		log:         l,
		wg:          worker.New(l),
		rl:          newRateLimiter(),
	}
}

// Run starts the QUIC listener and HTTPS server, blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// QUIC TLS: only the rift ALPN — the HTTPS listener uses a separate clone.
	quicTLS := s.tlsCfg.Clone()
	quicTLS.NextProtos = []string{"rift-v1"}

	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("bind UDP %s: %w", s.cfg.ListenAddr, err)
	}

	// quic.Transport gives us direct control over the UDP socket.
	// VerifySourceAddress enables QUIC Retry for every new connection —
	// adds one round-trip but prevents UDP amplification attacks.
	tr := &quic.Transport{
		Conn:                 udpConn,
		VerifySourceAddress:  func(net.Addr) bool { return true },
	}
	ln, err := tr.Listen(quicTLS, &quic.Config{
		MaxIdleTimeout:    30 * time.Second,
		KeepAlivePeriod:   15 * time.Second,
		MaxIncomingStreams: 1000,
		Allow0RTT:         false,
	})
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("QUIC listen: %w", err)
	}
	s.log.Info("QUIC listener started", zap.String("addr", s.cfg.ListenAddr))

	httpsTLS := s.tlsCfg.Clone()
	httpsTLS.NextProtos = append([]string{"h2", "http/1.1"}, httpsTLS.NextProtos...)

	eg, egCtx := errgroup.WithContext(ctx)
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

	if err := eg.Wait(); err != nil && ctx.Err() == nil {
		// ctx is the original signal context — if it's not cancelled, the error
		// came from a component failure rather than a graceful shutdown signal.
		return err
	}
	s.rl.Stop()  // stop rate-limiter cleanup goroutine
	s.wg.Wait()  // drain per-connection goroutines
	return nil
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
			)
			_ = conn.CloseWithError(1, "too many connections from your IP")
			continue
		}
		h := &connHandler{
			conn:          conn,
			ts:            s.ts,
			reg:           s.reg,
			dev:           s.cfg.Dev,
			domain:        s.cfg.Domain,
			workers:       s.wg,
			log:           s.log,
			rl:            s.rl,
			streamTimeout: s.cfg.EffectiveStreamTimeout(),
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
			// Derive a context that cancels when the QUIC connection closes,
			// so all goroutines spawned for this connection (including TCP tunnels)
			// exit promptly when the client disconnects.
			connCtx, connCancel := context.WithCancel(ctx)
			defer connCancel()
			context.AfterFunc(conn.Context(), connCancel)
			h.run(connCtx)
		})
	}
}

// allowConn increments the connection count for ip and returns true if below the limit.
func (s *Server) allowConn(ip string) bool {
	v, _ := s.connByIP.LoadOrStore(ip, new(atomic.Int64))
	count := v.(*atomic.Int64)
	if count.Add(1) > maxConnsPerIP {
		count.Add(-1)
		return false
	}
	return true
}

// releaseConn decrements the connection count for ip and removes the entry when it reaches zero.
func (s *Server) releaseConn(ip string) {
	if v, ok := s.connByIP.Load(ip); ok {
		if v.(*atomic.Int64).Add(-1) <= 0 {
			s.connByIP.Delete(ip)
		}
	}
}

// extractIP returns just the host portion of a net.Addr.
func extractIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
