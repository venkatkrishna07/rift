package server

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/relay"
)

// wtServer is lazily constructed on first h3 connection. It wraps a single
// http3.Server + webtransport.Server pair shared across all visitors. The
// handler routes by Host (subdomain) to a registered tunnel.
type wtServer struct {
	h3 *http3.Server
	wt *webtransport.Server
}

func (s *Server) ensureWT() *wtServer {
	s.wtOnce.Do(func() {
		mux := http.NewServeMux()
		s.wt = &wtServer{
			h3: &http3.Server{
				Handler: mux,
			},
		}
		s.wt.wt = &webtransport.Server{
			H3: s.wt.h3,
			// Per-tunnel Origin enforcement happens in handleWT once the
			// subdomain is resolved to a Tunnel. The library-level callback
			// only accepts requests without an Origin header (same-origin
			// CONNECTs from non-browser clients); browser requests pass
			// through handleWT's per-tunnel check before Upgrade.
			CheckOrigin: func(*http.Request) bool { return true },
		}
		webtransport.ConfigureHTTP3Server(s.wt.h3)
		mux.HandleFunc("/", s.handleWT)
	})
	return s.wt
}

// originAllowed returns true if origin matches the tunnel's allow-list.
// Empty allow-list rejects every cross-origin request. "*" matches any.
// An empty Origin header is treated as same-origin and always allowed.
func originAllowed(origin string, allowed []string) bool {
	if origin == "" {
		return true
	}
	for _, a := range allowed {
		if a == "*" || a == origin {
			return true
		}
	}
	return false
}

// serveWebTransport hands a single negotiated-h3 quic.Conn off to the
// shared webtransport.Server. Blocks until the connection ends.
func (s *Server) serveWebTransport(_ context.Context, conn *quic.Conn) {
	w := s.ensureWT()
	if err := w.wt.ServeQUICConn(conn); err != nil && !errors.Is(err, context.Canceled) {
		s.log.Debug("webtransport conn ended", zap.Error(err))
	}
}

// handleWT routes an incoming WT CONNECT to a registered tunnel and forwards
// every bidi stream from the visitor to the rift client over a fresh QUIC
// stream.
func (s *Server) handleWT(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	suffix := "." + s.cfg.Domain
	// Uniform 404 response for all "no match" reasons (bad host, wrong
	// subdomain shape, unknown tunnel, wrong proto). Distinct error strings
	// would let an attacker enumerate live subdomains by status/timing.
	const notFoundBody = "not found"
	if !strings.HasSuffix(host, suffix) {
		http.Error(w, notFoundBody, http.StatusNotFound)
		return
	}
	subdomain := strings.TrimSuffix(host, suffix)
	if subdomain == "" || strings.Contains(subdomain, ".") {
		http.Error(w, notFoundBody, http.StatusNotFound)
		return
	}

	t := s.reg.BySubdomain(subdomain)
	if t == nil || t.Proto != "wt" {
		http.Error(w, notFoundBody, http.StatusNotFound)
		return
	}

	if !originAllowed(r.Header.Get("Origin"), t.AllowedOrigins) {
		s.log.Warn("webtransport origin rejected",
			zap.String("subdomain", subdomain),
			zap.String("origin", r.Header.Get("Origin")),
		)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	wtSrv := s.ensureWT()
	sess, err := wtSrv.wt.Upgrade(w, r)
	if err != nil {
		s.log.Warn("webtransport upgrade failed",
			zap.String("subdomain", subdomain),
			zap.Error(err),
		)
		return
	}
	s.log.Info("webtransport session opened",
		zap.String("subdomain", subdomain),
		zap.Uint32("tunnel_id", t.ID),
	)
	defer sess.CloseWithError(0, "session ended")

	for {
		visitorStream, err := sess.AcceptStream(sess.Context())
		if err != nil {
			return
		}
		s.wg.Go("wt-stream", func() {
			s.proxyWTStream(t, visitorStream)
		})
	}
}

// proxyWTStream opens a QUIC stream on the rift client's connection, writes
// the 8-byte tunnel header, and hands both sides to relay.Relay so the WT
// path inherits the same idle-watchdog the HTTP and TCP paths use.
func (s *Server) proxyWTStream(t *Tunnel, visitorStream *webtransport.Stream) {
	clientStream, err := t.OpenDataStream(context.Background())
	if err != nil {
		_ = visitorStream.Close()
		s.log.Debug("open client stream for WT failed",
			zap.Uint32("tunnel_id", t.ID),
			zap.Error(err),
		)
		return
	}

	// 8-byte tunnel header: [tunnelID uint32 BE][reserved 4 bytes].
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], t.ID)
	if _, err := clientStream.Write(hdr[:]); err != nil {
		_ = clientStream.Close()
		_ = visitorStream.Close()
		return
	}

	timeout := s.cfg.EffectiveStreamTimeout()
	relay.Relay(visitorStream, clientStream, timeout, s.log)
}
