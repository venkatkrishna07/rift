package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

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

// dgramFramePool holds scratch buffers used when prefixing a visitor
// datagram with its tunnel ID + session ID before forwarding to the rift-
// client connection. Sized to cover a typical 1500-byte MTU. Buffers
// that grow past dgramFrameCapMax are dropped on return so pathological
// oversized datagrams cannot pump pool memory.
const dgramFrameCapMax = 4096

var dgramFramePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1500)
		return &b
	},
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
			// Library-level CSRF gate runs the same per-tunnel resolution
			// handleWT uses, so origin is checked before Upgrade has any
			// side effect — even if a future upstream change reorders
			// internal state writes around CheckOrigin.
			CheckOrigin: s.checkWTOrigin,
		}
		webtransport.ConfigureHTTP3Server(s.wt.h3)
		mux.HandleFunc("/_rift/", s.handleRiftPath)
		mux.HandleFunc("/", s.handleWT)
	})
	return s.wt
}

// handleRiftPath serves the reserved /_rift/ namespace. Currently only
// /_rift/healthz returns 204; future routes for /_rift/metrics, admin, and
// status APIs will land here. Anything else under the prefix returns 404
// so the namespace is unambiguously rift's.
func (s *Server) handleRiftPath(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/_rift/healthz":
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// checkWTOrigin resolves the request's subdomain to a tunnel and asks the
// per-tunnel origin policy whether the request is allowed. Requests that do
// not resolve to a live WT tunnel pass through to handleWT, where they are
// rejected with the same uniform 404 used for any other unknown route.
func (s *Server) checkWTOrigin(r *http.Request) bool {
	host := r.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	suffix := "." + s.cfg.Domain
	if !strings.HasSuffix(host, suffix) {
		return true
	}
	subdomain := strings.TrimSuffix(host, suffix)
	if subdomain == "" || strings.Contains(subdomain, ".") {
		return true
	}
	t := s.reg.BySubdomain(subdomain)
	if t == nil || t.Proto != "wt" {
		return true
	}
	return originAllowed(r.Header.Get("Origin"), t.AllowedOrigins)
}

// Bounds on Wt-Available-Protocols parsing. The wire format is sf-list of
// sf-strings (draft-ietf-webtrans-http3-14); a real browser sends a handful
// of short names. The caps keep a pathological client from inflating the
// allocation footprint with millions of commas or megabyte names.
const (
	maxWTProtocolOffered    = 32
	maxWTProtocolCandidate  = 64
)

// isWTProtocolToken reports whether b is a byte permitted in a sf-string
// token: printable ASCII excluding CR, LF, NUL, and DEL. The check is
// defence-in-depth — Go's net/http rejects CR/LF in response-header values
// when WriteHeader runs, but the WT-Protocol echo loop deserves its own
// validation so the rule is not lost in a future Go upgrade.
func isWTProtocolToken(b byte) bool {
	return b >= 0x21 && b <= 0x7E
}

// negotiateWTProtocol returns the first browser-offered WT subprotocol that
// the tunnel will accept. WT-Available-Protocols is a sf-list of sf-strings
// (draft-ietf-webtrans-http3-14); we treat each header value as a comma-
// separated list of bare protocol names and trim quotes / whitespace for
// robustness. allowed nil/empty accepts any single offered protocol.
// Candidates containing control characters or exceeding the per-candidate
// length cap are dropped; the total candidate count is capped to prevent a
// pathological header from forcing unbounded allocations.
func negotiateWTProtocol(headerValues, allowed []string) string {
	if len(headerValues) == 0 {
		return ""
	}
	offered := make([]string, 0, 8)
parse:
	for _, hv := range headerValues {
		for _, part := range strings.Split(hv, ",") {
			p := strings.TrimSpace(part)
			p = strings.Trim(p, "\"")
			if p == "" {
				continue
			}
			if len(p) > maxWTProtocolCandidate {
				continue
			}
			valid := true
			for i := 0; i < len(p); i++ {
				if !isWTProtocolToken(p[i]) {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
			offered = append(offered, p)
			if len(offered) >= maxWTProtocolOffered {
				break parse
			}
		}
	}
	if len(allowed) == 0 {
		if len(offered) > 0 {
			return offered[0]
		}
		return ""
	}
	allowSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		allowSet[a] = struct{}{}
	}
	for _, p := range offered {
		if _, ok := allowSet[p]; ok {
			return p
		}
	}
	return ""
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

	// Enforce per-tunnel visitor cap; existing HTTP/TCP tunnels already do
	// this. Without it a single browser could open unlimited WT sessions
	// and exhaust per-session goroutines + the rift-client FD pool.
	if !t.TryAddVisitor() {
		http.Error(w, "tunnel at capacity", http.StatusServiceUnavailable)
		return
	}
	defer t.VisitorDone()

	// Per-source-IP WT session cap. A single QUIC connection can multiplex
	// many WT sessions, so the QUIC-conn-per-IP cap is not sufficient.
	visitorIP := clientIP(r.RemoteAddr)
	if !s.allowWTVisitor(visitorIP) {
		s.log.Warn("webtransport rejected — per-IP session cap reached",
			zap.String("subdomain", subdomain),
			zap.String("ip", visitorIP),
		)
		http.Error(w, "too many sessions", http.StatusTooManyRequests)
		return
	}
	defer s.releaseWTVisitor(visitorIP)

	// Optional WT subprotocol negotiation. If the tunnel declares
	// AllowedWTProtocols, pick the first browser-offered protocol that
	// matches and echo it via WT-Protocol; with no allow-list, accept any.
	if chosen := negotiateWTProtocol(r.Header.Values("Wt-Available-Protocols"), t.AllowedWTProtocols); chosen != "" {
		w.Header().Set("WT-Protocol", chosen)
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

	// Register the session for the inbound-datagram demuxer; the returned
	// ID is stamped into the wire envelope so client-side routing is 1:1.
	sessionID := t.AddWTSession(sess)
	defer func() {
		t.RemoveWTSession(sessionID)
		sess.CloseWithError(0, "session ended")
	}()

	// Server-wide shutdown watchdog. If Run's ctx is cancelled while a
	// visitor is unresponsive, force-close the session so handleWT can
	// return and Shutdown stops blocking on it.
	if shutdownDone := s.runCtxDone(); shutdownDone != nil {
		go func() {
			select {
			case <-sess.Context().Done():
			case <-shutdownDone:
				_ = sess.CloseWithError(0, "shutdown")
			}
		}()
	}

	// Forward visitor→server datagrams onto the rift-client connection,
	// prefixed with the 4-byte tunnel ID. Returns when the session closes.
	s.wg.Go("wt-dgram-visitor", func() {
		for {
			msg, err := sess.ReceiveDatagram(sess.Context())
			if err != nil {
				return
			}
			bufPtr := dgramFramePool.Get().(*[]byte)
			buf := (*bufPtr)[:0]
			frameLen := 8 + len(msg)
			if cap(buf) < frameLen {
				buf = make([]byte, frameLen)
			} else {
				buf = buf[:frameLen]
			}
			binary.BigEndian.PutUint32(buf[:4], t.ID)
			binary.BigEndian.PutUint32(buf[4:8], sessionID)
			copy(buf[8:], msg)
			err = t.Conn.SendDatagram(buf)
			if cap(buf) <= dgramFrameCapMax {
				*bufPtr = buf
				dgramFramePool.Put(bufPtr)
			}
			if err != nil {
				s.log.Debug("forward visitor datagram failed",
					zap.Uint32("tunnel_id", t.ID),
					zap.Uint32("session_id", sessionID),
					zap.Int("len", frameLen),
					zap.Error(err),
				)
				return
			}
		}
	})

	// Two parallel accept loops: bidi streams and unidirectional streams.
	// Each spawned forwarder runs under the server-wide worker group so
	// Shutdown drains them.
	s.wg.Go("wt-uni-accept", func() {
		for {
			u, err := sess.AcceptUniStream(sess.Context())
			if err != nil {
				return
			}
			s.wg.Go("wt-uni-stream", func() {
				s.proxyWTUniStream(t, u)
			})
		}
	})

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

// proxyWTUniStream opens a server-initiated QUIC uni-stream on the rift
// client connection, writes the 8-byte tunnel header, and copies the
// visitor's uni-stream bytes through. The path is write-only by design:
// WT uni-streams have no return path so the local service receives bytes
// without being expected to reply on the same stream.
func (s *Server) proxyWTUniStream(t *Tunnel, visitorStream *webtransport.ReceiveStream) {
	clientStream, err := t.OpenDataUniStream(context.Background())
	if err != nil {
		s.log.Debug("open client uni-stream for WT failed",
			zap.Uint32("tunnel_id", t.ID),
			zap.Error(err),
		)
		return
	}
	defer clientStream.Close()

	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], t.ID)
	if _, err := clientStream.Write(hdr[:]); err != nil {
		return
	}

	if _, err := io.Copy(clientStream, visitorStream); err != nil {
		s.log.Debug("wt uni copy ended",
			zap.Uint32("tunnel_id", t.ID),
			zap.Error(err),
		)
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
