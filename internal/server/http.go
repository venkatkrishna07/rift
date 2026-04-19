package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/proto"
	"github.com/venkatkrishna07/rift/internal/relay"
)

// serveACMEHTTP starts a plain HTTP server on cfg.ACMEAddr that responds to
// Let's Encrypt HTTP-01 challenges and redirects all other traffic to HTTPS.
func (s *Server) serveACMEHTTP(ctx context.Context) error {
	addr := s.cfg.ACMEAddr
	if addr == "" {
		addr = ":80"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.acmeHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	s.log.Info("ACME HTTP-01 listener started", zap.String("addr", addr))
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("ACME HTTP listen %s: %w", addr, err)
	}
	return nil
}

// serveHTTPS starts the TLS listener and routes visitors to registered HTTP tunnels.
func (s *Server) serveHTTPS(ctx context.Context, tlsCfg *tls.Config) error {
	ln, err := tls.Listen("tcp", s.cfg.ListenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("HTTPS listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.log.Info("HTTPS listener started", zap.String("addr", s.cfg.ListenAddr))

	// 100 req/s sustained, burst 200; evict idle entries after 10 minutes.
	vrl := newPerIPLimiter(100, 200, 10*time.Minute)
	vrl.start(ctx)

	var issuer TokenIssuer
	if s.cfg.AdminSecret != "" && s.ts != nil {
		issuer = NewAdminSecretIssuer(s.cfg.AdminSecret, s.ts, s.cfg.TokenTTL, s.log)
	}

	srv := &http.Server{
		Handler: &httpHandler{
			reg:           s.reg,
			log:           s.log,
			maxBodyBytes:  s.cfg.EffectiveMaxBodyBytes(),
			streamTimeout: s.cfg.EffectiveStreamTimeout(),
			visitorRL:     vrl,
			issuer:        issuer,
		},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return fmt.Errorf("HTTPS serve: %w", err)
	}
	return nil
}

type httpHandler struct {
	reg           *Registry
	log           *zap.Logger
	maxBodyBytes  int64
	streamTimeout time.Duration
	visitorRL     *perIPLimiter
	issuer        TokenIssuer // nil = no token provisioning endpoint
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.issuer != nil && h.issuer.Match(r) {
		h.issuer.ServeHTTP(w, r)
		return
	}

	visitorIP := clientIP(r.RemoteAddr)
	if !h.visitorRL.Allow(visitorIP) {
		h.log.Debug("visitor rate limited", zap.String("ip", visitorIP))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	host := r.Host
	if i := strings.IndexByte(host, ':'); i != -1 {
		host = host[:i]
	}
	subdomain := strings.SplitN(host, ".", 2)[0]
	tun := h.reg.BySubdomain(subdomain)
	if tun == nil {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}
	if !tun.TryAddVisitor() {
		http.Error(w, "tunnel at capacity", http.StatusServiceUnavailable)
		return
	}
	defer tun.VisitorDone()

	// Enforce body size limit before any reading.
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)

	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		h.proxyWebSocket(w, r, tun)
		return
	}
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Delete every header a visitor could inject to spoof identity.
			// Set them authoritatively below — delete first, then set.
			for _, hdr := range []string{
				"X-Forwarded-For",
				"X-Forwarded-Host",
				"X-Forwarded-Proto",
				"X-Real-Ip",
				"X-Real-IP",
				"True-Client-Ip",
				"True-Client-IP",
				"Cf-Connecting-Ip",
				"CF-Connecting-IP",
				"X-Original-Forwarded-For",
				"X-Client-IP",
			} {
				req.Header.Del(hdr)
			}
			req.URL.Scheme = "http"
			req.URL.Host = r.Host
			req.Header.Set("X-Forwarded-For", visitorIP)
			req.Header.Set("X-Real-IP", visitorIP)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", r.Host)
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Body = io.NopCloser(io.LimitReader(resp.Body, h.maxBodyBytes))
			return nil
		},
		Transport: &tunnelTransport{conn: tun.Conn, tunnelID: tun.ID},
	}
	rp.ServeHTTP(w, r)
}

type tunnelTransport struct {
	conn     *quic.Conn
	tunnelID uint32
}

func (t *tunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	stream, err := t.conn.OpenStreamSync(req.Context())
	if err != nil {
		return nil, fmt.Errorf("open QUIC stream: %w", err)
	}
	// Short deadline for header write; clear before proxying the request body.
	if err := stream.SetDeadline(time.Now().Add(streamHeaderTimeout)); err != nil {
		stream.Close()
		return nil, fmt.Errorf("set stream deadline: %w", err)
	}
	if err := proto.WriteHeader(stream, proto.TunnelHeader{TunnelID: t.tunnelID}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write header: %w", err)
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("clear stream deadline: %w", err)
	}
	if err := req.Write(stream); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	resp.Body = &streamBody{ReadCloser: resp.Body, stream: stream}
	return resp, nil
}

// streamBody wraps a response body and closes the underlying QUIC stream when done.
type streamBody struct {
	io.ReadCloser
	stream io.Closer
}

func (b *streamBody) Close() error {
	err := b.ReadCloser.Close()
	_ = b.stream.Close()
	return err
}

// bufReadWriteCloser pairs a bufio.Reader (which may hold bytes buffered beyond
// the HTTP response headers) with an io.WriteCloser for the same stream.
// Ensures early WebSocket frames buffered during http.ReadResponse are not lost.
type bufReadWriteCloser struct {
	*bufio.Reader
	io.WriteCloser
}

func (b *bufReadWriteCloser) Close() error { return b.WriteCloser.Close() }

// readerWriteCloser combines an arbitrary io.Reader with an io.WriteCloser.
// Used when the visitor-side reader must drain a bufio buffer before the raw
// net.Conn (e.g. any bytes buffered from the HTTP upgrade request).
type readerWriteCloser struct {
	io.Reader
	io.WriteCloser
}

func (r *readerWriteCloser) Close() error { return r.WriteCloser.Close() }

func (h *httpHandler) proxyWebSocket(w http.ResponseWriter, r *http.Request, tun *Tunnel) {
	// 1. Open stream and write tunnel header with a short I/O deadline.
	stream, err := tun.Conn.OpenStreamSync(r.Context())
	if err != nil {
		h.log.Error("open QUIC stream for websocket", zap.Error(err))
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if err := stream.SetDeadline(time.Now().Add(streamHeaderTimeout)); err != nil {
		h.log.Error("set websocket stream deadline", zap.Error(err))
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if err := proto.WriteHeader(stream, proto.TunnelHeader{TunnelID: tun.ID}); err != nil {
		h.log.Error("write websocket tunnel header", zap.Error(err))
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		h.log.Error("clear websocket stream deadline", zap.Error(err))
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// 2. Forward the upgrade request.
	if err := r.Write(stream); err != nil {
		h.log.Error("write websocket request to tunnel", zap.Error(err))
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// 3. Read and verify the backend's response BEFORE involving the visitor.
	// Use bufio.Reader — the backend may send WebSocket frames immediately after
	// the 101, which must be preserved for the relay (not discarded).
	streamBuf := bufio.NewReader(stream)
	resp, err := http.ReadResponse(streamBuf, r)
	if err != nil {
		h.log.Error("read websocket upgrade response from tunnel", zap.Error(err))
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	resp.Body.Close() // 101 has no body

	if resp.StatusCode != http.StatusSwitchingProtocols {
		h.log.Error("websocket upgrade rejected by backend",
			zap.Int("status", resp.StatusCode),
			zap.String("status_text", resp.Status),
		)
		stream.Close()
		http.Error(w, fmt.Sprintf("websocket upgrade rejected: %s", resp.Status), http.StatusBadGateway)
		return
	}

	// 4. Hijack the visitor connection now that we have a confirmed 101.
	hj, ok := w.(http.Hijacker)
	if !ok {
		h.log.Error("websocket upgrade not supported by ResponseWriter")
		stream.Close()
		http.Error(w, "websocket unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		h.log.Error("websocket hijack failed", zap.Error(err))
		stream.Close()
		return
	}
	defer clientConn.Close()

	// 5. Forward the 101 response to the visitor so it can complete its handshake.
	if err := resp.Write(clientBuf.Writer); err != nil {
		h.log.Error("write 101 to visitor", zap.Error(err))
		stream.Close()
		return
	}
	if err := clientBuf.Writer.Flush(); err != nil {
		h.log.Error("flush 101 to visitor", zap.Error(err))
		stream.Close()
		return
	}

	// 6. Relay raw WebSocket frames.
	// streamBuf may have buffered bytes beyond the 101 headers — must not discard.
	streamRWC := &bufReadWriteCloser{Reader: streamBuf, WriteCloser: stream}

	// clientBuf.Reader may have buffered bytes from the upgrade request — drain them.
	var clientReader io.Reader = clientConn
	if clientBuf.Reader.Buffered() > 0 {
		clientReader = io.MultiReader(clientBuf.Reader, clientConn)
	}
	clientRWC := &readerWriteCloser{Reader: clientReader, WriteCloser: clientConn}

	relay.Relay(clientRWC, streamRWC, h.streamTimeout, h.log)
}

func clientIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}
