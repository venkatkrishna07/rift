package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/config"
	mcpproto "github.com/venkatkrishna07/caddy-mcp/proto"
)

const mcpMaxBodyBytes = 100 * 1024 * 1024 // 100 MiB

// connectMCP implements the caddy-mcp wire protocol: ALPN mcp-v1,
// 24-byte tunnel headers, and HTTP request/response proxying.
func (c *Client) connectMCP(ctx context.Context, addr, token string) error {
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: c.cfg.Insecure, //nolint:gosec
		NextProtos:         []string{"mcp-v1"},
	}, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		Allow0RTT:       false,
	})
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.CloseWithError(0, "done")
	c.log.Info("connected (mcp)", zap.String("server", addr))

	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		return fmt.Errorf("waiting for handshake: %w", ctx.Err())
	}

	ctrl, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}

	// Auth
	if err := mcpproto.WriteMsg(ctrl, &mcpproto.ControlMsg{Type: mcpproto.TypeAuth, Token: token}); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}
	resp, err := mcpproto.ReadMsg(ctrl)
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	if resp.Type != mcpproto.TypeAuthOK {
		return fmt.Errorf("auth rejected: %s", resp.Error)
	}
	c.log.Info("authenticated (mcp)")

	// Register tunnels — currently single-tunnel only.
	// Multi-tunnel requires protocol extension (TunnelID in RegisterOK response).
	if len(c.cfg.Tunnels) > 1 {
		c.log.Warn("MCP protocol currently supports single tunnel per connection; using first tunnel only")
	}
	spec := c.cfg.Tunnels[0]

	if err := mcpproto.WriteMsg(ctrl, &mcpproto.ControlMsg{
		Type:    mcpproto.TypeRegister,
		Tunnels: []mcpproto.TunnelRegistration{{Name: spec.Name}},
	}); err != nil {
		return fmt.Errorf("send register: %w", err)
	}
	regResp, err := mcpproto.ReadMsg(ctrl)
	if err != nil {
		return fmt.Errorf("read register response: %w", err)
	}
	if regResp.Type == mcpproto.TypeError {
		return fmt.Errorf("registration failed: %s", regResp.Error)
	}
	if regResp.Type != mcpproto.TypeRegisterOK {
		return fmt.Errorf("unexpected register response: %s", regResp.Type)
	}

	c.log.Info("mcp tunnel ready", zap.String("tunnel", spec.Name))

	return c.acceptMCPDataStreams(ctx, conn, spec)
}

func (c *Client) acceptMCPDataStreams(ctx context.Context, conn *quic.Conn, spec config.TunnelSpec) error {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept mcp data stream: %w", err)
		}
		c.workers.Go(fmt.Sprintf("mcp-stream-%d", stream.StreamID()), func() {
			c.handleMCPStream(stream, spec)
		})
	}
}

func (c *Client) handleMCPStream(stream *quic.Stream, spec config.TunnelSpec) {
	defer stream.Close()

	// Read 24-byte tunnel header with deadline
	if err := stream.SetDeadline(time.Now().Add(streamHeaderTimeout)); err != nil {
		c.log.Error("set mcp stream deadline", zap.Error(err))
		return
	}
	if _, err := mcpproto.ReadHeader(stream); err != nil {
		c.log.Error("read mcp tunnel header", zap.Error(err))
		return
	}

	// Set read deadline for HTTP request parsing (prevent stalled partial requests)
	if err := stream.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		c.log.Error("set mcp request deadline", zap.Error(err))
		return
	}

	// Read HTTP request from stream (server writes full HTTP/1.1)
	br := bufio.NewReader(stream)
	req, err := http.ReadRequest(br)
	if err != nil {
		c.log.Error("read http request from mcp stream", zap.Error(err))
		return
	}
	defer req.Body.Close()

	// Clear deadline before proxying (response may take time)
	if err := stream.SetDeadline(time.Time{}); err != nil {
		c.log.Error("clear mcp stream deadline", zap.Error(err))
		return
	}

	// Read full body with size limit
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, mcpMaxBodyBytes))
		if err != nil {
			c.log.Error("read request body", zap.Error(err))
			writeHTTPError(stream, http.StatusBadRequest, "failed to read request body")
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
	}

	// Rewrite request to upstream
	upstream := fmt.Sprintf("http://localhost:%d", spec.LocalPort)
	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		c.log.Error("parse upstream url", zap.Error(err))
		writeHTTPError(stream, http.StatusBadGateway, "bad upstream URL")
		return
	}
	req.URL.Scheme = upstreamURL.Scheme
	req.URL.Host = upstreamURL.Host
	req.RequestURI = ""

	// Forward to upstream with stream context for cancellation
	req = req.WithContext(stream.Context())
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		c.log.Error("forward to upstream", zap.Error(err),
			zap.String("upstream", upstream),
			zap.String("path", req.URL.Path),
		)
		writeHTTPError(stream, http.StatusBadGateway, "upstream unreachable")
		return
	}

	// Use sync.Once to prevent double-close of resp.Body.
	// The cleanup goroutine closes it when stream is cancelled (SSE),
	// and the defer closes it on normal completion.
	var closeOnce sync.Once
	closeBody := func() { resp.Body.Close() }
	defer closeOnce.Do(closeBody)

	// For SSE/streaming: close upstream body when QUIC stream is cancelled.
	// For normal responses: done channel ensures goroutine exits promptly.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-stream.Context().Done():
			closeOnce.Do(closeBody)
		case <-done:
		}
	}()

	// Write response back to QUIC stream
	if err := resp.Write(stream); err != nil {
		c.log.Debug("stream write ended", zap.Error(err))
		return
	}

	c.log.Debug("mcp request proxied",
		zap.String("method", req.Method),
		zap.String("path", req.URL.Path),
		zap.Int("status", resp.StatusCode),
	)
}

// writeHTTPError sends a minimal HTTP error response back on the QUIC stream.
func writeHTTPError(stream *quic.Stream, code int, msg string) {
	resp := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(bytes.NewBufferString(msg)),
	}
	resp.ContentLength = int64(len(msg))
	_ = resp.Write(stream)
}
