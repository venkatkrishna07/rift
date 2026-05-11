// Package client implements the rift tunnel client.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/config"
	"github.com/venkatkrishna07/rift/internal/proto"
	"github.com/venkatkrishna07/rift/internal/server"
	"github.com/venkatkrishna07/rift/internal/store"
	"github.com/venkatkrishna07/rift/internal/worker"
)

// Client connects to a rift server and manages tunnel registration.
type Client struct {
	cfg     config.ClientConfig
	ts      store.TokenStore
	log     *zap.Logger
	workers *worker.Group

	lifecycleMu sync.Mutex
	cancel      context.CancelFunc
	done        chan struct{}
	closeOnce   sync.Once
}

// New creates a Client.
func New(cfg config.ClientConfig, ts store.TokenStore, log *zap.Logger) *Client {
	l := log.With(zap.String("component", "client"))
	return &Client{cfg: cfg, ts: ts, log: l, workers: worker.New(l)}
}

// Close cancels an in-flight Connect and waits for it to return. Idempotent;
// subsequent calls return nil without blocking. Safe to call before Connect.
func (c *Client) Close() error {
	var done chan struct{}
	var cancel context.CancelFunc
	c.closeOnce.Do(func() {
		c.lifecycleMu.Lock()
		cancel = c.cancel
		done = c.done
		c.lifecycleMu.Unlock()
		if cancel != nil {
			cancel()
		}
	})
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("client close timed out after 5s")
	}
}

// Connect dials the server and reconnects with exponential backoff until ctx is done.
// Returns a non-nil error only for permanent server errors (auth failure, rate limit,
// token expired) that retrying will not fix, or the parent ctx error
// (context.Canceled / context.DeadlineExceeded) when the parent ctx caused
// the exit. Returns nil only when Close was the cause of exit.
//
// When the parent ctx expires while the most recent dial attempt failed
// (typically TLS verification or a refused connection), the returned error
// joins the parent ctx error with the last connection error so callers can
// inspect both via errors.Is.
func (c *Client) Connect(ctx context.Context) error {
	parentCtx := ctx
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{})
	c.lifecycleMu.Lock()
	c.cancel = cancel
	c.done = done
	c.lifecycleMu.Unlock()
	defer close(done)

	var lastConnErr error

	// exitErr surfaces the parent ctx error when it caused the exit, joined
	// with the last connection error if one was captured (so TLS / refused
	// failures are observable rather than masked by ctx.Err()).
	exitErr := func() error {
		pe := parentCtx.Err()
		if pe == nil {
			return nil
		}
		if lastConnErr != nil {
			return errors.Join(pe, lastConnErr)
		}
		return pe
	}

	ctx = runCtx

	const maxBackoff = 30 * time.Second
	backoff := time.Second
	for {
		err := c.connect(ctx)
		if err != nil && ctx.Err() == nil {
			if isPermanentError(err) {
				c.log.Error("fatal server error — not retrying", zap.Error(err))
				c.workers.Wait()
				return wrapPermanent(err)
			}
			lastConnErr = err
			c.log.Error("disconnected", zap.Error(err), zap.Duration("retry_in", backoff))
			select {
			case <-ctx.Done():
				c.workers.Wait()
				return exitErr()
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		if ctx.Err() != nil {
			c.workers.Wait()
			return exitErr()
		}
		backoff = time.Second // reset on clean disconnect
	}
}

// isPermanentError returns true for server-signalled errors that retrying won't fix.
// Error codes:
//
//	2 — auth failed or rate limited (IP blocked due to repeated failures)
//	3 — token expired
//	4 — token revoked
//
// Also returns true for ErrMCPNotCompiled — the binary lacks MCP support and
// retrying will not fix the missing dependency.
func isPermanentError(err error) bool {
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.ErrorCode == 2 || appErr.ErrorCode == 3 || appErr.ErrorCode == 4
	}
	return errors.Is(err, ErrMCPNotCompiled)
}

// wrapPermanent maps a permanent-failure error to the public sentinel that
// the rift package exposes. Auth/IP-block path uses code 2 and surfaces as
// ErrAuthFailed; token-expiry uses code 3 and surfaces as ErrTokenExpired;
// token-revoked uses code 4 and surfaces as ErrTokenRevoked. Other errors
// (e.g. ErrMCPNotCompiled) pass through unchanged.
func wrapPermanent(err error) error {
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		switch appErr.ErrorCode {
		case 2:
			return fmt.Errorf("%w: %w", server.ErrAuthFailed, err)
		case 3:
			return fmt.Errorf("%w: %w", server.ErrTokenExpired, err)
		case 4:
			return fmt.Errorf("%w: %w", server.ErrTokenRevoked, err)
		}
	}
	return err
}

func (c *Client) connect(ctx context.Context) error {
	addr := c.cfg.Server
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	token := c.cfg.Token
	if token == "" && c.ts != nil {
		var err error
		token, err = c.ts.Lookup(ctx, c.cfg.Server)
		if err != nil {
			return fmt.Errorf("lookup token: %w", err)
		}
	}

	host, _, _ := net.SplitHostPort(addr)
	if err := checkInsecureFlags(c.cfg.Insecure, c.cfg.ForceInsecure, host); err != nil {
		return err
	}
	if c.cfg.Insecure && c.cfg.ForceInsecure {
		c.log.Warn("TLS certificate verification DISABLED — MITM attacks are possible",
			zap.String("server", addr),
		)
	}

	if c.cfg.Protocol == config.ProtocolMCP {
		return c.connectMCP(ctx, addr, token)
	}

	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: c.cfg.Insecure, //nolint:gosec // controlled by ForceInsecure guard above
		NextProtos:         []string{"rift-v1"},
	}, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		Allow0RTT:       false, // server rejects 0-RTT; auth is always sent after 1-RTT handshake
	})
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.CloseWithError(0, "done")
	c.log.Info("connected", zap.String("server", addr))

	// Wait for the 1-RTT handshake before sending auth.
	// Ensures auth token and register frames are never in replayable 0-RTT data.
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		return fmt.Errorf("waiting for handshake: %w", ctx.Err())
	}

	ctrl, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}

	// Hello first so the server can reject unknown protocol versions before
	// any token is sent.
	if err := proto.WriteMsg(ctrl, &proto.ControlMsg{
		Type:    proto.TypeHello,
		Version: proto.ProtocolVersion,
	}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	helloResp, err := proto.ReadMsg(ctrl)
	if err != nil {
		return fmt.Errorf("read hello response: %w", err)
	}
	switch helloResp.Type {
	case proto.TypeHelloOK:
		// ok
	case proto.TypeError:
		return fmt.Errorf("server rejected hello: %s", helloResp.Error)
	default:
		return fmt.Errorf("unexpected hello response type %q", helloResp.Type)
	}

	if err := proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeAuth, Token: token}); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}
	resp, err := proto.ReadMsg(ctrl)
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	switch resp.Type {
	case proto.TypeAuthOK:
		// ok
	case proto.TypeError:
		return fmt.Errorf("%w: %s", server.ErrAuthFailed, resp.Error)
	default:
		return fmt.Errorf("%w: unexpected auth response type %q", server.ErrAuthFailed, resp.Type)
	}
	c.log.Info("authenticated")

	tunnelMap := make(map[uint32]config.TunnelSpec, len(c.cfg.Tunnels))
	for _, spec := range c.cfg.Tunnels {
		if err := proto.WriteMsg(ctrl, &proto.ControlMsg{
			Type:           proto.TypeRegister,
			Port:           spec.LocalPort,
			Proto:          spec.Proto,
			Name:           spec.Name,
			AllowedOrigins: spec.AllowedOrigins,
		}); err != nil {
			return fmt.Errorf("send register: %w", err)
		}
		reg, err := proto.ReadMsg(ctrl)
		if err != nil {
			return fmt.Errorf("read register response: %w", err)
		}
		switch reg.Type {
		case proto.TypeOK:
			// proceed
		case proto.TypeError:
			c.log.Error("registration rejected", zap.String("err", reg.Error))
			continue
		default:
			c.log.Warn("unexpected register response type",
				zap.String("type", reg.Type),
				zap.String("proto", spec.Proto),
			)
			continue
		}
		tunnelMap[reg.TunnelID] = spec
		switch spec.Proto {
		case proto.ProtoHTTP, proto.ProtoWT:
			c.log.Info("tunnel ready",
				zap.String("proto", spec.Proto),
				zap.String("url", reg.URL),
				zap.Uint16("local_port", spec.LocalPort),
			)
		case proto.ProtoTCP:
			c.log.Info("tunnel ready",
				zap.String("proto", spec.Proto),
				zap.String("remote_addr", reg.Addr),
				zap.Uint16("local_port", spec.LocalPort),
			)
		default:
			c.log.Warn("tunnel ready with unknown protocol",
				zap.String("proto", spec.Proto),
				zap.Uint16("local_port", spec.LocalPort),
			)
		}
	}

	if len(tunnelMap) == 0 {
		return fmt.Errorf("no tunnels registered successfully")
	}

	return c.acceptDataStreams(ctx, conn, tunnelMap)
}

// checkInsecureFlags validates the --insecure / --force-insecure combination.
// Callers (the CLI) are responsible for any environment-variable double-check
// before setting forceInsecure; the library never reads process env.
func checkInsecureFlags(insecure, forceInsecure bool, host string) error {
	if !insecure {
		return nil
	}
	if forceInsecure {
		return nil
	}
	if !isLocalhost(host) {
		return fmt.Errorf(
			"insecure mode is only allowed with localhost targets; "+
				"set AcknowledgeInsecure to bypass cert verification for %q",
			host,
		)
	}
	return nil
}

// isLocalhost reports whether host resolves to a loopback address.
func isLocalhost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
