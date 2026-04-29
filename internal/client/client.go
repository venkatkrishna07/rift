// Package client implements the rift tunnel client.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/config"
	"github.com/venkatkrishna07/rift/internal/proto"
	"github.com/venkatkrishna07/rift/internal/store"
	"github.com/venkatkrishna07/rift/internal/worker"
)

// Client connects to a rift server and manages tunnel registration.
type Client struct {
	cfg     config.ClientConfig
	ts      store.TokenStore
	log     *zap.Logger
	workers *worker.Group
}

// New creates a Client.
func New(cfg config.ClientConfig, ts store.TokenStore, log *zap.Logger) *Client {
	l := log.With(zap.String("component", "client"))
	return &Client{cfg: cfg, ts: ts, log: l, workers: worker.New(l)}
}

// Connect dials the server and reconnects with exponential backoff until ctx is done.
// Returns a non-nil error only for permanent server errors (auth failure, rate limit,
// token expired) that retrying will not fix. Returns nil on clean shutdown via ctx.
func (c *Client) Connect(ctx context.Context) error {
	const maxBackoff = 30 * time.Second
	backoff := time.Second
	for {
		err := c.connect(ctx)
		if err != nil && ctx.Err() == nil {
			if isPermanentError(err) {
				c.log.Error("fatal server error — not retrying", zap.Error(err))
				c.workers.Wait()
				return err
			}
			c.log.Error("disconnected", zap.Error(err), zap.Duration("retry_in", backoff))
			select {
			case <-ctx.Done():
				c.workers.Wait()
				return nil
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		if ctx.Err() != nil {
			c.workers.Wait()
			return nil
		}
		backoff = time.Second // reset on clean disconnect
	}
}

// isPermanentError returns true for server-signalled errors that retrying won't fix.
// Error codes:
//
//	2 — auth failed or rate limited (IP blocked due to repeated failures)
//	3 — token expired
func isPermanentError(err error) bool {
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.ErrorCode == 2 || appErr.ErrorCode == 3
	}
	return false
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

	if err := proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeAuth, Token: token}); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}
	resp, err := proto.ReadMsg(ctrl)
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	if resp.Type != proto.TypeAuthOK {
		return fmt.Errorf("auth rejected: %s", resp.Error)
	}
	c.log.Info("authenticated")

	tunnelMap := make(map[uint32]config.TunnelSpec, len(c.cfg.Tunnels))
	for _, spec := range c.cfg.Tunnels {
		if err := proto.WriteMsg(ctrl, &proto.ControlMsg{
			Type:  proto.TypeRegister,
			Port:  spec.LocalPort,
			Proto: spec.Proto,
			Name:  spec.Name,
		}); err != nil {
			return fmt.Errorf("send register: %w", err)
		}
		reg, err := proto.ReadMsg(ctrl)
		if err != nil {
			return fmt.Errorf("read register response: %w", err)
		}
		if reg.Type == proto.TypeError {
			c.log.Error("registration rejected", zap.String("err", reg.Error))
			continue
		}
		tunnelMap[reg.TunnelID] = spec
		switch spec.Proto {
		case proto.ProtoHTTP:
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
// Separating this logic makes it testable without a real QUIC connection.
func checkInsecureFlags(insecure, forceInsecure bool, host string) error {
	if !insecure {
		return nil
	}
	if forceInsecure {
		if os.Getenv("RIFT_FORCE_INSECURE") != "yes" {
			return fmt.Errorf(
				"--force-insecure requires the environment variable RIFT_FORCE_INSECURE=yes " +
					"to prevent accidental TLS verification bypass on production servers",
			)
		}
		return nil
	}
	if !isLocalhost(host) {
		return fmt.Errorf(
			"--insecure is only allowed with localhost targets; "+
				"use --force-insecure (and set RIFT_FORCE_INSECURE=yes) for %q",
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
