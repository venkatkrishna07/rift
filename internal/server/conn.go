package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/proto"
	"github.com/venkatkrishna07/rift/internal/store"
	"github.com/venkatkrishna07/rift/internal/worker"
)

const maxTunnelsPerClient = 10

// streamHeaderTimeout is the deadline applied to tunnel header I/O before the
// relay starts. Prevents stalled streams from holding goroutines indefinitely.
const streamHeaderTimeout = 10 * time.Second

// subdomainRE enforces RFC 1123 DNS label rules: 1–63 chars, lowercase
// alphanumeric with interior hyphens, no leading/trailing hyphens.
var subdomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// reservedSubdomains is the blocklist of labels clients may not claim.
var reservedSubdomains = map[string]struct{}{
	"www":       {},
	"api":       {},
	"mail":      {},
	"smtp":      {},
	"ftp":       {},
	"admin":     {},
	"root":      {},
	"ns":        {},
	"ns1":       {},
	"ns2":       {},
	"mx":        {},
	"vpn":       {},
	"ssh":       {},
	"localhost": {},
}

// validateSubdomain returns a non-nil error if s is not a safe DNS label for
// tunnel use. Enforces RFC 1123 syntax (lowercase only) and rejects reserved names.
func validateSubdomain(s string) error {
	if !subdomainRE.MatchString(s) {
		return errors.New("subdomain must be 1–63 lowercase alphanumeric characters; interior hyphens allowed, no leading/trailing hyphens")
	}
	if _, reserved := reservedSubdomains[s]; reserved {
		return errors.New("subdomain is reserved")
	}
	return nil
}

// blockedLocalPorts lists ports that must not be exposed as TCP tunnels.
// These are commonly abused for spam/amplification attacks.
var blockedLocalPorts = map[uint16]string{
	25:  "SMTP",
	53:  "DNS",
	465: "SMTPS",
	587: "SMTP submission",
}

// validateTCPLocalPort returns an error if port is 0 or on the blocked list.
func validateTCPLocalPort(port uint16) error {
	if port == 0 {
		return fmt.Errorf("port 0 is not allowed")
	}
	if svc, blocked := blockedLocalPorts[port]; blocked {
		return fmt.Errorf("port %d (%s) is not allowed as a TCP tunnel target", port, svc)
	}
	return nil
}

// connHandler handles a single authenticated QUIC connection from a client.
type connHandler struct {
	conn          *quic.Conn
	ts            store.TokenStore // nil in dev mode
	reg           *Registry
	dev           bool
	domain        string
	workers       *worker.Group
	log           *zap.Logger
	rl            *rateLimiter
	streamTimeout time.Duration
}

// run opens the control stream, authenticates the client, and processes
// tunnel registration requests until the connection closes.
func (h *connHandler) run(ctx context.Context) {
	ip := extractIP(h.conn.RemoteAddr())

	// Reject immediately if this IP is rate-limited.
	if h.rl.IsBlocked(ip) {
		h.log.Warn("connection rejected — IP rate-limited", zap.String("ip", ip))
		_ = h.conn.CloseWithError(2, "rate limited")
		return
	}

	ctrl, err := h.conn.AcceptStream(ctx)
	if err != nil {
		h.log.Error("accept control stream", zap.Error(err))
		return
	}
	defer ctrl.Close()

	// ── authentication ──────────────────────────────────────────────────────
	// Always read the auth frame — the client always sends it, even in dev mode,
	// so both sides use the same wire protocol regardless of auth mode.
	{
		msg, err := proto.ReadMsg(ctrl)
		if err != nil || msg.Type != proto.TypeAuth {
			if !h.dev {
				blocked := h.rl.RecordFailure(ip)
				h.log.Warn("bad auth frame",
					zap.String("ip", ip),
					zap.Bool("now_blocked", blocked),
					zap.Error(err),
				)
			} else {
				h.log.Warn("bad auth frame (dev)", zap.String("ip", ip), zap.Error(err))
			}
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "expected auth"})
			_ = h.conn.CloseWithError(2, "auth failed")
			return
		}

		if h.dev {
			msg.Token = "" // zero immediately — a prod client pointing at a dev server
			               // would send its real token; don't leave it in memory or logs
			// Dev mode: accept any token without validation.
			if err := proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeAuthOK}); err != nil {
				h.log.Error("send auth OK (dev)", zap.String("ip", ip), zap.Error(err))
				_ = h.conn.CloseWithError(2, "auth failed")
				return
			}
			h.log.Info("dev mode auth accepted", zap.String("ip", ip))
		} else {
			h.log.Info("auth attempt", zap.String("ip", ip))
			// Log token prefix only (never the full token).
			tokenHint := tokenPrefix(msg.Token)
			ok, err := h.ts.Validate(ctx, msg.Token)
			if err != nil || !ok {
				blocked := h.rl.RecordFailure(ip)
				h.log.Warn("auth rejected",
					zap.String("ip", ip),
					zap.String("token_prefix", tokenHint),
					zap.Bool("now_blocked", blocked),
				)
				_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "invalid token"})
				_ = h.conn.CloseWithError(2, "auth failed")
				return
			}

			if err := proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeAuthOK}); err != nil {
				h.log.Error("send auth OK", zap.String("ip", ip), zap.Error(err))
				_ = h.conn.CloseWithError(2, "auth failed")
				return
			}
			h.log.Info("client authenticated",
				zap.String("ip", ip),
				zap.String("token_prefix", tokenHint),
			)
		}
	}

	// ── registration loop ───────────────────────────────────────────────────
	// Track HTTP tunnel IDs so we can unregister them when this connection closes.
	// TCP tunnels unregister themselves inside serveTCPTunnel.
	var httpTunnels []uint32
	defer func() {
		for _, id := range httpTunnels {
			h.reg.Unregister(id)
		}
	}()

	tunnelCount := 0
	for {
		msg, err := proto.ReadMsg(ctrl)
		if err != nil {
			if ctx.Err() == nil {
				h.log.Debug("control stream closed", zap.String("ip", ip), zap.Error(err))
			}
			return
		}
		if msg.Type != proto.TypeRegister {
			h.log.Warn("unexpected message type", zap.String("ip", ip), zap.String("type", string(msg.Type)))
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "expected register"})
			_ = h.conn.CloseWithError(2, "protocol error")
			return
		}

		if tunnelCount >= maxTunnelsPerClient {
			h.log.Warn("tunnel limit reached",
				zap.String("ip", ip),
				zap.Int("max", maxTunnelsPerClient),
			)
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{
				Type:  proto.TypeError,
				Error: fmt.Sprintf("max %d tunnels per client", maxTunnelsPerClient),
			})
			time.Sleep(100 * time.Millisecond) // throttle tight-loop abuse
			continue
		}

		switch strings.ToLower(msg.Proto) {
		case proto.ProtoHTTP:
			subdomain := msg.Name
			if subdomain == "" {
				subdomain, err = randomSubdomain()
				if err != nil {
					_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "internal error"})
					continue
				}
			} else {
				if verr := validateSubdomain(subdomain); verr != nil {
					h.log.Warn("invalid subdomain rejected",
						zap.String("ip", ip),
						zap.String("name", subdomain),
						zap.Error(verr),
					)
					_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: verr.Error()})
					continue
				}
			}
			tun, regErr := h.reg.RegisterHTTP(subdomain, h.conn)
			if regErr != nil {
				h.log.Warn("HTTP tunnel registration failed",
					zap.String("ip", ip),
					zap.String("subdomain", subdomain),
					zap.Error(regErr),
				)
				_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: regErr.Error()})
				continue
			}
			httpTunnels = append(httpTunnels, tun.ID)
			url := fmt.Sprintf("https://%s.%s", subdomain, h.domain)
			tunnelCount++
			h.log.Info("HTTP tunnel registered",
				zap.String("ip", ip),
				zap.String("subdomain", subdomain),
				zap.String("url", url),
				zap.Uint32("tunnel_id", tun.ID),
			)
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{
				Type:     proto.TypeOK,
				TunnelID: tun.ID,
				URL:      url,
			})
		case proto.ProtoTCP:
			if err := validateTCPLocalPort(msg.Port); err != nil {
				h.log.Warn("TCP port blocked",
					zap.String("ip", ip),
					zap.Uint16("port", msg.Port),
					zap.Error(err),
				)
				_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: err.Error()})
				continue
			}
			tun, err := h.reg.RegisterTCP(h.conn)
			if err != nil {
				h.log.Error("TCP tunnel registration failed", zap.String("ip", ip), zap.Error(err))
				_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: err.Error()})
				continue
			}
			addr := fmt.Sprintf("%s:%d", h.domain, tun.Port)
			h.log.Warn("TCP tunnel registered — publicly accessible, NO visitor authentication",
				zap.String("ip", ip),
				zap.Uint16("port", tun.Port),
				zap.String("addr", addr),
			)
			h.log.Info("TCP tunnel registered",
				zap.String("ip", ip),
				zap.Uint16("port", tun.Port),
				zap.Uint32("tunnel_id", tun.ID),
			)
			bindCh := make(chan error, 1)
			h.workers.Go(fmt.Sprintf("tcp-tunnel-%d", tun.ID), func() {
				serveTCPTunnel(ctx, h.conn, tun.ID, tun.Port, h.reg, h.streamTimeout, bindCh, h.log)
			})

			// Wait for bind result before confirming to client.
			if bindErr := <-bindCh; bindErr != nil {
				h.reg.Unregister(tun.ID)
				h.log.Error("TCP tunnel bind failed", zap.Error(bindErr), zap.Uint16("port", tun.Port))
				_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "failed to allocate TCP port"})
				continue
			}

			tunnelCount++
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{
				Type:     proto.TypeOK,
				TunnelID: tun.ID,
				Addr:     addr,
			})
		default:
			safeProto := sanitizeProto(msg.Proto)
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{
				Type:  proto.TypeError,
				Error: fmt.Sprintf("unknown proto: %s", safeProto),
			})
		}
	}
}

// sanitizeProto truncates proto to 20 chars and strips non-printable bytes
// before including it in error responses sent to clients.
func sanitizeProto(s string) string {
	const maxLen = 20
	var b []byte
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b = append(b, byte(r))
		}
		if len(b) >= maxLen {
			break
		}
	}
	return string(b)
}

// randomSubdomain generates a cryptographically random 8-hex-char subdomain.
func randomSubdomain() (string, error) {
	b := make([]byte, 4) // 4 bytes → 8 hex chars
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate subdomain: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// tokenPrefix returns the first 8 characters of a token for safe logging.
func tokenPrefix(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "..."
}
