package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
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
	"www":        {},
	"api":        {},
	"mail":       {},
	"smtp":       {},
	"ftp":        {},
	"admin":      {},
	"root":       {},
	"ns":         {},
	"ns1":        {},
	"ns2":        {},
	"ns3":        {},
	"ns4":        {},
	"mx":         {},
	"mx1":        {},
	"mx2":        {},
	"vpn":        {},
	"ssh":        {},
	"localhost":  {},
	"cdn":        {},
	"static":     {},
	"assets":     {},
	"media":      {},
	"images":     {},
	"img":        {},
	"docs":       {},
	"help":       {},
	"support":    {},
	"status":     {},
	"monitor":    {},
	"dashboard":  {},
	"panel":      {},
	"git":        {},
	"ci":         {},
	"registry":   {},
	"auth":       {},
	"login":      {},
	"account":    {},
	"internal":   {},
	"private":    {},
	"manage":     {},
	"portal":     {},
	"secure":     {},
	"staging":    {},
	"prod":       {},
	"production": {},
	"dev":        {},
	"beta":       {},
	"test":       {},
	"demo":       {},
	"db":         {},
	"database":   {},
	"cache":      {},
	"proxy":      {},
	"gateway":    {},
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

// controlStreamIdle is the max time the post-auth control stream may sit
// idle before the server closes it. Defends against authenticated-but-quiet
// clients hoarding resources.
const controlStreamIdle = 5 * time.Minute

// blockedLocalPorts lists ports that must not be exposed as TCP tunnels even
// when the client opts in to publishing low ports. Each entry covers a
// service whose accidental exposure is a known incident class: spam relays,
// amplification, lateral movement, or trivially brute-forceable databases.
var blockedLocalPorts = map[uint16]string{
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	135:   "RPC",
	139:   "NetBIOS",
	445:   "SMB",
	465:   "SMTPS",
	587:   "SMTP submission",
	1433:  "MSSQL",
	1434:  "MSSQL Browser",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	6379:  "Redis",
	9200:  "Elasticsearch",
	11211: "memcached",
	27017: "MongoDB",
}

// allowLowLocalPorts gates publishing local ports below 1024. The default
// posture refuses them because a typo turns "expose local dev server" into
// "publish privileged service to the world". Operators override via
// $RIFT_UNSAFE_TCP_PORT=yes when they really need it.
func allowLowLocalPorts() bool {
	return os.Getenv("RIFT_UNSAFE_TCP_PORT") == "yes"
}

// validateTCPLocalPort returns an error if port is 0, on the blocked list,
// or below 1024 without the low-port opt-in.
func (h *connHandler) validateTCPLocalPort(port uint16) error {
	if port == 0 {
		return fmt.Errorf("port 0 is not allowed")
	}
	if svc, blocked := blockedLocalPorts[port]; blocked {
		return fmt.Errorf("port %d (%s) is not allowed as a TCP tunnel target", port, svc)
	}
	if port < 1024 && !h.allowLowPorts && !allowLowLocalPorts() {
		return fmt.Errorf("port %d is below 1024 — privileged ports are blocked; enable WithAllowLowLocalPorts or set RIFT_UNSAFE_TCP_PORT=yes to override", port)
	}
	return nil
}

// connHandler handles a single authenticated QUIC connection from a client.
type connHandler struct {
	conn          *quic.Conn
	ts            store.TokenStore // nil in dev mode
	reg           *Registry
	revokes       *RevokeRegistry // nil in dev mode
	regRL         *perIPLimiter   // per-token-name registration rate limiter
	dev           bool
	domain        string
	workers       *worker.Group
	log           *zap.Logger
	rl            *rateLimiter
	streamTimeout time.Duration

	// tokenName is set after a successful auth in prod mode and used as the
	// rate-limit key for tunnel registration.
	tokenName string

	// allowLowPorts mirrors ServerConfig.AllowLowLocalPorts (or the env
	// override) so validation does not have to reach back into Server.
	allowLowPorts bool
}

// doHello performs the Hello exchange. Returns false (and closes the
// connection) if the peer is missing the Hello frame or speaks a version we
// do not understand. The implementation is deliberately permissive on the
// optional Capabilities field — unknown names are ignored so future clients
// can advertise new flags safely.
func (h *connHandler) doHello(_ context.Context, ctrl *quic.Stream, ip string) bool {
	_ = ctrl.SetReadDeadline(time.Now().Add(streamHeaderTimeout))
	msg, err := proto.ReadMsg(ctrl)
	if err != nil || msg.Type != proto.TypeHello {
		h.log.Warn("missing hello frame",
			zap.String("ip", ip),
			zap.Error(err),
		)
		_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "expected hello"})
		_ = h.conn.CloseWithError(2, "protocol error")
		return false
	}
	if msg.Version != proto.ProtocolVersion {
		h.log.Warn("unsupported protocol version",
			zap.String("ip", ip),
			zap.Int("client_version", msg.Version),
			zap.Int("server_version", proto.ProtocolVersion),
		)
		_ = proto.WriteMsg(ctrl, &proto.ControlMsg{
			Type:    proto.TypeError,
			Version: proto.ProtocolVersion,
			Error:   fmt.Sprintf("server speaks protocol version %d", proto.ProtocolVersion),
		})
		_ = h.conn.CloseWithError(2, "version mismatch")
		return false
	}
	_ = ctrl.SetReadDeadline(time.Time{})
	if err := proto.WriteMsg(ctrl, &proto.ControlMsg{
		Type:    proto.TypeHelloOK,
		Version: proto.ProtocolVersion,
	}); err != nil {
		h.log.Error("send hello_ok", zap.String("ip", ip), zap.Error(err))
		_ = h.conn.CloseWithError(2, "protocol error")
		return false
	}
	return true
}

// run opens the control stream, authenticates the client, and processes
// tunnel registration requests until the connection closes.
func (h *connHandler) run(ctx context.Context) {
	ip := extractIP(h.conn.RemoteAddr())

	// Reject immediately if this IP is rate-limited.
	if h.rl.IsBlocked(ip) {
		h.log.Warn("connection rejected — IP rate-limited",
			zap.String("ip", ip),
			zap.Error(fmt.Errorf("%w: %s", ErrIPBlocked, ip)),
		)
		_ = h.conn.CloseWithError(2, "rate limited")
		return
	}

	ctrl, err := h.conn.AcceptStream(ctx)
	if err != nil {
		h.log.Error("accept control stream", zap.Error(err))
		return
	}
	defer ctrl.Close()

	// ── version negotiation ────────────────────────────────────────────────
	// Hello is the first frame on the control stream and carries the wire
	// version the peer speaks. Rejecting unknown versions cleanly here is
	// what lets us evolve the protocol later without burning an ALPN bump.
	if !h.doHello(ctx, ctrl, ip) {
		return
	}

	// ── authentication ──────────────────────────────────────────────────────
	// Always read the auth frame — the client always sends it, even in dev mode,
	// so both sides use the same wire protocol regardless of auth mode.
	{
		msg, err := proto.ReadMsg(ctrl)
		if err != nil || msg.Type != proto.TypeAuth {
			authErr := fmt.Errorf("%w: bad auth frame", ErrAuthFailed)
			if err != nil {
				authErr = fmt.Errorf("%w: bad auth frame: %w", ErrAuthFailed, err)
			}
			if !h.dev {
				blocked := h.rl.RecordFailure(ip)
				h.log.Warn("bad auth frame",
					zap.String("ip", ip),
					zap.Bool("now_blocked", blocked),
					zap.Error(authErr),
				)
			} else {
				h.log.Warn("bad auth frame (dev)", zap.String("ip", ip), zap.Error(authErr))
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
			tokenHint := proto.RedactToken(msg.Token)
			name, found, err := h.ts.OwnerOf(ctx, msg.Token)
			if err != nil || !found || name == "" {
				blocked := h.rl.RecordFailure(ip)
				h.log.Warn("auth rejected",
					zap.String("ip", ip),
					zap.String("token_prefix", tokenHint),
					zap.Bool("now_blocked", blocked),
					zap.Error(fmt.Errorf("%w: invalid token", ErrAuthFailed)),
				)
				_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "invalid token"})
				_ = h.conn.CloseWithError(2, "auth failed")
				return
			}

			h.tokenName = name
			// Register a revoke callback before sending TypeAuthOK, then
			// re-check that the token still exists. This three-step pattern
			// closes the race where Delete fires between OwnerOf and Register.
			unregister := h.revokes.Register(name, func() {
				_ = h.conn.CloseWithError(4, "token revoked")
			})
			defer unregister()

			if _, stillFound, _ := h.ts.OwnerOf(ctx, msg.Token); !stillFound {
				unregister()
				h.log.Info("token revoked during auth",
					zap.String("ip", ip),
					zap.String("token_prefix", tokenHint),
				)
				_ = h.conn.CloseWithError(4, "token revoked")
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

			// Apply a deadline context so the connection closes automatically
			// when the token expires. Zero expiry = no deadline.
			if expiry, err := h.ts.TokenExpiry(ctx, msg.Token); err != nil {
				h.log.Warn("could not determine token expiry — connection will not auto-disconnect at TTL",
					zap.String("ip", ip),
					zap.String("token_prefix", tokenHint),
					zap.Error(err),
				)
			} else if !expiry.IsZero() {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, expiry)
				defer cancel()
				context.AfterFunc(ctx, func() {
					if ctx.Err() == context.DeadlineExceeded {
						h.log.Info("token expired, closing connection",
							zap.String("ip", ip),
							zap.String("token_prefix", tokenHint),
							zap.Time("expired_at", expiry),
							zap.Error(fmt.Errorf("%w at %s", ErrTokenExpired, expiry.Format(time.RFC3339))),
						)
						_ = h.conn.CloseWithError(3, "token expired")
					}
				})
			}
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
		// Idle deadline on the post-auth control stream so a silent
		// authenticated client cannot squat on server resources. Reset on
		// every successful read.
		if err := ctrl.SetReadDeadline(time.Now().Add(controlStreamIdle)); err != nil {
			h.log.Error("set control idle deadline", zap.String("ip", ip), zap.Error(err))
			return
		}
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
		// Per-token registration rate limit. Caps churn from a single token
		// reconnecting and re-registering subdomains/ports rapidly. In dev
		// mode tokenName is empty and the limit is keyed by remote IP.
		regKey := h.tokenName
		if regKey == "" {
			regKey = ip
		}
		if h.regRL != nil && !h.regRL.Allow(regKey) {
			h.log.Warn("tunnel registration rate-limited",
				zap.String("ip", ip),
				zap.String("token", regKey),
			)
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "registration rate limit exceeded"})
			continue
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
					h.log.Error("generate random subdomain", zap.String("ip", ip), zap.Error(err))
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
			if err := h.validateTCPLocalPort(msg.Port); err != nil {
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
				serveTCPTunnel(ctx, h.conn, tun.ID, tun.Port, h.reg, h.workers, h.streamTimeout, bindCh, h.log)
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
		case proto.ProtoWT:
			subdomain := msg.Name
			if subdomain == "" {
				subdomain, err = randomSubdomain()
				if err != nil {
					h.log.Error("generate random subdomain", zap.String("ip", ip), zap.Error(err))
					_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "internal error"})
					continue
				}
			} else if verr := validateSubdomain(subdomain); verr != nil {
				h.log.Warn("invalid subdomain rejected",
					zap.String("ip", ip),
					zap.String("name", subdomain),
					zap.Error(verr),
				)
				_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: verr.Error()})
				continue
			}
			tun, regErr := h.reg.RegisterWT(subdomain, h.conn, msg.AllowedOrigins)
			if regErr != nil {
				h.log.Warn("WT tunnel registration failed",
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
			h.log.Info("WT tunnel registered",
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

// randomSubdomain generates a cryptographically random 20-hex-char subdomain.
// 10 bytes → 80 bits of entropy. Resists birthday-style enumeration on
// servers with a large active-tunnel population.
func randomSubdomain() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate subdomain: %w", err)
	}
	return hex.EncodeToString(b), nil
}

