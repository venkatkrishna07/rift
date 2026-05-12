// Package proto defines the rift wire protocol.
//
// Control stream: 4-byte big-endian length prefix followed by a JSON-encoded ControlMsg.
// Data streams:   8-byte tunnel header [tunnelID uint32 BE][reserved 4 bytes].
package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"go.uber.org/zap/zapcore"
)

// Message type constants.
const (
	TypeHello    = "hello"
	TypeHelloOK  = "hello_ok"
	TypeAuth     = "auth"
	TypeAuthOK   = "auth_ok"
	TypeRegister = "register"
	TypeOK       = "ok"
	TypeError    = "error"
)

// ProtocolVersion is the rift wire-protocol version this binary speaks. Sent
// in the Hello frame at the start of every control stream so future clients
// and servers can negotiate features without bumping the ALPN.
//
// Version policy:
//
//   - ALPN ("rift-v1") changes when the framing-level invariants break
//     and the two sides cannot meaningfully communicate. Bump rarely.
//   - ProtocolVersion changes when the semantics of an existing field or
//     frame change in a way an older peer would misinterpret.
//   - Capabilities (the Hello ControlMsg's Capabilities field) carry
//     additive features. A peer that does not understand a capability
//     simply does not use it; this is the preferred extension path.
const ProtocolVersion = 2

// Capability names exchanged in the Hello frame. New capabilities should
// be added here and gated at the call site via a helper like
// `HasCapability(caps, CapWTDgramV2)`.
const (
	// CapWTDgramV2 advertises the v2 WT datagram wire envelope:
	// [tunnelID:4][sessionID:4][payload]. Required for per-session
	// routing; absence means the peer only understands the v1 envelope
	// [tunnelID:4][payload], which is incompatible with v0.1.1+ servers.
	CapWTDgramV2 = "wt.dgram.v2"
)

// DefaultCapabilities is the capability set this binary advertises in
// Hello. Keep small; add a capability only when its absence would change
// peer behaviour.
var DefaultCapabilities = []string{CapWTDgramV2}

// HasCapability reports whether caps contains name. Linear scan because
// capability lists are tiny in practice (single-digit entries).
func HasCapability(caps []string, name string) bool {
	for _, c := range caps {
		if c == name {
			return true
		}
	}
	return false
}

// Proto identifies the tunnel protocol.
const (
	ProtoHTTP = "http"
	ProtoTCP  = "tcp"
	// ProtoWT routes incoming HTTP/3 WebTransport sessions on a subdomain
	// (same naming model as ProtoHTTP) to a local TCP service on the client.
	// Each bidi WT stream is spliced 1:1 onto a fresh TCP connection.
	ProtoWT = "wt"
)

// ControlMsg is the JSON payload exchanged on the control stream.
type ControlMsg struct {
	Type     string `json:"type"`
	Token    string `json:"token,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Name     string `json:"name,omitempty"`
	TunnelID uint32 `json:"tunnel_id,omitempty"`
	URL      string `json:"url,omitempty"`
	Addr     string `json:"addr,omitempty"`
	Error    string `json:"error,omitempty"`
	// Version is the protocol version the sender speaks. Populated on Hello.
	Version int `json:"version,omitempty"`
	// Capabilities is the optional feature flag set advertised in Hello.
	// Receivers ignore unknown names — future versions can add capabilities
	// without breaking older peers.
	Capabilities []string `json:"capabilities,omitempty"`
	// AllowedOrigins lists permitted Origin header values for WT tunnels.
	// Empty means deny all cross-origin requests. Exact-match comparison.
	// "*" is accepted as an explicit any-origin escape hatch.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// AllowedWTProtocols lists WebTransport subprotocols the WT tunnel is
	// willing to negotiate; rift echoes the chosen value via WT-Protocol.
	// Empty accepts whatever the browser sends (or none).
	AllowedWTProtocols []string `json:"allowed_wt_protocols,omitempty"`
}

// RedactToken returns the first 8 characters of token followed by "..." for
// safe use in log output. Returns "***" for tokens of 8 characters or fewer.
func RedactToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "..."
}

// String returns a redacted view of the message. Used by %v / %+v in fmt
// callers so an accidental log of a *ControlMsg never includes the raw token.
// Wire encoding goes through json.Marshal in WriteMsg and is unaffected.
func (m *ControlMsg) String() string {
	if m == nil {
		return "<nil ControlMsg>"
	}
	tok := ""
	if m.Token != "" {
		tok = " token=" + RedactToken(m.Token)
	}
	return fmt.Sprintf("ControlMsg{type=%s%s port=%d proto=%s name=%s tunnel_id=%d url=%s addr=%s err=%s}",
		m.Type, tok, m.Port, m.Proto, m.Name, m.TunnelID, m.URL, m.Addr, m.Error)
}

// MarshalLogObject implements zapcore.ObjectMarshaler.
// The Token field is redacted to its first 8 characters, preventing accidental
// bearer-token leakage via zap.Object or zap.Any log calls.
// json.Marshal (used for wire encoding in WriteMsg) is NOT affected.
func (m *ControlMsg) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("type", m.Type)
	if m.Token != "" {
		enc.AddString("token_prefix", RedactToken(m.Token))
	}
	if m.Port != 0 {
		enc.AddUint64("port", uint64(m.Port))
	}
	if m.Proto != "" {
		enc.AddString("proto", m.Proto)
	}
	if m.Name != "" {
		enc.AddString("name", m.Name)
	}
	if m.TunnelID != 0 {
		enc.AddUint64("tunnel_id", uint64(m.TunnelID))
	}
	if m.URL != "" {
		enc.AddString("url", m.URL)
	}
	if m.Addr != "" {
		enc.AddString("addr", m.Addr)
	}
	if m.Error != "" {
		enc.AddString("error", m.Error)
	}
	return nil
}

// WriteMsg serialises msg as a length-prefixed JSON frame.
func WriteMsg(w io.Writer, msg *ControlMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal control msg: %w", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write length prefix: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write control msg payload: %w", err)
	}
	return nil
}

// ReadMsg reads one length-prefixed JSON frame from r.
func ReadMsg(r io.Reader) (*ControlMsg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read length prefix: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > 1<<20 { // sanity cap: 1 MiB
		return nil, fmt.Errorf("control msg too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read control msg payload: %w", err)
	}
	var msg ControlMsg
	if err := json.Unmarshal(buf, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal control msg: %w", err)
	}
	return &msg, nil
}

// TunnelHeader is the 8-byte header prepended to every data stream.
type TunnelHeader struct {
	TunnelID uint32
	// 4 reserved bytes, always zero
}

// WriteHeader writes the 8-byte tunnel header to w.
func WriteHeader(w io.Writer, h TunnelHeader) error {
	var buf [8]byte
	binary.BigEndian.PutUint32(buf[:4], h.TunnelID)
	if _, err := w.Write(buf[:]); err != nil {
		return fmt.Errorf("write tunnel header: %w", err)
	}
	return nil
}

// ReadHeader reads the 8-byte tunnel header from r.
func ReadHeader(r io.Reader) (TunnelHeader, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return TunnelHeader{}, fmt.Errorf("read tunnel header: %w", err)
	}
	return TunnelHeader{TunnelID: binary.BigEndian.Uint32(buf[:4])}, nil
}
