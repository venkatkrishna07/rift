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
	TypeAuth     = "auth"
	TypeAuthOK   = "auth_ok"
	TypeRegister = "register"
	TypeOK       = "ok"
	TypeError    = "error"
)

// Proto identifies the tunnel protocol.
const (
	ProtoHTTP = "http"
	ProtoTCP  = "tcp"
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
}

// redactToken returns the first 8 characters of token followed by "..." for
// safe use in log output. Returns "***" for tokens of 8 characters or fewer.
func redactToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "..."
}

// MarshalLogObject implements zapcore.ObjectMarshaler.
// The Token field is redacted to its first 8 characters, preventing accidental
// bearer-token leakage via zap.Object or zap.Any log calls.
// json.Marshal (used for wire encoding in WriteMsg) is NOT affected.
func (m *ControlMsg) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("type", m.Type)
	if m.Token != "" {
		enc.AddString("token_prefix", redactToken(m.Token))
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
