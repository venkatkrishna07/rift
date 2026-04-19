package proto

import (
	"bytes"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestControlMsgTokenRedactedInLogs(t *testing.T) {
	fullToken := "t_" + strings.Repeat("a", 64)
	msg := &ControlMsg{Type: TypeAuth, Token: fullToken}

	var buf bytes.Buffer
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&buf),
		zapcore.DebugLevel,
	)
	zap.New(core).Info("test", zap.Object("msg", msg))

	output := buf.String()
	if strings.Contains(output, fullToken) {
		t.Errorf("full token leaked in log output:\n%s", output)
	}
	if !strings.Contains(output, fullToken[:8]) {
		t.Errorf("token prefix missing — redaction may be broken:\n%s", output)
	}
}

func TestControlMsgWireEncodingUnaffected(t *testing.T) {
	fullToken := "t_" + strings.Repeat("b", 64)
	msg := &ControlMsg{Type: TypeAuth, Token: fullToken}

	var buf bytes.Buffer
	if err := WriteMsg(&buf, msg); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	if !strings.Contains(buf.String(), fullToken) {
		t.Error("wire encoding must contain the full unredacted token")
	}
}

func TestProtoConstants(t *testing.T) {
	if ProtoHTTP != "http" {
		t.Fatalf("ProtoHTTP = %q, want %q", ProtoHTTP, "http")
	}
	if ProtoTCP != "tcp" {
		t.Fatalf("ProtoTCP = %q, want %q", ProtoTCP, "tcp")
	}
}
