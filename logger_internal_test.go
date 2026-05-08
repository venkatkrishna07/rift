package rift

import (
	"sync"
	"testing"

	"go.uber.org/zap"
)

type captureLogger struct {
	mu      sync.Mutex
	entries []capturedEntry
}

type capturedEntry struct {
	level string
	msg   string
	kv    []any
}

func (c *captureLogger) record(level, msg string, kv []any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]any, len(kv))
	copy(cp, kv)
	c.entries = append(c.entries, capturedEntry{level: level, msg: msg, kv: cp})
}

func (c *captureLogger) Debug(msg string, kv ...any) { c.record("debug", msg, kv) }
func (c *captureLogger) Info(msg string, kv ...any)  { c.record("info", msg, kv) }
func (c *captureLogger) Warn(msg string, kv ...any)  { c.record("warn", msg, kv) }
func (c *captureLogger) Error(msg string, kv ...any) { c.record("error", msg, kv) }

func TestZapFromLoggerEndToEnd(t *testing.T) {
	cap := &captureLogger{}
	z := zapFromLogger(cap)

	z.Debug("dmsg", zap.String("k1", "v1"))
	z.Info("imsg", zap.Int("n", 42))
	z.Warn("wmsg", zap.String("a", "b"), zap.String("c", "d"))
	z.Error("emsg", zap.Bool("ok", false))

	if got, want := len(cap.entries), 4; got != want {
		t.Fatalf("entries: got %d want %d", got, want)
	}
	cases := []struct {
		level string
		msg   string
		kv    []any
	}{
		{"debug", "dmsg", []any{"k1", "v1"}},
		{"info", "imsg", []any{"n", int64(42)}},
		{"warn", "wmsg", []any{"a", "b", "c", "d"}},
		{"error", "emsg", []any{"ok", false}},
	}
	for i, c := range cases {
		e := cap.entries[i]
		if e.level != c.level || e.msg != c.msg {
			t.Errorf("entry[%d]: %v %q, want %v %q", i, e.level, e.msg, c.level, c.msg)
		}
		if len(e.kv) != len(c.kv) {
			t.Errorf("entry[%d] kv len: got %d want %d (%v)", i, len(e.kv), len(c.kv), e.kv)
			continue
		}
		for j := range c.kv {
			if e.kv[j] != c.kv[j] {
				t.Errorf("entry[%d] kv[%d]: got %#v want %#v", i, j, e.kv[j], c.kv[j])
			}
		}
	}
}

func TestZapFromLoggerNilSafe(t *testing.T) {
	z := zapFromLogger(nil)
	if z == nil {
		t.Fatal("zapFromLogger(nil) returned nil zap")
	}
	z.Info("noop")
	z.Debug("noop")
	z.Error("noop", zap.String("k", "v"))
}

func TestZapFromLoggerNopShortCircuit(t *testing.T) {
	z := zapFromLogger(nopLogger{})
	z.Info("noop", zap.String("k", "v"))
}

func TestFieldsToKVPreservesOrder(t *testing.T) {
	cap := &captureLogger{}
	z := zapFromLogger(cap)

	for range 50 {
		z.Info("ord",
			zap.String("first", "1"),
			zap.String("second", "2"),
			zap.String("third", "3"),
		)
	}

	for i, e := range cap.entries {
		want := []any{"first", "1", "second", "2", "third", "3"}
		if len(e.kv) != len(want) {
			t.Fatalf("entry[%d] len mismatch: %v", i, e.kv)
		}
		for j := range want {
			if e.kv[j] != want[j] {
				t.Fatalf("entry[%d] kv[%d]: got %v want %v (full: %v)", i, j, e.kv[j], want[j], e.kv)
			}
		}
	}
}
