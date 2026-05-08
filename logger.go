package rift

import (
	"log/slog"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the minimal logging interface accepted by rift. Use SlogAdapter
// to plug in a *slog.Logger, or NopLogger for silence. To use zap, write a
// thin shim that satisfies this interface — rift does not import zap from
// its public API.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Logger interface {
	Debug(msg string, kv ...any)
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

// SlogAdapter wraps a *slog.Logger so it satisfies Logger.
func SlogAdapter(l *slog.Logger) Logger { return slogAdapter{l: l} }

type slogAdapter struct{ l *slog.Logger }

func (s slogAdapter) Debug(msg string, kv ...any) { s.l.Debug(msg, kv...) }
func (s slogAdapter) Info(msg string, kv ...any)  { s.l.Info(msg, kv...) }
func (s slogAdapter) Warn(msg string, kv ...any)  { s.l.Warn(msg, kv...) }
func (s slogAdapter) Error(msg string, kv ...any) { s.l.Error(msg, kv...) }

// NopLogger returns a Logger that discards all messages.
func NopLogger() Logger { return nopLogger{} }

type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// zapFromLogger bridges a public Logger into the *zap.Logger consumed by
// internal/. nopLogger short-circuits to zap.NewNop. Otherwise we install a
// custom core that fans entries out to the public Logger.
func zapFromLogger(l Logger) *zap.Logger {
	if l == nil {
		return zap.NewNop()
	}
	if _, ok := l.(nopLogger); ok {
		return zap.NewNop()
	}
	return zap.New(&loggerCore{l: l, level: zapcore.DebugLevel})
}

type loggerCore struct {
	l      Logger
	level  zapcore.Level
	fields []zapcore.Field
}

func (c *loggerCore) Enabled(lvl zapcore.Level) bool { return lvl >= c.level }

func (c *loggerCore) With(fs []zapcore.Field) zapcore.Core {
	cc := *c
	cc.fields = append(append([]zapcore.Field(nil), c.fields...), fs...)
	return &cc
}

func (c *loggerCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c *loggerCore) Write(e zapcore.Entry, fs []zapcore.Field) error {
	all := append(append([]zapcore.Field(nil), c.fields...), fs...)
	kv := fieldsToKV(all)
	switch e.Level {
	case zapcore.DebugLevel:
		c.l.Debug(e.Message, kv...)
	case zapcore.InfoLevel:
		c.l.Info(e.Message, kv...)
	case zapcore.WarnLevel:
		c.l.Warn(e.Message, kv...)
	default:
		c.l.Error(e.Message, kv...)
	}
	return nil
}

func (c *loggerCore) Sync() error { return nil }

// fieldsToKV flattens zap fields to slog-style key,value pairs preserving the
// caller's original field order. Per-field encoders avoid the map iteration
// non-determinism of zapcore.MapObjectEncoder.
func fieldsToKV(fs []zapcore.Field) []any {
	if len(fs) == 0 {
		return nil
	}
	out := make([]any, 0, len(fs)*2)
	for _, f := range fs {
		enc := zapcore.NewMapObjectEncoder()
		f.AddTo(enc)
		v, ok := enc.Fields[f.Key]
		if !ok {
			continue
		}
		out = append(out, f.Key, v)
	}
	return out
}
