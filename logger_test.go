package rift_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/venkatkrishna07/rift"
)

func TestSlogAdapterDelegates(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := rift.SlogAdapter(slog.New(h))
	l.Debug("dmsg", "k", "v")
	l.Info("imsg", "k", "v")
	l.Warn("wmsg", "k", "v")
	l.Error("emsg", "k", "v")
	out := buf.String()
	for _, want := range []string{"dmsg", "imsg", "wmsg", "emsg", "k=v"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output: %s", want, out)
		}
	}
}

func TestNopLoggerNoPanic(t *testing.T) {
	l := rift.NopLogger()
	l.Debug("x")
	l.Info("x")
	l.Warn("x")
	l.Error("x", "k", 1)
}
