// Package relay provides bidirectional stream copying with an optional
// idle-timeout watchdog. Buffers are pooled to reduce allocations.
package relay

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
	"go.uber.org/zap"
)

// errCodeRelayIdle is the QUIC application error code emitted when the
// idle watchdog aborts a stream. A non-zero value lets the peer
// distinguish a relay-side idle abort from a graceful close (code 0).
const errCodeRelayIdle quic.StreamErrorCode = 1

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// Relay copies data between a and b concurrently until either side closes.
//
// If timeout > 0 an idle watchdog aborts both sides when no bytes are
// transferred for the timeout duration. For QUIC streams the watchdog uses
// CancelRead+CancelWrite so the peer observes a real stream-reset rather
// than a silent EOF. For non-QUIC RWCs the watchdog falls back to Close.
// Both a and b are always closed before Relay returns.
func Relay(a, b io.ReadWriteCloser, timeout time.Duration, log *zap.Logger) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // stops watchdog when relay finishes normally

	ra, rb := io.ReadWriteCloser(a), io.ReadWriteCloser(b)

	if timeout > 0 {
		var last atomic.Int64
		last.Store(time.Now().UnixNano())

		ra = &activityRWC{ReadWriteCloser: a, last: &last}
		rb = &activityRWC{ReadWriteCloser: b, last: &last}

		go func() {
			// Poll 4× per timeout period for a responsive watchdog.
			ticker := time.NewTicker(timeout / 4)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					idle := time.Since(time.Unix(0, last.Load()))
					if idle > timeout {
						log.Debug("relay idle timeout — aborting streams",
							zap.Duration("idle", idle),
							zap.Duration("timeout", timeout),
						)
						abortOrClose(a)
						abortOrClose(b)
						return
					}
				}
			}
		}()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyHalf(ra, rb, log) }()
	go func() { defer wg.Done(); copyHalf(rb, ra, log) }()
	wg.Wait()
}

// abortOrClose cancels a QUIC or WebTransport stream with a non-zero error
// code so the peer sees a real stream-reset on idle-timeout. For everything
// else (plain net.Conn, etc.) it falls back to a Close.
func abortOrClose(rwc io.ReadWriteCloser) {
	switch s := rwc.(type) {
	case *quic.Stream:
		s.CancelRead(errCodeRelayIdle)
		s.CancelWrite(errCodeRelayIdle)
	case *webtransport.Stream:
		s.CancelRead(webtransport.StreamErrorCode(errCodeRelayIdle))
		s.CancelWrite(webtransport.StreamErrorCode(errCodeRelayIdle))
	default:
		_ = rwc.Close()
	}
}

// activityRWC wraps an io.ReadWriteCloser and records the nanosecond timestamp
// of the last successful byte transfer in the shared last counter.
type activityRWC struct {
	io.ReadWriteCloser
	last *atomic.Int64
}

func (a *activityRWC) Read(p []byte) (int, error) {
	n, err := a.ReadWriteCloser.Read(p)
	if n > 0 {
		a.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (a *activityRWC) Write(p []byte) (int, error) {
	n, err := a.ReadWriteCloser.Write(p)
	if n > 0 {
		a.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func copyHalf(dst io.WriteCloser, src io.Reader, log *zap.Logger) {
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	if _, err := io.CopyBuffer(dst, src, *buf); err != nil && !errors.Is(err, io.EOF) {
		log.Debug("relay copy ended", zap.Error(err))
	}
	if err := dst.Close(); err != nil && !errors.Is(err, io.EOF) {
		log.Debug("relay close ended", zap.Error(err))
	}
}
