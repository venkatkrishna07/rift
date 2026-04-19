// Package worker provides a goroutine group with named goroutines, panic recovery,
// and an atomic active-count suitable for observability and graceful shutdown.
package worker

import (
	"runtime/debug"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// Group manages a collection of named goroutines.
// Zero value is not usable — create via New.
type Group struct {
	wg    sync.WaitGroup
	count atomic.Int64
	log   *zap.Logger
}

// New returns a ready-to-use Group that logs panics with log.
func New(log *zap.Logger) *Group {
	return &Group{log: log}
}

// Go starts fn in a goroutine named name.
// Panics inside fn are caught, logged, and do not propagate.
func (g *Group) Go(name string, fn func()) {
	g.wg.Add(1)
	g.count.Add(1)
	go func() {
		defer g.wg.Done()
		defer g.count.Add(-1)
		defer g.recoverPanic(name)
		fn()
	}()
}

// Count returns the number of currently running goroutines.
func (g *Group) Count() int64 { return g.count.Load() }

// Wait blocks until all goroutines started by Go have returned.
func (g *Group) Wait() { g.wg.Wait() }

func (g *Group) recoverPanic(name string) {
	r := recover()
	if r == nil {
		return
	}
	g.log.Error("goroutine panicked — recovered",
		zap.String("worker", name),
		zap.Any("panic", r),
		zap.String("stack", string(debug.Stack())),
	)
}
