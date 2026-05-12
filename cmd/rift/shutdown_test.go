package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGracefulShutdownCtx_RunReturnsBeforeSignal(t *testing.T) {
	want := errors.New("run failed")
	got := runWithGracefulShutdownCtx(context.Background(),
		func(context.Context) error { return want },
		func(context.Context) error { t.Fatal("shutdown should not run"); return nil },
		1*time.Second,
	)
	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGracefulShutdownCtx_SignalTriggersShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	shutdownCalled := make(chan struct{})

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	err := runWithGracefulShutdownCtx(ctx,
		func(c context.Context) error {
			<-c.Done()
			return nil
		},
		func(context.Context) error {
			close(shutdownCalled)
			return nil
		},
		1*time.Second,
	)
	if err != nil {
		t.Errorf("expected nil err, got %v", err)
	}
	select {
	case <-shutdownCalled:
	default:
		t.Error("shutdownFn was not invoked")
	}
}

func TestGracefulShutdownCtx_TimeoutWrapsShutdownError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	runDone := make(chan struct{})
	wantShutdownErr := errors.New("drain timed out")

	err := runWithGracefulShutdownCtx(ctx,
		func(c context.Context) error {
			<-c.Done()
			<-runDone
			return nil
		},
		func(context.Context) error { return wantShutdownErr },
		1*time.Second,
	)
	close(runDone)

	if !errors.Is(err, wantShutdownErr) {
		t.Errorf("expected wrapped %v, got %v", wantShutdownErr, err)
	}
}

func TestGracefulShutdownCtx_ShutdownReturnsRunErr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	wantRunErr := errors.New("run errored on exit")

	err := runWithGracefulShutdownCtx(ctx,
		func(c context.Context) error {
			<-c.Done()
			return wantRunErr
		},
		func(context.Context) error { return nil },
		1*time.Second,
	)
	if !errors.Is(err, wantRunErr) {
		t.Errorf("expected %v, got %v", wantRunErr, err)
	}
}
