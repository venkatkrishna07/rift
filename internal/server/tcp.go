package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/proto"
	"github.com/venkatkrishna07/rift/internal/relay"
	"github.com/venkatkrishna07/rift/internal/worker"
)

func serveTCPTunnel(ctx context.Context, conn *quic.Conn, id uint32, port uint16, reg *Registry, streamTimeout time.Duration, bindErr chan<- error, log *zap.Logger) {
	log = log.With(zap.Uint32("tunnel_id", id), zap.Uint16("port", port))

	tun := reg.ByID(id)
	if tun == nil {
		log.Error("TCP tunnel not found in registry")
		bindErr <- fmt.Errorf("TCP tunnel not found in registry")
		return
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Error("TCP tunnel bind failed", zap.Error(err))
		bindErr <- fmt.Errorf("bind TCP port %d: %w", port, err)
		return
	}
	bindErr <- nil
	log.Info("TCP tunnel listener ready")
	log.Warn("TCP port bound on all interfaces (0.0.0.0) — no visitor authentication is enforced",
		zap.String("bind", fmt.Sprintf("0.0.0.0:%d", port)),
	)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	defer func() {
		_ = ln.Close()
		reg.Unregister(id)
	}()

	visitors := worker.New(log)
	for {
		visitor, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				visitors.Wait()
				return
			}
			log.Error("TCP accept error", zap.Error(err))
			visitors.Wait()
			return
		}
		if !tun.TryAddVisitor() {
			log.Warn("visitor limit reached, dropping connection")
			_ = visitor.Close()
			continue
		}
		visitors.Go(fmt.Sprintf("tcp-visitor-%s", visitor.RemoteAddr()), func() {
			forwardTCPVisitor(ctx, visitor, conn, id, tun, streamTimeout, log)
		})
	}
}

func forwardTCPVisitor(ctx context.Context, visitor net.Conn, conn *quic.Conn, tunnelID uint32, tun *Tunnel, streamTimeout time.Duration, log *zap.Logger) {
	defer visitor.Close()
	defer tun.VisitorDone()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Error("open QUIC stream for TCP visitor", zap.Error(err))
		return
	}

	// Short deadline for header write; clear before entering relay.
	if err := stream.SetDeadline(time.Now().Add(streamHeaderTimeout)); err != nil {
		log.Error("set stream header deadline", zap.Error(err))
		_ = stream.Close()
		return
	}
	if err := proto.WriteHeader(stream, proto.TunnelHeader{TunnelID: tunnelID}); err != nil {
		log.Error("write TCP tunnel header", zap.Error(err))
		_ = stream.Close()
		return
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		log.Error("clear stream deadline", zap.Error(err))
		_ = stream.Close()
		return
	}

	relay.Relay(visitor, stream, streamTimeout, log)
}
