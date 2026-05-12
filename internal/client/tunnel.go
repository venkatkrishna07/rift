package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/venkatkrishna07/rift/internal/config"
	"github.com/venkatkrishna07/rift/internal/proto"
	"github.com/venkatkrishna07/rift/internal/relay"
)

// streamHeaderTimeout is the deadline for reading the tunnel header sent by
// the server. Prevents stalled streams from holding goroutines indefinitely.
const streamHeaderTimeout = 10 * time.Second

func (c *Client) acceptDataStreams(ctx context.Context, conn *quic.Conn, tunnels map[uint32]config.TunnelSpec) error {
	// Uni-stream accept loop runs in parallel with bidi for WT uni-streams
	// coming from the server. Exits when the parent context is cancelled
	// (server connection closed).
	c.workers.Go("uni-stream-accept", func() {
		for {
			u, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			c.workers.Go(fmt.Sprintf("uni-stream-%d", u.StreamID()), func() {
				c.handleUniStream(u, tunnels)
			})
		}
	})

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept data stream: %w", err)
		}
		c.workers.Go(fmt.Sprintf("stream-%d", stream.StreamID()), func() {
			c.handleStream(stream, tunnels)
		})
	}
}

// handleUniStream consumes a server-initiated unidirectional QUIC stream,
// reads the 8-byte tunnel header, and writes the remaining bytes to the
// tunnel's local TCP target. Used for WebTransport uni-streams from
// visitors: write-only, no return path.
func (c *Client) handleUniStream(stream *quic.ReceiveStream, tunnels map[uint32]config.TunnelSpec) {
	hdr, err := proto.ReadHeader(stream)
	if err != nil {
		c.log.Debug("read uni tunnel header", zap.Error(err))
		return
	}
	spec, ok := tunnels[hdr.TunnelID]
	if !ok {
		c.log.Warn("unknown tunnel ID on uni-stream", zap.Uint32("tunnel_id", hdr.TunnelID))
		return
	}
	local, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", spec.LocalPort))
	if err != nil {
		c.log.Error("dial local service for uni-stream", zap.Error(err), zap.Uint16("port", spec.LocalPort))
		return
	}
	defer local.Close()

	if _, err := io.Copy(local, stream); err != nil {
		c.log.Debug("uni-stream copy ended", zap.Error(err))
	}
}

func (c *Client) handleStream(stream *quic.Stream, tunnels map[uint32]config.TunnelSpec) {
	defer stream.Close()

	// Short deadline for header read; clear before entering relay.
	if err := stream.SetDeadline(time.Now().Add(streamHeaderTimeout)); err != nil {
		c.log.Error("set stream header deadline", zap.Error(err))
		return
	}
	hdr, err := proto.ReadHeader(stream)
	if err != nil {
		c.log.Error("read tunnel header", zap.Error(err))
		return
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		c.log.Error("clear stream deadline", zap.Error(err))
		return
	}

	spec, ok := tunnels[hdr.TunnelID]
	if !ok {
		c.log.Error("unknown tunnel ID", zap.Uint32("tunnel_id", hdr.TunnelID))
		return
	}
	local, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", spec.LocalPort))
	if err != nil {
		c.log.Error("dial local service", zap.Error(err), zap.Uint16("port", spec.LocalPort))
		return
	}

	c.log.Debug("relaying", zap.Uint32("id", hdr.TunnelID), zap.Uint16("port", spec.LocalPort))
	relay.Relay(local, stream, c.cfg.EffectiveStreamTimeout(), c.log)
}
