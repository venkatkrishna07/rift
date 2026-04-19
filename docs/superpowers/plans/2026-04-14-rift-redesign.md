# rift Redesign Plan — QUIC Tunnel with BadgerDB + zap + worker.Group

**Date:** 2026-04-14  
**Author:** Principal Software Engineer (Claude)  
**Status:** Active

## Stack

| Concern | Library | Version |
|---------|---------|---------|
| QUIC transport | `github.com/quic-go/quic-go` | v0.50.1 |
| Structured logging | `go.uber.org/zap` | v1.27.0 |
| Embedded KV store | `github.com/dgraph-io/badger/v4` | v4.9.1 |
| Goroutine lifecycle | `golang.org/x/sync/errgroup` | latest |
| TLS autocert | `golang.org/x/crypto/acme/autocert` | latest |
| Go version | `go 1.24` | — |

## Architecture Summary

```
cmd/rift/
  main.go                  ← flag parsing, zap init, signal handling

internal/
  config/      config.go   ← typed ServerConfig, ClientConfig, TunnelSpec structs
  proto/       proto.go    ← 4-byte length-prefix JSON control + 8-byte tunnel header
  store/       store.go    ← TokenStore interface + GenerateToken()
               badger.go   ← BadgerDB implementation
  worker/      group.go    ← named goroutines, panic recovery, atomic counter
  relay/       relay.go    ← sync.Pool 32 KiB bidirectional copy
  server/      server.go   ← Server struct, Run (quic.Transport + errgroup)
               conn.go     ← per-connection auth + tunnel registration
               http.go     ← HTTPS subdomain reverse proxy + WebSocket
               tcp.go      ← TCP tunnel listener + forwarder
               tls.go      ← DevTLSConfig + ProdTLSConfig (autocert)
               registry.go ← thread-safe tunnel registry (RWMutex)
  client/      client.go   ← Client struct, Connect with exponential backoff
               tunnel.go   ← acceptDataStreams + handleStream relay
```

---

## Task 1: Project Scaffold

**Files:**
- Create: `go.mod`
- Create: `cmd/rift/main.go` (stub)
- Create: `.gitignore`

- [ ] **Step 1: Initialize module**

```bash
cd ~/Downloads/Projects/Personal/rift
git init
go mod init github.com/user/rift
go get github.com/quic-go/quic-go@v0.50.1
go get go.uber.org/zap@v1.27.0
go get github.com/dgraph-io/badger/v4@v4.9.1
go get golang.org/x/sync@latest
go get golang.org/x/crypto@latest
```

- [ ] **Step 2: Create directory tree**

```bash
mkdir -p cmd/rift internal/{config,proto,store,worker,relay,server,client}
```

- [ ] **Step 3: Create stub main.go**

`cmd/rift/main.go`:
```go
package main

import (
	"fmt"
	"os"

	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync() //nolint:errcheck

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: rift <server|client>")
		os.Exit(1)
	}
	logger.Info("rift starting", zap.String("subcmd", os.Args[1]))
}
```

- [ ] **Step 4: Create .gitignore**

`.gitignore`:
```
rift
*.pem
/tmp/
```

- [ ] **Step 5: Verify scaffold compiles**

```bash
go build ./cmd/rift/
```

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum cmd/ .gitignore
git commit -m "chore: initialize rift module with quic-go, zap, badger dependencies"
```

---

## Task 2: Config Package

**Files:**
- Create: `internal/config/config.go`

- [ ] **Step 1: Implement typed config structs**

`internal/config/config.go`:
```go
// Package config holds typed configuration structs for rift server and client.
package config

// ServerConfig holds all server-side configuration.
type ServerConfig struct {
	ListenAddr string // e.g. ":443" — shared by QUIC (UDP) and HTTPS (TCP)
	Domain     string // base domain, e.g. "tunnel.example.com"
	Dev        bool   // dev mode: self-signed cert, no token auth
	DBPath     string // BadgerDB data directory
}

// ClientConfig holds all client-side configuration.
type ClientConfig struct {
	Server   string       // host or host:port of rift server
	Token    string       // auth token (overrides DB lookup when set)
	Tunnels  []TunnelSpec // tunnels to register
	Insecure bool         // skip TLS cert verification (dev mode only)
	DBPath   string       // BadgerDB data directory for token persistence
}

// TunnelSpec describes a single tunnel the client wants to expose.
type TunnelSpec struct {
	LocalPort uint16 // local TCP port to forward to
	Proto     string // "http" or "tcp"
	Name      string // optional human name; server picks subdomain/port if empty
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/config/
```

- [ ] **Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): typed ServerConfig, ClientConfig, TunnelSpec structs"
```

---

## Task 3: Proto Package — Control Messages + Tunnel Header

**Files:**
- Create: `internal/proto/proto.go`

- [ ] **Step 1: Implement wire protocol**

`internal/proto/proto.go`:
```go
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
)

// Message type constants.
const (
	TypeAuth     = "auth"
	TypeAuthOK   = "auth_ok"
	TypeRegister = "register"
	TypeOK       = "ok"
	TypeError    = "error"
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
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/proto/
```

- [ ] **Step 3: Commit**

```bash
git add internal/proto/proto.go
git commit -m "feat(proto): 4-byte length-prefix JSON control frames + 8-byte data stream header"
```

---

## Task 4: Store Package — TokenStore Interface + BadgerDB

**Files:**
- Create: `internal/store/store.go`
- Create: `internal/store/badger.go`

- [ ] **Step 1: Define TokenStore interface + GenerateToken**

`internal/store/store.go`:
```go
// Package store provides token persistence for rift server and client.
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// TokenStore abstracts token persistence — swappable without touching business logic.
type TokenStore interface {
	// Validate reports whether token is a valid server-issued token.
	Validate(ctx context.Context, token string) (bool, error)
	// Add stores a new named token on the server side.
	Add(ctx context.Context, name, token string) error
	// Lookup retrieves a stored token by key (client-side: key = server address).
	Lookup(ctx context.Context, key string) (string, error)
	// Save stores an arbitrary key→token mapping (client-side persistence).
	Save(ctx context.Context, key, token string) error
	// Close flushes and releases resources.
	Close() error
}

// GenerateToken returns a cryptographically random token with format "t_<64 hex chars>".
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return "t_" + hex.EncodeToString(b), nil
}
```

- [ ] **Step 2: Implement BadgerDB backend**

`internal/store/badger.go`:
```go
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"
)

const (
	prefixToken  = "token:"  // server: name → token
	prefixClient = "client:" // client: server-addr → token
)

// BadgerStore is a BadgerDB-backed TokenStore.
type BadgerStore struct {
	db *badger.DB
}

// OpenBadger opens (or creates) a BadgerDB at path.
func OpenBadger(path string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(path)
	opts.Logger = nil        // suppress badger's own logging; zap handles ours
	opts.SyncWrites = false  // async writes — WAL still guarantees durability on crash
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open badger at %s: %w", path, err)
	}
	return &BadgerStore{db: db}, nil
}

// Close flushes pending writes and closes the database.
func (s *BadgerStore) Close() error { return s.db.Close() }

// Add stores name→token under the server-side prefix.
func (s *BadgerStore) Add(_ context.Context, name, token string) error {
	key := []byte(prefixToken + name)
	return s.db.Update(func(tx *badger.Txn) error {
		return tx.Set(key, []byte(token))
	})
}

// Validate checks whether token exists among the stored server tokens.
func (s *BadgerStore) Validate(_ context.Context, token string) (bool, error) {
	var found bool
	err := s.db.View(func(tx *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		it := tx.NewIterator(opts)
		defer it.Close()
		prefix := []byte(prefixToken)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			val, err := it.Item().ValueCopy(nil)
			if err != nil {
				return err
			}
			if string(val) == token {
				found = true
				return nil
			}
		}
		return nil
	})
	return found, err
}

// Lookup retrieves a token by key (client-side: key = server address).
func (s *BadgerStore) Lookup(_ context.Context, key string) (string, error) {
	var val []byte
	err := s.db.View(func(tx *badger.Txn) error {
		item, err := tx.Get([]byte(prefixClient + key))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		val, err = item.ValueCopy(nil)
		return err
	})
	return string(val), err
}

// Save stores key→token under the client-side prefix.
func (s *BadgerStore) Save(_ context.Context, key, token string) error {
	return s.db.Update(func(tx *badger.Txn) error {
		return tx.Set([]byte(prefixClient+key), []byte(token))
	})
}
```

- [ ] **Step 3: Verify compilation**

```bash
go build ./internal/store/
```

- [ ] **Step 4: Commit**

```bash
git add internal/store/store.go internal/store/badger.go
git commit -m "feat(store): TokenStore interface + BadgerDB v4 implementation with namespaced keys"
```

---

## Task 5: Worker Package — Named Goroutines with Panic Recovery

**Files:**
- Create: `internal/worker/group.go`

- [ ] **Step 1: Implement worker.Group**

`internal/worker/group.go`:
```go
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
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/worker/
```

- [ ] **Step 3: Commit**

```bash
git add internal/worker/group.go
git commit -m "feat(worker): named goroutine group with panic recovery and atomic counter"
```

---

## Task 6: Relay Package — Bidirectional Copy with sync.Pool Buffer

**Files:**
- Create: `internal/relay/relay.go`

- [ ] **Step 1: Implement relay**

`internal/relay/relay.go`:
```go
// Package relay provides bidirectional stream copying using pooled 32 KiB buffers.
package relay

import (
	"io"
	"sync"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// Relay copies data between a and b concurrently until either side closes.
// Both a and b are closed before Relay returns.
func Relay(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyHalf(a, b) }()
	go func() { defer wg.Done(); copyHalf(b, a) }()
	wg.Wait()
}

func copyHalf(dst io.WriteCloser, src io.Reader) {
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	_, _ = io.CopyBuffer(dst, src, *buf)
	_ = dst.Close()
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/relay/
```

- [ ] **Step 3: Commit**

```bash
git add internal/relay/relay.go
git commit -m "feat(relay): bidirectional copy with sync.Pool 32 KiB buffer"
```

---

## Task 7: Server TLS — Dev Self-Signed + Prod Let's Encrypt

**Files:**
- Create: `internal/server/tls.go`

- [ ] **Step 1: Implement TLS helpers**

`internal/server/tls.go`:
```go
package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// DevTLSConfig generates a self-signed wildcard ECDSA P-256 certificate
// covering domain and *.domain. For development only.
func DevTLSConfig(domain string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate dev key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "*." + domain},
		DNSNames:     []string{domain, "*." + domain},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal dev key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load dev cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ProdTLSConfig returns a *tls.Config that obtains certificates from Let's Encrypt
// via TLS-ALPN-01 for domain and *.domain subdomains. cacheDir stores cached certs.
func ProdTLSConfig(domain, cacheDir string) *tls.Config {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(
			domain,
			"*."+domain,
		),
	}
	cfg := m.TLSConfig()
	cfg.MinVersion = tls.VersionTLS13
	return cfg
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/server/
```

- [ ] **Step 3: Commit**

```bash
git add internal/server/tls.go
git commit -m "feat(server/tls): DevTLSConfig (self-signed wildcard) + ProdTLSConfig (autocert)"
```

---

## Task 8: Server Registry — Thread-Safe Tunnel Map

**Files:**
- Create: `internal/server/registry.go`

- [ ] **Step 1: Implement Registry**

`internal/server/registry.go`:
```go
package server

import (
	"math/rand"
	"sync"

	"github.com/quic-go/quic-go"
)

// Tunnel holds the metadata for a registered tunnel.
type Tunnel struct {
	ID        uint32
	Subdomain string // set for HTTP tunnels
	Port      uint16 // set for TCP tunnels
	Proto     string // "http" or "tcp"
	Conn      quic.Connection
}

// Registry is a thread-safe store of active tunnels.
type Registry struct {
	mu       sync.RWMutex
	byID     map[uint32]*Tunnel
	bySubdom map[string]*Tunnel
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		byID:     make(map[uint32]*Tunnel),
		bySubdom: make(map[string]*Tunnel),
	}
}

// RegisterHTTP registers an HTTP tunnel and returns the assigned Tunnel.
func (r *Registry) RegisterHTTP(subdomain string, conn quic.Connection) *Tunnel {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := &Tunnel{ID: r.nextID(), Subdomain: subdomain, Proto: "http", Conn: conn}
	r.byID[t.ID] = t
	r.bySubdom[subdomain] = t
	return t
}

// RegisterTCP registers a TCP tunnel with a random port in [10000, 65535].
func (r *Registry) RegisterTCP(conn quic.Connection) *Tunnel {
	r.mu.Lock()
	defer r.mu.Unlock()
	port := uint16(10000 + rand.Intn(55536)) //nolint:gosec // random port, not security-sensitive
	t := &Tunnel{ID: r.nextID(), Port: port, Proto: "tcp", Conn: conn}
	r.byID[t.ID] = t
	return t
}

// BySubdomain returns the tunnel for subdomain, or nil.
func (r *Registry) BySubdomain(subdomain string) *Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bySubdom[subdomain]
}

// Unregister removes the tunnel with id.
func (r *Registry) Unregister(id uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.byID[id]
	if !ok {
		return
	}
	delete(r.byID, id)
	if t.Subdomain != "" {
		delete(r.bySubdom, t.Subdomain)
	}
}

// nextID returns a non-zero ID not currently in use. Must be called with mu held.
func (r *Registry) nextID() uint32 {
	for {
		id := rand.Uint32() //nolint:gosec // ID assignment, not security-sensitive
		if id != 0 {
			if _, exists := r.byID[id]; !exists {
				return id
			}
		}
	}
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/server/
```

- [ ] **Step 3: Commit**

```bash
git add internal/server/registry.go
git commit -m "feat(server/registry): thread-safe tunnel registry with RWMutex"
```

---

## Task 9: Server — Per-Connection Handler (Auth + Registration)

**Files:**
- Create: `internal/server/conn.go`

- [ ] **Step 1: Implement connHandler**

`internal/server/conn.go`:
```go
package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/user/rift/internal/proto"
	"github.com/user/rift/internal/store"
)

// connHandler handles a single authenticated QUIC connection from a client.
type connHandler struct {
	conn    quic.Connection
	ts      store.TokenStore // nil in dev mode
	reg     *Registry
	dev     bool
	domain  string
	workers interface{ Go(string, func()) }
	log     *zap.Logger
}

// run opens the control stream, authenticates the client, and processes
// tunnel registration requests until the connection closes.
func (h *connHandler) run(ctx context.Context) {
	ctrl, err := h.conn.AcceptStream(ctx)
	if err != nil {
		h.log.Error("accept control stream", zap.Error(err))
		return
	}
	defer ctrl.Close()

	// ── authentication ──────────────────────────────────────────────────────
	if !h.dev {
		msg, err := proto.ReadMsg(ctrl)
		if err != nil || msg.Type != proto.TypeAuth {
			h.log.Warn("bad auth frame", zap.Error(err))
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "expected auth"})
			return
		}
		ok, err := h.ts.Validate(ctx, msg.Token)
		if err != nil || !ok {
			h.log.Warn("auth rejected", zap.String("remote", h.conn.RemoteAddr().String()))
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "invalid token"})
			return
		}
		if err := proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeAuthOK}); err != nil {
			return
		}
		h.log.Info("client authenticated", zap.String("remote", h.conn.RemoteAddr().String()))
	}

	// ── registration loop ───────────────────────────────────────────────────
	for {
		msg, err := proto.ReadMsg(ctrl)
		if err != nil {
			return // connection closed or error
		}
		if msg.Type != proto.TypeRegister {
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "expected register"})
			return
		}
		switch strings.ToLower(msg.Proto) {
		case "http":
			subdomain := msg.Name
			if subdomain == "" {
				subdomain = fmt.Sprintf("%d", msg.Port)
			}
			tun := h.reg.RegisterHTTP(subdomain, h.conn)
			url := fmt.Sprintf("https://%s.%s", subdomain, h.domain)
			h.log.Info("HTTP tunnel registered",
				zap.String("subdomain", subdomain),
				zap.String("url", url),
				zap.Uint32("tunnel_id", tun.ID),
			)
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{
				Type:     proto.TypeOK,
				TunnelID: tun.ID,
				URL:      url,
			})
		case "tcp":
			tun := h.reg.RegisterTCP(h.conn)
			addr := fmt.Sprintf("%s:%d", h.domain, tun.Port)
			h.log.Info("TCP tunnel registered",
				zap.Uint16("port", tun.Port),
				zap.Uint32("tunnel_id", tun.ID),
			)
			h.workers.Go(fmt.Sprintf("tcp-tunnel-%d", tun.ID), func() {
				serveTCPTunnel(ctx, h.conn, tun.ID, tun.Port, h.reg, h.log)
			})
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{
				Type:     proto.TypeOK,
				TunnelID: tun.ID,
				Addr:     addr,
			})
		default:
			_ = proto.WriteMsg(ctrl, &proto.ControlMsg{
				Type:  proto.TypeError,
				Error: fmt.Sprintf("unknown proto: %s", msg.Proto),
			})
		}
	}
}

// serveTCPTunnel stub — replaced by tcp.go in Task 11.
func serveTCPTunnel(ctx context.Context, conn quic.Connection, id uint32, port uint16, reg *Registry, log *zap.Logger) {
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/server/
```

- [ ] **Step 3: Commit**

```bash
git add internal/server/conn.go
git commit -m "feat(server/conn): per-connection auth + HTTP/TCP tunnel registration handler"
```

---

## Task 10: Server — Main Server Struct + Run

**Files:**
- Create: `internal/server/server.go`

- [ ] **Step 1: Implement Server struct and Run using quic.Transport + errgroup**

`internal/server/server.go`:
```go
// Package server implements the rift QUIC tunnel server.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/user/rift/internal/config"
	"github.com/user/rift/internal/store"
	"github.com/user/rift/internal/worker"
)

// Server is the rift tunnel server.
type Server struct {
	cfg    config.ServerConfig
	ts     store.TokenStore // nil in dev mode
	reg    *Registry
	tlsCfg *tls.Config
	log    *zap.Logger
	wg     *worker.Group
}

// New constructs a Server. ts may be nil when cfg.Dev is true.
func New(cfg config.ServerConfig, ts store.TokenStore, tlsCfg *tls.Config, log *zap.Logger) *Server {
	l := log.With(zap.String("component", "server"))
	return &Server{
		cfg:    cfg,
		ts:     ts,
		reg:    NewRegistry(),
		tlsCfg: tlsCfg,
		log:    l,
		wg:     worker.New(l),
	}
}

// Run starts the QUIC listener and HTTPS server, blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	// QUIC TLS: only the rift ALPN — the HTTPS listener uses a separate clone.
	quicTLS := s.tlsCfg.Clone()
	quicTLS.NextProtos = []string{"rift-v1"}

	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("bind UDP %s: %w", s.cfg.ListenAddr, err)
	}

	// quic.Transport gives us direct control over the UDP socket.
	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.Listen(quicTLS, &quic.Config{
		MaxIdleTimeout:    30 * time.Second,
		KeepAlivePeriod:   15 * time.Second,
		MaxIncomingStreams: 1000,
		Allow0RTT:         true,
	})
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("QUIC listen: %w", err)
	}
	s.log.Info("QUIC listener started", zap.String("addr", s.cfg.ListenAddr))

	httpsTLS := s.tlsCfg.Clone()
	httpsTLS.NextProtos = append([]string{"h2", "http/1.1"}, httpsTLS.NextProtos...)

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return s.acceptLoop(ctx, ln) })
	eg.Go(func() error { return s.serveHTTPS(ctx, httpsTLS) })
	eg.Go(func() error {
		<-ctx.Done()
		_ = ln.Close()
		_ = udpConn.Close()
		return nil
	})

	if err := eg.Wait(); err != nil && ctx.Err() == nil {
		return err
	}
	s.wg.Wait() // drain per-connection goroutines
	return nil
}

// acceptLoop accepts QUIC connections and dispatches a connHandler per connection.
func (s *Server) acceptLoop(ctx context.Context, ln *quic.Listener) error {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Error("QUIC accept error", zap.Error(err))
			return fmt.Errorf("accept: %w", err)
		}
		h := &connHandler{
			conn:    conn,
			ts:      s.ts,
			reg:     s.reg,
			dev:     s.cfg.Dev,
			domain:  s.cfg.Domain,
			workers: s.wg,
			log:     s.log,
		}
		s.wg.Go(fmt.Sprintf("conn-%s", conn.RemoteAddr()), func() {
			h.run(ctx)
		})
	}
}

// serveHTTPS stub — replaced when http.go is written.
func (s *Server) serveHTTPS(ctx context.Context, tlsCfg *tls.Config) error {
	<-ctx.Done()
	return nil
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/server/
```

- [ ] **Step 3: Commit**

```bash
git add internal/server/server.go
git commit -m "feat(server): Server struct with quic.Transport + errgroup lifecycle management"
```

---

## Task 11: Server — HTTP Reverse Proxy + TCP Tunnel

**Files:**
- Create: `internal/server/http.go`
- Create: `internal/server/tcp.go`
- Modify: `internal/server/server.go` (remove serveHTTPS stub)
- Modify: `internal/server/conn.go` (remove serveTCPTunnel stub)

- [ ] **Step 1: Implement HTTP reverse proxy**

`internal/server/http.go`:
```go
package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/user/rift/internal/proto"
	"github.com/user/rift/internal/relay"
)

// serveHTTPS starts the TLS listener and routes visitors to registered HTTP tunnels.
func (s *Server) serveHTTPS(ctx context.Context, tlsCfg *tls.Config) error {
	ln, err := tls.Listen("tcp", s.cfg.ListenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("HTTPS listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.log.Info("HTTPS listener started", zap.String("addr", s.cfg.ListenAddr))

	srv := &http.Server{
		Handler:           &httpHandler{reg: s.reg, log: s.log},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return fmt.Errorf("HTTPS serve: %w", err)
	}
	return nil
}

type httpHandler struct {
	reg *Registry
	log *zap.Logger
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if i := strings.IndexByte(host, ':'); i != -1 {
		host = host[:i]
	}
	subdomain := strings.SplitN(host, ".", 2)[0]
	tun := h.reg.BySubdomain(subdomain)
	if tun == nil {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		h.proxyWebSocket(w, r, tun)
		return
	}
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = r.Host
			req.Header.Set("X-Forwarded-For", clientIP(r.RemoteAddr))
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", r.Host)
		},
		Transport: &tunnelTransport{conn: tun.Conn, tunnelID: tun.ID},
	}
	rp.ServeHTTP(w, r)
}

type tunnelTransport struct {
	conn     quic.Connection
	tunnelID uint32
}

func (t *tunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	stream, err := t.conn.OpenStreamSync(req.Context())
	if err != nil {
		return nil, fmt.Errorf("open QUIC stream: %w", err)
	}
	if err := proto.WriteHeader(stream, proto.TunnelHeader{TunnelID: t.tunnelID}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write header: %w", err)
	}
	if err := req.Write(stream); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream.(io.Reader)), req)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	return resp, nil
}

func (h *httpHandler) proxyWebSocket(w http.ResponseWriter, r *http.Request, tun *Tunnel) {
	stream, err := tun.Conn.OpenStreamSync(r.Context())
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if err := proto.WriteHeader(stream, proto.TunnelHeader{TunnelID: tun.ID}); err != nil {
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if err := r.Write(stream); err != nil {
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		stream.Close()
		http.Error(w, "websocket unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		stream.Close()
		return
	}
	defer clientConn.Close()
	relay.Relay(clientConn, stream.(io.ReadWriteCloser))
}

func clientIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return ip
}
```

- [ ] **Step 2: Implement TCP tunnel**

`internal/server/tcp.go`:
```go
package server

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/user/rift/internal/proto"
	"github.com/user/rift/internal/relay"
)

func serveTCPTunnel(ctx context.Context, conn quic.Connection, id uint32, port uint16, reg *Registry, log *zap.Logger) {
	log = log.With(zap.Uint32("tunnel_id", id), zap.Uint16("port", port))

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Error("TCP tunnel bind failed", zap.Error(err))
		reg.Unregister(id)
		return
	}
	log.Info("TCP tunnel listener ready")

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	defer func() {
		_ = ln.Close()
		reg.Unregister(id)
	}()

	for {
		visitor, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error("TCP accept error", zap.Error(err))
			return
		}
		go forwardTCPVisitor(ctx, visitor, conn, id, log)
	}
}

func forwardTCPVisitor(ctx context.Context, visitor net.Conn, conn quic.Connection, tunnelID uint32, log *zap.Logger) {
	defer visitor.Close()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Error("open QUIC stream for TCP visitor", zap.Error(err))
		return
	}
	defer stream.Close()

	if err := proto.WriteHeader(stream, proto.TunnelHeader{TunnelID: tunnelID}); err != nil {
		log.Error("write TCP tunnel header", zap.Error(err))
		return
	}
	relay.Relay(visitor, stream.(io.ReadWriteCloser))
}
```

- [ ] **Step 3: Remove stubs**

In `server.go` delete:
```go
// serveHTTPS stub — replaced when http.go is written.
func (s *Server) serveHTTPS(ctx context.Context, tlsCfg *tls.Config) error {
	<-ctx.Done()
	return nil
}
```

In `conn.go` delete:
```go
// serveTCPTunnel stub — replaced by tcp.go in Task 11.
func serveTCPTunnel(ctx context.Context, conn quic.Connection, id uint32, port uint16, reg *Registry, log *zap.Logger) {
}
```

- [ ] **Step 4: Verify compilation**

```bash
go build ./internal/server/
```

- [ ] **Step 5: Commit**

```bash
git add internal/server/http.go internal/server/tcp.go internal/server/server.go internal/server/conn.go
git commit -m "feat(server): HTTPS subdomain proxy with WebSocket + TCP tunnel listener"
```

---

## Task 12: Client — QUIC Connect + Auth + Reconnect

**Files:**
- Create: `internal/client/client.go`

- [ ] **Step 1: Implement Client**

`internal/client/client.go`:
```go
// Package client implements the rift tunnel client.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/user/rift/internal/config"
	"github.com/user/rift/internal/proto"
	"github.com/user/rift/internal/store"
	"github.com/user/rift/internal/worker"
)

// Client connects to a rift server and manages tunnel registration.
type Client struct {
	cfg     config.ClientConfig
	ts      store.TokenStore
	log     *zap.Logger
	workers *worker.Group
}

// New creates a Client.
func New(cfg config.ClientConfig, ts store.TokenStore, log *zap.Logger) *Client {
	l := log.With(zap.String("component", "client"))
	return &Client{cfg: cfg, ts: ts, log: l, workers: worker.New(l)}
}

// Connect dials the server and reconnects with exponential backoff until ctx is done.
func (c *Client) Connect(ctx context.Context) {
	const maxBackoff = 30 * time.Second
	backoff := time.Second
	for {
		if err := c.connect(ctx); err != nil && ctx.Err() == nil {
			c.log.Error("disconnected", zap.Error(err), zap.Duration("retry_in", backoff))
			select {
			case <-ctx.Done():
				c.workers.Wait()
				return
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}
		if ctx.Err() != nil {
			c.workers.Wait()
			return
		}
		backoff = time.Second // reset on clean disconnect
	}
}

func (c *Client) connect(ctx context.Context) error {
	addr := c.cfg.Server
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	token := c.cfg.Token
	if token == "" && c.ts != nil {
		var err error
		token, err = c.ts.Lookup(ctx, c.cfg.Server)
		if err != nil {
			return fmt.Errorf("lookup token: %w", err)
		}
	}

	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: c.cfg.Insecure, //nolint:gosec // dev mode only
		NextProtos:         []string{"rift-v1"},
	}, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		Allow0RTT:       true,
	})
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.CloseWithError(0, "done")
	c.log.Info("connected", zap.String("server", addr))

	ctrl, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}

	if err := proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeAuth, Token: token}); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}
	resp, err := proto.ReadMsg(ctrl)
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	if resp.Type != proto.TypeAuthOK {
		return fmt.Errorf("auth rejected: %s", resp.Error)
	}
	c.log.Info("authenticated")

	tunnelMap := make(map[uint32]config.TunnelSpec, len(c.cfg.Tunnels))
	for _, spec := range c.cfg.Tunnels {
		if err := proto.WriteMsg(ctrl, &proto.ControlMsg{
			Type:  proto.TypeRegister,
			Port:  spec.LocalPort,
			Proto: spec.Proto,
			Name:  spec.Name,
		}); err != nil {
			return fmt.Errorf("send register: %w", err)
		}
		reg, err := proto.ReadMsg(ctrl)
		if err != nil {
			return fmt.Errorf("read register response: %w", err)
		}
		if reg.Type == proto.TypeError {
			c.log.Error("registration rejected", zap.String("err", reg.Error))
			continue
		}
		tunnelMap[reg.TunnelID] = spec
		if reg.URL != "" {
			c.log.Info("tunnel ready", zap.String("url", reg.URL), zap.Uint16("local", spec.LocalPort))
		} else {
			c.log.Info("tunnel ready", zap.String("addr", reg.Addr), zap.Uint16("local", spec.LocalPort))
		}
	}

	return c.acceptDataStreams(ctx, conn, tunnelMap)
}

// stub — replaced by tunnel.go in Task 13
func (c *Client) acceptDataStreams(ctx context.Context, conn quic.Connection, tunnels map[uint32]config.TunnelSpec) error {
	<-ctx.Done()
	return ctx.Err()
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/client/
```

- [ ] **Step 3: Commit**

```bash
git add internal/client/client.go
git commit -m "feat(client): QUIC dial, auth, tunnel registration, exponential-backoff reconnect"
```

---

## Task 13: Client — Data Stream Relay

**Files:**
- Create: `internal/client/tunnel.go`
- Modify: `internal/client/client.go` (remove stub)

- [ ] **Step 1: Implement stream relay**

`internal/client/tunnel.go`:
```go
package client

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/user/rift/internal/config"
	"github.com/user/rift/internal/proto"
	"github.com/user/rift/internal/relay"
)

func (c *Client) acceptDataStreams(ctx context.Context, conn quic.Connection, tunnels map[uint32]config.TunnelSpec) error {
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

func (c *Client) handleStream(stream quic.Stream, tunnels map[uint32]config.TunnelSpec) {
	defer stream.Close()

	hdr, err := proto.ReadHeader(stream)
	if err != nil {
		c.log.Error("read tunnel header", zap.Error(err))
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
	defer local.Close()

	c.log.Debug("relaying", zap.Uint32("id", hdr.TunnelID), zap.Uint16("port", spec.LocalPort))
	relay.Relay(local, stream.(io.ReadWriteCloser))
}
```

- [ ] **Step 2: Remove stub from client.go**

Delete these lines from `internal/client/client.go`:
```go
// stub — replaced by tunnel.go in Task 13
func (c *Client) acceptDataStreams(ctx context.Context, conn quic.Connection, tunnels map[uint32]config.TunnelSpec) error {
	<-ctx.Done()
	return ctx.Err()
}
```

- [ ] **Step 3: Verify compilation**

```bash
go build ./internal/client/
```

- [ ] **Step 4: Commit**

```bash
git add internal/client/tunnel.go internal/client/client.go
git commit -m "feat(client): accept server data streams and relay to localhost via worker.Group"
```

---

## Task 14: CLI — Full Flag Wiring

**Files:**
- Modify: `cmd/rift/main.go` (replace stubs with full implementation)

- [ ] **Step 1: Write final main.go**

`cmd/rift/main.go`:
```go
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"go.uber.org/zap"

	"github.com/user/rift/internal/client"
	"github.com/user/rift/internal/config"
	"github.com/user/rift/internal/server"
	"github.com/user/rift/internal/store"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck
	log := logger

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:], log)
	case "client":
		err = runClient(os.Args[2:], log)
	case "version":
		fmt.Println("rift dev")
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
	if err != nil {
		log.Fatal("fatal", zap.Error(err))
	}
}

func runServer(args []string, log *zap.Logger) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	domain := fs.String("domain", "tunnel.localhost", "Base domain for HTTP tunnels")
	listen := fs.String("listen", ":443", "Listen address (QUIC=UDP, HTTPS=TCP share this port)")
	dev    := fs.Bool("dev", false, "Dev mode: self-signed cert, no token auth")
	certF  := fs.String("cert", "", "TLS cert PEM (pre-provisioned wildcard cert)")
	keyF   := fs.String("key", "", "TLS key PEM (required with --cert)")
	dbPath := fs.String("db", "/var/lib/rift/db", "BadgerDB data directory")
	addTok := fs.String("add-token", "", "Provision a token for NAME, print it, and exit")
	_ = fs.Parse(args)

	ts, err := store.OpenBadger(*dbPath)
	if err != nil {
		return fmt.Errorf("open token store: %w", err)
	}
	defer ts.Close()

	if *addTok != "" {
		tok, err := store.GenerateToken()
		if err != nil {
			return err
		}
		if err := ts.Add(context.Background(), *addTok, tok); err != nil {
			return fmt.Errorf("save token: %w", err)
		}
		fmt.Printf("Token for %q:\n%s\n", *addTok, tok)
		return nil
	}

	var tlsCfg *tls.Config
	switch {
	case *dev:
		tlsCfg, err = server.DevTLSConfig(*domain)
		if err != nil {
			return fmt.Errorf("dev TLS: %w", err)
		}
		log.Warn("dev mode active — self-signed cert, auth disabled", zap.String("domain", *domain))
	case *certF != "":
		cert, err := tls.LoadX509KeyPair(*certF, *keyF)
		if err != nil {
			return fmt.Errorf("load cert/key: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
	default:
		tlsCfg = server.ProdTLSConfig(*domain, filepath.Join(*dbPath, "certs"))
	}

	cfg := config.ServerConfig{ListenAddr: *listen, Domain: *domain, Dev: *dev}
	var ts2 store.TokenStore
	if !*dev {
		ts2 = ts
	}
	return runWithSignal(server.New(cfg, ts2, tlsCfg, log).Run)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runClient(args []string, log *zap.Logger) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	srvAddr  := fs.String("server", "", "rift server host or host:port (required)")
	insecure := fs.Bool("insecure", false, "Skip TLS cert verification (dev mode)")
	tokenArg := fs.String("token", "", "Auth token (overrides DB lookup)")
	dbPath   := fs.String("db", defaultClientDB(), "BadgerDB data directory")
	var exposeFlags multiFlag
	fs.Var(&exposeFlags, "expose", "PORT:PROTO[:NAME], e.g. 3000:http:myapp (repeatable)")
	_ = fs.Parse(args)

	if *srvAddr == "" {
		return fmt.Errorf("--server is required")
	}
	if len(exposeFlags) == 0 {
		return fmt.Errorf("at least one --expose flag is required")
	}

	specs := make([]config.TunnelSpec, 0, len(exposeFlags))
	for _, e := range exposeFlags {
		spec, err := parseTunnelSpec(e)
		if err != nil {
			return err
		}
		specs = append(specs, spec)
	}

	ts, err := store.OpenBadger(*dbPath)
	if err != nil {
		return fmt.Errorf("open client DB: %w", err)
	}
	defer ts.Close()

	cfg := config.ClientConfig{
		Server:   *srvAddr,
		Token:    *tokenArg,
		Tunnels:  specs,
		Insecure: *insecure,
	}
	c := client.New(cfg, ts, log)
	return runWithSignal(func(ctx context.Context) error {
		c.Connect(ctx)
		return nil
	})
}

func parseTunnelSpec(s string) (config.TunnelSpec, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 2 {
		return config.TunnelSpec{}, fmt.Errorf("invalid --expose %q: want PORT:PROTO[:NAME]", s)
	}
	var port uint16
	if _, err := fmt.Sscanf(parts[0], "%d", &port); err != nil || port == 0 {
		return config.TunnelSpec{}, fmt.Errorf("invalid port in --expose %q", s)
	}
	if parts[1] != "http" && parts[1] != "tcp" {
		return config.TunnelSpec{}, fmt.Errorf("unknown proto %q in --expose %q", parts[1], s)
	}
	name := ""
	if len(parts) == 3 {
		name = parts[2]
	}
	return config.TunnelSpec{LocalPort: port, Proto: parts[1], Name: name}, nil
}

func runWithSignal(fn func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return fn(ctx)
}

func defaultClientDB() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "rift")
}

func printUsage() {
	fmt.Print(`rift — self-hosted QUIC tunnel

Usage:
  rift server [flags]   Start the tunnel server (run on your VPS)
  rift client [flags]   Connect and expose local services
  rift version          Print version

Server flags:
  --domain string       Base domain (default: tunnel.localhost)
  --listen string       Listen addr — QUIC=UDP, HTTPS=TCP (default: :443)
  --dev                 Dev mode: self-signed cert, no auth required
  --cert / --key        Pre-provisioned TLS cert+key PEM files
  --db string           BadgerDB data dir (default: /var/lib/rift/db)
  --add-token string    Provision a token for NAME and exit

Client flags:
  --server string       Server host or host:port (required)
  --expose value        PORT:PROTO[:NAME] e.g. 3000:http:myapp (repeatable)
  --token string        Auth token (overrides DB lookup)
  --db string           BadgerDB data dir (default: ~/.local/share/rift)
  --insecure            Skip TLS cert verification (for --dev server)

Examples:
  rift server --dev --listen :4443
  rift client --server localhost:4443 --insecure --expose 3000:http

  rift server --domain tunnel.example.com --add-token alice
  rift client --server tunnel.example.com --expose 3000:http:myapp --expose 5432:tcp
`)
}
```

- [ ] **Step 2: Verify full build**

```bash
go build ./cmd/rift/
./rift version
./rift server --help
./rift client --help
```

- [ ] **Step 3: Commit**

```bash
git add cmd/rift/main.go
git commit -m "feat(cli): full server+client flag wiring with BadgerDB, zap, errgroup"
```

---

## Task 15: Makefile + go vet

**Files:**
- Create: `Makefile`

- [ ] **Step 1: Create Makefile**

`Makefile`:
```makefile
.PHONY: build vet tidy lint clean dev-server dev-client

BINARY  := rift
MODULE  := github.com/user/rift

build:
	go build -o $(BINARY) ./cmd/rift/

vet:
	go vet ./...

tidy:
	go mod tidy

lint: vet
	@which staticcheck >/dev/null 2>&1 \
		&& staticcheck ./... \
		|| echo "staticcheck not installed — run: go install honnef.co/go/tools/cmd/staticcheck@latest"

clean:
	rm -f $(BINARY)

dev-server:
	go run ./cmd/rift/ server --dev --listen :4443 --db /tmp/rift-dev-server

dev-client:
	go run ./cmd/rift/ client --server localhost:4443 --insecure \
		--expose 3000:http --db /tmp/rift-dev-client
```

- [ ] **Step 2: Vet and build**

```bash
make vet
make build
./rift version
```

Expected: `rift dev`, zero vet warnings.

- [ ] **Step 3: Smoke-test dev workflow** (requires a process on :3000)

```bash
# Terminal 1
make dev-server

# Terminal 2
make dev-client
```

Expected: client logs `tunnel ready` with a URL.

- [ ] **Step 4: Commit**

```bash
git add Makefile
git commit -m "chore: Makefile with build/vet/lint/dev-run targets"
```

---

## Spec Coverage Checklist

| Requirement | Task |
|-------------|------|
| Single binary, `server`/`client` subcommands | 1, 14 |
| `--expose PORT:PROTO[:NAME]` repeatable | 12, 14 |
| QUIC on port 443, ALPN `rift-v1` | 10 |
| 4-byte length-prefix + JSON control stream | 3 |
| 8-byte tunnel data stream header | 3 |
| Token format `t_` + 64 hex chars | 4 |
| BadgerDB token persistence (server + client) | 4 |
| `sync.Pool` 32 KiB relay buffer | 6 |
| Thread-safe `Registry` with `sync.RWMutex` | 8 |
| Named goroutines with panic recovery | 5 |
| `worker.Group` goroutine counter | 5 |
| `errgroup` for server component lifecycle | 10 |
| HTTP subdomain routing + `X-Forwarded-*` | 11 |
| WebSocket upgrade support | 11 |
| TCP tunnel random port [10000, 65535] | 11 |
| `quic.Transport` (not `ListenAddr`) | 10 |
| Dev: self-signed wildcard cert | 7 |
| Prod: Let's Encrypt autocert | 7 |
| Exponential backoff reconnect 1s → 30s | 12 |
| SIGINT/SIGTERM graceful shutdown | 14 |
| zap structured logging (production-grade) | 1, all |
| BadgerDB v4.9.1 — high-perf embedded KV | 4 |
| Go 1.24, quic-go v0.50.1, zap v1.27 | 1 |
| `--add-token` setup command | 14 |
| `make dev-server` / `make dev-client` helpers | 15 |

**Type consistency verification:**
- `relay.Relay(a, b io.ReadWriteCloser)` — callers cast `quic.Stream` and `net.Conn` ✓
- `store.TokenStore` interface: `BadgerStore` implements all 5 methods ✓
- `server.New(cfg, ts, tlsCfg, log)` matches Task 14 call site ✓
- `client.New(cfg, ts, log)` matches Task 14 call site ✓
- `worker.Group.Go(name string, fn func())` — all call sites pass `func()` ✓
- `connHandler.workers` field type `interface{ Go(string, func()) }` — satisfied by `*worker.Group` ✓
- `Registry.RegisterHTTP(subdomain string, conn quic.Connection)` — called in `conn.go` ✓
- `Registry.RegisterTCP(conn quic.Connection)` — called in `conn.go` ✓
