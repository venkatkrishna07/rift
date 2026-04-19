# rift Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> **Git rule:** Do NOT run any git commands. Code changes and test verification only.

**Goal:** Fix all 14 identified security vulnerabilities in rift, establishing defence-in-depth for a self-hosted QUIC tunnel serving local APIs over the internet.

**Architecture:** All fixes are in-place within existing packages — no package restructuring. Three new fields are added to `ServerConfig`/`ClientConfig` (`MaxBodyBytes`, `StreamTimeout`, `MaxTotalConns`). The `relay` package gains a configurable idle-timeout watchdog. All changes are test-driven: failing test written first, then implementation.

**Tech Stack:** Go 1.25, quic-go v0.59, go.uber.org/zap v1.27, go.uber.org/zap/zapcore (already in module), golang.org/x/time/rate (new — added in Task 13 only)

---

## Design decisions

| # | Decision |
|---|----------|
| Issue #1 (0-RTT) | Keep `Allow0RTT: true` on both sides for QUIC performance. Instead, both client **and** server wait for `conn.HandshakeComplete()` before touching the control stream — guarantees auth never travels in replayable 0-RTT data. |
| Issue #3 (TCP exposure) | Bind stays `0.0.0.0`. Emit `log.Warn` at both registration and bind time so operators are never surprised (Q1-C). |
| Issue #7 (force-insecure) | Keep flag but require `RIFT_FORCE_INSECURE=yes` env var alongside it (Q2-B). |
| Issue #5 (body limits) | Default 100 MiB, server-wide `--max-body-bytes` flag. Industry standard for API tunnels (Q3). |
| Issue #6 (stream timeout) | `--stream-timeout` flag, default 5 min. Header I/O timeout hardcoded 10 s (Q4). |

---

## File map

| File | What changes |
|------|-------------|
| `internal/config/config.go` | Add `MaxBodyBytes`, `StreamTimeout`, `MaxTotalConns` to `ServerConfig`; `StreamTimeout` to `ClientConfig`; `time` import; `Effective*()` helpers |
| `internal/server/server.go` | `acceptLoop`: wait for `HandshakeComplete` before dispatching handler; global conn counter |
| `internal/client/client.go` | Wait for `HandshakeComplete` before opening control stream; `RIFT_FORCE_INSECURE` env guard |
| `internal/server/conn.go` | `validateSubdomain()`; zero token in dev mode; `streamHeaderTimeout` const; `streamTimeout` field on `connHandler`; registration throttle |
| `internal/server/registry.go` | `RegisterHTTP` returns `(*Tunnel, error)` + `ErrSubdomainTaken`; `crypto/rand` for IDs |
| `internal/server/http.go` | Strip proxy headers + set `X-Real-IP`; body/response limits; WebSocket 101 verification; `streamTimeout`/`maxBodyBytes` on `httpHandler`; relay helper types |
| `internal/server/tcp.go` | Warning on bind; `streamTimeout` param; header deadline before relay |
| `internal/relay/relay.go` | New signature `Relay(a, b, timeout, log)`; idle-timeout watchdog; `activityRWC` wrapper |
| `internal/proto/proto.go` | `MarshalLogObject` implementing `zapcore.ObjectMarshaler` |
| `cmd/rift/main.go` | `--max-body-bytes`, `--stream-timeout`, `--max-conns` flags |
| `internal/server/conn_test.go` | New — `validateSubdomain` tests |
| `internal/server/registry_test.go` | New — collision + unregister-frees-subdomain + ID uniqueness tests |
| `internal/relay/relay_test.go` | New — idle-timeout, zero-timeout, data-flows tests |
| `internal/proto/proto_test.go` | New — `MarshalLogObject` redaction + wire-encoding-unaffected tests |
| `internal/client/client_test.go` | New — `isLocalhost` + force-insecure guard tests |

---

## Task 1: 0-RTT Replay Protection (Issue #1 — Critical)

**Context:** `Allow0RTT: true` lets a client with a cached session ticket send QUIC data before
the 1-RTT handshake completes. That data is cryptographically replayable by an on-path attacker.
The auth token and register frames are the first things sent on the control stream.

**Fix:** Keep `Allow0RTT: true` (QUIC reconnect performance is real). Instead, both sides wait
for `conn.HandshakeComplete()` before touching the control stream. Data sent after
`HandshakeComplete()` is in 1-RTT-protected streams and cannot be replayed.

`HandshakeComplete()` is on `*quic.Conn` (confirmed in quic-go v0.59 source), returns
`<-chan struct{}` that closes when the 1-RTT handshake is confirmed.

**Files:**
- Modify: `internal/client/client.go`
- Modify: `internal/server/server.go`

- [ ] **Step 1: Add HandshakeComplete wait on the client**

In `internal/client/client.go`, in the `connect` function, after `quic.DialAddr` succeeds and
before `conn.OpenStreamSync`, add:

```go
// Wait for the 1-RTT handshake to complete before sending auth.
// This ensures the auth token and register frames are never sent in
// 0-RTT data, which is replayable by on-path attackers.
select {
case <-conn.HandshakeComplete():
case <-ctx.Done():
    return fmt.Errorf("waiting for handshake: %w", ctx.Err())
}
```

The full `connect` function after this change (control-stream section only):

```go
conn, err := quic.DialAddr(ctx, addr, &tls.Config{
    InsecureSkipVerify: c.cfg.Insecure, //nolint:gosec // guarded by checkInsecureFlags
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

// Wait for 1-RTT handshake before touching the control plane.
select {
case <-conn.HandshakeComplete():
case <-ctx.Done():
    return fmt.Errorf("waiting for handshake: %w", ctx.Err())
}

ctrl, err := conn.OpenStreamSync(ctx)
```

- [ ] **Step 2: Add HandshakeComplete wait on the server**

In `internal/server/server.go`, in `acceptLoop`, add a wait **before** dispatching the
`connHandler` goroutine. The wait must be non-blocking in the accept loop itself — put it inside
the goroutine so the accept loop keeps accepting new connections while waiting:

```go
s.totalConns.Add(1)
s.wg.Go(fmt.Sprintf("conn-%s", conn.RemoteAddr()), func() {
    defer s.totalConns.Add(-1)
    defer s.releaseConn(ip)

    // Wait for 1-RTT handshake before processing any control messages.
    // Defence-in-depth: ensures no stream data is processed before the
    // client's liveness is confirmed (guards against replayed 0-RTT streams).
    select {
    case <-conn.HandshakeComplete():
    case <-ctx.Done():
        return
    }

    h.run(ctx)
})
```

Note: `totalConns` and the goroutine dispatch are added in Task 9; for now add the
`HandshakeComplete` wait to the existing goroutine dispatch:

```go
s.wg.Go(fmt.Sprintf("conn-%s", conn.RemoteAddr()), func() {
    defer s.releaseConn(ip)
    select {
    case <-conn.HandshakeComplete():
    case <-ctx.Done():
        return
    }
    h.run(ctx)
})
```

- [ ] **Step 3: Build**

```bash
go build ./...
```
Expected: exits 0, no output.

- [ ] **Step 4: Verify Allow0RTT is still present (not disabled)**

```bash
grep -n "Allow0RTT" internal/server/server.go internal/client/client.go
```
Expected: both lines show `Allow0RTT: true` — we kept it enabled.

---

## Task 2: Subdomain Validation + Collision Guard (Issues #2 & #10 — High + Medium)

**Context — Issue #2:** `msg.Name` is used verbatim as a subdomain. No validation allows:
- Reserved-name squatting (`www`, `admin`, `_acme-challenge` — would interfere with ACME renewal)
- Oversized labels (1 MiB name stored in memory and logs)
- Non-DNS characters

**Context — Issue #10:** `RegisterHTTP` overwrites an existing entry silently. An authenticated
attacker can steal another client's subdomain by re-registering it.

**Files:**
- Modify: `internal/server/conn.go`
- Modify: `internal/server/registry.go`
- Create: `internal/server/conn_test.go`
- Create: `internal/server/registry_test.go`

- [ ] **Step 1: Write failing tests for validateSubdomain**

Create `internal/server/conn_test.go`:

```go
package server

import (
	"strings"
	"testing"
)

func TestValidateSubdomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// valid
		{"single char", "a", false},
		{"two chars", "ab", false},
		{"alphanumeric", "abc123", false},
		{"hyphen in middle", "my-app", false},
		{"digits only", "123", false},
		{"max length 63", strings.Repeat("a", 63), false},
		// invalid format
		{"empty", "", true},
		{"starts with hyphen", "-abc", true},
		{"ends with hyphen", "abc-", true},
		{"uppercase", "ABC", true},
		{"mixed case", "myApp", true},
		{"underscore", "my_app", true},
		{"dot", "my.app", true},
		{"space", "my app", true},
		{"too long 64 chars", strings.Repeat("a", 64), true},
		// reserved names
		{"reserved www", "www", true},
		{"reserved api", "api", true},
		{"reserved admin", "admin", true},
		{"reserved mail", "mail", true},
		{"reserved smtp", "smtp", true},
		{"reserved ftp", "ftp", true},
		{"reserved ns", "ns", true},
		{"reserved ns1", "ns1", true},
		{"reserved ns2", "ns2", true},
		{"reserved mx", "mx", true},
		{"reserved vpn", "vpn", true},
		{"reserved ssh", "ssh", true},
		{"reserved localhost", "localhost", true},
		{"reserved root", "root", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSubdomain(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateSubdomain(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}
```

- [ ] **Step 2: Run — expect compile error**

```bash
go test ./internal/server/ -run TestValidateSubdomain -v 2>&1 | head -5
```
Expected: `undefined: validateSubdomain`

- [ ] **Step 3: Add validateSubdomain to conn.go**

Add the following to `internal/server/conn.go` after the imports block (add `"errors"` and
`"regexp"` to imports):

```go
// subdomainRE enforces RFC 1123 DNS label rules: 1–63 chars, lowercase
// alphanumeric with interior hyphens, no leading/trailing hyphens.
var subdomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// reservedSubdomains is the blocklist of labels clients may not claim.
var reservedSubdomains = map[string]struct{}{
	"www":       {},
	"api":       {},
	"mail":      {},
	"smtp":      {},
	"ftp":       {},
	"admin":     {},
	"root":      {},
	"ns":        {},
	"ns1":       {},
	"ns2":       {},
	"mx":        {},
	"vpn":       {},
	"ssh":       {},
	"localhost": {},
}

// validateSubdomain returns a non-nil error if s is not a safe DNS label for
// tunnel use. Enforces RFC 1123 syntax (lowercase only) and rejects reserved names.
func validateSubdomain(s string) error {
	if !subdomainRE.MatchString(s) {
		return errors.New("subdomain must be 1–63 lowercase alphanumeric characters; interior hyphens allowed, no leading/trailing hyphens")
	}
	if _, reserved := reservedSubdomains[s]; reserved {
		return errors.New("subdomain is reserved")
	}
	return nil
}
```

- [ ] **Step 4: Run validation tests — expect pass**

```bash
go test ./internal/server/ -run TestValidateSubdomain -v
```
Expected: all sub-tests PASS.

- [ ] **Step 5: Write failing tests for collision guard**

Create `internal/server/registry_test.go`:

```go
package server

import (
	"errors"
	"testing"
)

func TestRegisterHTTPCollision(t *testing.T) {
	r := NewRegistry()

	tun, err := r.RegisterHTTP("myapp", nil)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	if tun == nil {
		t.Fatal("expected non-nil tunnel on first registration")
	}

	_, err = r.RegisterHTTP("myapp", nil)
	if !errors.Is(err, ErrSubdomainTaken) {
		t.Fatalf("expected ErrSubdomainTaken on collision, got: %v", err)
	}
}

func TestRegisterHTTPDifferentSubdomains(t *testing.T) {
	r := NewRegistry()
	if _, err := r.RegisterHTTP("app1", nil); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if _, err := r.RegisterHTTP("app2", nil); err != nil {
		t.Fatalf("second registration: %v", err)
	}
}

func TestUnregisterFreesSubdomain(t *testing.T) {
	r := NewRegistry()
	tun, err := r.RegisterHTTP("myapp", nil)
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	r.Unregister(tun.ID)

	if _, err := r.RegisterHTTP("myapp", nil); err != nil {
		t.Fatalf("re-registration after unregister failed: %v", err)
	}
}
```

- [ ] **Step 6: Run — expect compile error**

```bash
go test ./internal/server/ -run TestRegisterHTTP -v 2>&1 | head -5
```
Expected: `RegisterHTTP` returns one value; `ErrSubdomainTaken` undefined.

- [ ] **Step 7: Update RegisterHTTP in registry.go**

Add `"errors"` to imports. Add the sentinel and update the function:

```go
// ErrSubdomainTaken is returned by RegisterHTTP when the subdomain is already
// claimed by an active tunnel.
var ErrSubdomainTaken = errors.New("subdomain already in use")

// RegisterHTTP registers an HTTP tunnel. Returns ErrSubdomainTaken if the
// subdomain is already active, preventing tunnel hijacking by re-registration.
func (r *Registry) RegisterHTTP(subdomain string, conn *quic.Conn) (*Tunnel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.bySubdom[subdomain]; exists {
		return nil, ErrSubdomainTaken
	}
	t := &Tunnel{ID: r.nextID(), Subdomain: subdomain, Proto: "http", Conn: conn}
	r.byID[t.ID] = t
	r.bySubdom[subdomain] = t
	return t, nil
}
```

- [ ] **Step 8: Update the HTTP case in conn.go to use validateSubdomain and handle the new error**

Replace the `"http":` case in the registration switch:

```go
case "http":
    subdomain := msg.Name
    if subdomain == "" {
        subdomain, err = randomSubdomain()
        if err != nil {
            _ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: "internal error"})
            continue
        }
    } else {
        if verr := validateSubdomain(subdomain); verr != nil {
            h.log.Warn("invalid subdomain rejected",
                zap.String("ip", ip),
                zap.String("name", subdomain),
                zap.Error(verr),
            )
            _ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: verr.Error()})
            continue
        }
    }
    tun, regErr := h.reg.RegisterHTTP(subdomain, h.conn)
    if regErr != nil {
        h.log.Warn("HTTP tunnel registration failed",
            zap.String("ip", ip),
            zap.String("subdomain", subdomain),
            zap.Error(regErr),
        )
        _ = proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeError, Error: regErr.Error()})
        continue
    }
    httpTunnels = append(httpTunnels, tun.ID)
    url := fmt.Sprintf("https://%s.%s", subdomain, h.domain)
    tunnelCount++
    h.log.Info("HTTP tunnel registered",
        zap.String("ip", ip),
        zap.String("subdomain", subdomain),
        zap.String("url", url),
        zap.Uint32("tunnel_id", tun.ID),
    )
    _ = proto.WriteMsg(ctrl, &proto.ControlMsg{
        Type:     proto.TypeOK,
        TunnelID: tun.ID,
        URL:      url,
    })
```

- [ ] **Step 9: Build**

```bash
go build ./...
```
Expected: exits 0.

- [ ] **Step 10: Run all server tests**

```bash
go test ./internal/server/ -v
```
Expected: all PASS.

---

## Task 3: Strip Injected Proxy Headers (Issue #4 — High)

**Context:** A visitor can inject `X-Real-IP: 127.0.0.1` (or `True-Client-IP`, `CF-Connecting-IP`
etc.) and have it forwarded verbatim to the backend, bypassing IP-based access controls. The
`Director` must delete all identity headers before setting them authoritatively.

**Files:**
- Modify: `internal/server/http.go`

- [ ] **Step 1: Replace the Director function in ServeHTTP**

Replace the existing `Director` func inside `ServeHTTP` with:

```go
Director: func(req *http.Request) {
    // Delete every header a visitor could inject to spoof identity.
    // These are set authoritatively below — order matters: delete first.
    for _, hdr := range []string{
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Real-Ip",
        "X-Real-IP",
        "True-Client-Ip",
        "True-Client-IP",
        "Cf-Connecting-Ip",
        "CF-Connecting-IP",
        "X-Original-Forwarded-For",
        "X-Client-IP",
    } {
        req.Header.Del(hdr)
    }
    visitorIP := clientIP(r.RemoteAddr)
    req.URL.Scheme = "http"
    req.URL.Host = r.Host
    req.Header.Set("X-Forwarded-For", visitorIP)
    req.Header.Set("X-Real-IP", visitorIP)
    req.Header.Set("X-Forwarded-Proto", "https")
    req.Header.Set("X-Forwarded-Host", r.Host)
},
```

Note: the variable `r` here is the outer `*http.Request` captured by the closure — the same
pattern used in the original code.

- [ ] **Step 2: Build**

```bash
go build ./...
```
Expected: exits 0.

---

## Task 4: Config Fields + HTTP Body/Response Size Limits (Issue #5 — High)

**Context:** No body-size cap means an attacker can stream gigabytes through any HTTP tunnel.
The limit (`--max-body-bytes`, default 100 MiB) is applied with `http.MaxBytesReader` on
requests and `io.LimitReader` on responses. Config additions here (`StreamTimeout`,
`MaxTotalConns`) are also used by Tasks 5 and 9.

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/server/http.go`
- Modify: `cmd/rift/main.go`

- [ ] **Step 1: Rewrite config.go**

Replace the entire contents of `internal/config/config.go`:

```go
// Package config holds typed configuration structs for rift server and client.
package config

import "time"

// Defaults applied when the corresponding config field is zero.
const (
	// DefaultMaxBodyBytes is the maximum HTTP request or response body proxied
	// through an HTTP tunnel. 100 MiB matches common API gateway defaults.
	DefaultMaxBodyBytes int64 = 100 * 1024 * 1024

	// DefaultStreamTimeout is the data-stream idle timeout. A stream with no
	// bytes transferred for this duration is closed by the relay watchdog.
	DefaultStreamTimeout = 5 * time.Minute

	// DefaultMaxTotalConns is the server-wide cap on concurrent QUIC connections.
	DefaultMaxTotalConns = 500
)

// ServerConfig holds all server-side configuration.
type ServerConfig struct {
	ListenAddr    string        // e.g. ":443" — shared by QUIC (UDP) and HTTPS (TCP)
	ACMEAddr      string        // e.g. ":80"  — HTTP-01 ACME challenge listener (prod only)
	Domain        string        // base domain, e.g. "tunnel.example.com"
	Dev           bool          // dev mode: self-signed cert, no token auth
	DBPath        string        // BadgerDB data directory
	MaxBodyBytes  int64         // max HTTP body size; 0 → DefaultMaxBodyBytes
	StreamTimeout time.Duration // data stream idle timeout; 0 → DefaultStreamTimeout
	MaxTotalConns int           // max concurrent connections server-wide; 0 → DefaultMaxTotalConns
}

// EffectiveMaxBodyBytes returns the configured limit or the package default.
func (c ServerConfig) EffectiveMaxBodyBytes() int64 {
	if c.MaxBodyBytes > 0 {
		return c.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

// EffectiveStreamTimeout returns the configured timeout or the package default.
func (c ServerConfig) EffectiveStreamTimeout() time.Duration {
	if c.StreamTimeout > 0 {
		return c.StreamTimeout
	}
	return DefaultStreamTimeout
}

// EffectiveMaxTotalConns returns the configured limit or the package default.
func (c ServerConfig) EffectiveMaxTotalConns() int {
	if c.MaxTotalConns > 0 {
		return c.MaxTotalConns
	}
	return DefaultMaxTotalConns
}

// ClientConfig holds all client-side configuration.
type ClientConfig struct {
	Server        string        // host or host:port of rift server
	Token         string        // auth token (overrides DB lookup when set)
	Tunnels       []TunnelSpec  // tunnels to register
	Insecure      bool          // skip TLS cert verification (dev mode only)
	ForceInsecure bool          // allow --insecure with non-localhost servers
	DBPath        string        // BadgerDB data directory for token persistence
	StreamTimeout time.Duration // data stream idle timeout; 0 → DefaultStreamTimeout
}

// EffectiveStreamTimeout returns the configured timeout or the package default.
func (c ClientConfig) EffectiveStreamTimeout() time.Duration {
	if c.StreamTimeout > 0 {
		return c.StreamTimeout
	}
	return DefaultStreamTimeout
}

// TunnelSpec describes a single tunnel the client wants to expose.
type TunnelSpec struct {
	LocalPort uint16 // local TCP port to forward to
	Proto     string // "http" or "tcp"
	Name      string // optional human name; server picks subdomain/port if empty
}
```

- [ ] **Step 2: Add maxBodyBytes + streamTimeout to httpHandler**

In `internal/server/http.go`, update the struct:

```go
type httpHandler struct {
	reg           *Registry
	log           *zap.Logger
	maxBodyBytes  int64
	streamTimeout time.Duration
}
```

- [ ] **Step 3: Apply MaxBytesReader and ModifyResponse in ServeHTTP**

In `ServeHTTP`, add body limit immediately after the `TryAddVisitor` check and before the
WebSocket branch:

```go
// Enforce body size limit before any reading. Applies to both regular HTTP
// requests and WebSocket upgrade requests.
r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
```

Add `ModifyResponse` to the `httputil.ReverseProxy` (after the `Director` field, before
`Transport`):

```go
ModifyResponse: func(resp *http.Response) error {
    resp.Body = io.NopCloser(io.LimitReader(resp.Body, h.maxBodyBytes))
    return nil
},
```

`"io"` is already imported in `http.go`.

- [ ] **Step 4: Wire httpHandler fields in serveHTTPS**

In `internal/server/http.go`, update `serveHTTPS`:

```go
srv := &http.Server{
    Handler: &httpHandler{
        reg:           s.reg,
        log:           s.log,
        maxBodyBytes:  s.cfg.EffectiveMaxBodyBytes(),
        streamTimeout: s.cfg.EffectiveStreamTimeout(),
    },
    ReadHeaderTimeout: 10 * time.Second,
    IdleTimeout:       120 * time.Second,
}
```

- [ ] **Step 5: Add CLI flags in main.go**

In `cmd/rift/main.go`, inside `runServer`, add to the flag set (after existing flags, before
`fs.Parse`):

```go
maxBodyBytes  := fs.Int64("max-body-bytes", config.DefaultMaxBodyBytes,
    "Max HTTP request/response body size in bytes (default 100 MiB)")
streamTimeout := fs.Duration("stream-timeout", config.DefaultStreamTimeout,
    "Data stream idle timeout; stream closed after this much inactivity (default 5m)")
maxConns      := fs.Int("max-conns", config.DefaultMaxTotalConns,
    "Max total concurrent QUIC connections server-wide (default 500)")
```

Update `ServerConfig` construction:

```go
cfg := config.ServerConfig{
    ListenAddr:    *listen,
    ACMEAddr:      *httpAddr,
    Domain:        *domain,
    Dev:           *dev,
    MaxBodyBytes:  *maxBodyBytes,
    StreamTimeout: *streamTimeout,
    MaxTotalConns: *maxConns,
}
```

In `runClient`, add:

```go
streamTimeout := fs.Duration("stream-timeout", config.DefaultStreamTimeout,
    "Data stream idle timeout; stream closed after this much inactivity (default 5m)")
```

Update `ClientConfig` construction:

```go
cfg := config.ClientConfig{
    Server:        *srvAddr,
    Token:         *tokenArg,
    Tunnels:       specs,
    Insecure:      *insecure,
    ForceInsecure: *forceInsecure,
    StreamTimeout: *streamTimeout,
}
```

- [ ] **Step 6: Build**

```bash
go build ./...
```
Expected: exits 0.

---

## Task 5: Data Stream Timeouts (Issue #6 — High)

**Context:** Two timeouts are needed:

1. **Header I/O timeout (10 s, hardcoded):** The 8-byte tunnel header must be written/read
   within 10 seconds. An attacker who opens 1000 streams and stalls them would otherwise hold
   1000 goroutines indefinitely (quic-go's `MaxIncomingStreams: 1000`).

2. **Relay idle timeout (configurable, default 5 min):** Once the relay is running, if no bytes
   are transferred for the timeout duration the relay closes both sides via a watchdog goroutine.

`relay.Relay` gains a new `timeout time.Duration` parameter. All callers are updated here.
The WebSocket relay call in `http.go` is updated to compile here; the full WebSocket fix
(including 101 verification) is in Task 10.

**Files:**
- Modify: `internal/relay/relay.go`
- Modify: `internal/client/tunnel.go`
- Modify: `internal/server/tcp.go`
- Modify: `internal/server/conn.go` (add `streamHeaderTimeout` const + `streamTimeout` field)
- Modify: `internal/server/http.go` (update relay call signature + add header deadline to transport)
- Create: `internal/relay/relay_test.go`

- [ ] **Step 1: Write failing relay tests**

Create `internal/relay/relay_test.go`:

```go
package relay

import (
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestRelayIdleTimeout(t *testing.T) {
	a, aRemote := net.Pipe()
	b, bRemote := net.Pipe()
	defer a.Close()
	defer b.Close()

	log, _ := zap.NewDevelopment()
	timeout := 200 * time.Millisecond

	done := make(chan struct{})
	go func() {
		defer close(done)
		Relay(aRemote, bRemote, timeout, log)
	}()

	// Send one byte so relay starts, then go idle.
	if _, err := a.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := b.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	select {
	case <-done:
		// relay self-terminated after idle — expected
	case <-time.After(timeout * 6):
		t.Fatal("relay did not close after idle timeout")
	}
}

func TestRelayZeroTimeoutExitsOnClose(t *testing.T) {
	a, aRemote := net.Pipe()
	b, bRemote := net.Pipe()

	log, _ := zap.NewDevelopment()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Relay(aRemote, bRemote, 0, log)
	}()

	a.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit after connection close")
	}
	b.Close()
}

func TestRelayDataFlows(t *testing.T) {
	a, aRemote := net.Pipe()
	b, bRemote := net.Pipe()
	defer a.Close()
	defer b.Close()

	log, _ := zap.NewDevelopment()
	go Relay(aRemote, bRemote, 0, log)

	want := []byte("hello relay")
	go func() { a.Write(want) }()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run — expect compile error**

```bash
go test ./internal/relay/ -run TestRelay -v 2>&1 | head -5
```
Expected: `too many arguments in call to Relay`.

- [ ] **Step 3: Rewrite relay.go**

Replace `internal/relay/relay.go` entirely:

```go
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

	"go.uber.org/zap"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// Relay copies data between a and b concurrently until either side closes.
//
// If timeout > 0 an idle watchdog closes both sides when no bytes are
// transferred for the timeout duration. Both a and b are always closed before
// Relay returns.
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
						log.Debug("relay idle timeout — closing streams",
							zap.Duration("idle", idle),
							zap.Duration("timeout", timeout),
						)
						_ = a.Close()
						_ = b.Close()
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
```

- [ ] **Step 4: Run relay tests — expect pass**

```bash
go test ./internal/relay/ -v -timeout 30s
```
Expected: `TestRelayIdleTimeout`, `TestRelayZeroTimeoutExitsOnClose`, `TestRelayDataFlows` — all PASS.

- [ ] **Step 5: Add streamHeaderTimeout and streamTimeout to conn.go**

In `internal/server/conn.go`, add at package level (after imports):

```go
// streamHeaderTimeout is the deadline applied to tunnel header I/O before the
// relay starts. Prevents stalled streams from holding goroutines indefinitely.
const streamHeaderTimeout = 10 * time.Second
```

Add `"time"` to imports if not present.

Add `streamTimeout time.Duration` field to `connHandler`:

```go
type connHandler struct {
	conn          *quic.Conn
	ts            store.TokenStore
	reg           *Registry
	dev           bool
	domain        string
	workers       *worker.Group
	log           *zap.Logger
	rl            *rateLimiter
	streamTimeout time.Duration
}
```

Pass `h.streamTimeout` when launching the TCP goroutine:

```go
h.workers.Go(fmt.Sprintf("tcp-tunnel-%d", tun.ID), func() {
    serveTCPTunnel(ctx, h.conn, tun.ID, tun.Port, h.reg, h.streamTimeout, h.log)
})
```

- [ ] **Step 6: Update acceptLoop in server.go to populate streamTimeout**

In `internal/server/server.go`, update `connHandler` construction in `acceptLoop`:

```go
h := &connHandler{
    conn:          conn,
    ts:            s.ts,
    reg:           s.reg,
    dev:           s.cfg.Dev,
    domain:        s.cfg.Domain,
    workers:       s.wg,
    log:           s.log,
    rl:            s.rl,
    streamTimeout: s.cfg.EffectiveStreamTimeout(),
}
```

- [ ] **Step 7: Rewrite tcp.go with header deadline and relay timeout**

Replace `internal/server/tcp.go`:

```go
package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/user/rift/internal/proto"
	"github.com/user/rift/internal/relay"
)

func serveTCPTunnel(ctx context.Context, conn *quic.Conn, id uint32, port uint16, reg *Registry, streamTimeout time.Duration, log *zap.Logger) {
	log = log.With(zap.Uint32("tunnel_id", id), zap.Uint16("port", port))

	tun := reg.ByID(id)
	if tun == nil {
		log.Error("TCP tunnel not found in registry")
		return
	}

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
		if !tun.TryAddVisitor() {
			log.Warn("visitor limit reached, dropping connection")
			_ = visitor.Close()
			continue
		}
		go forwardTCPVisitor(ctx, visitor, conn, id, tun, streamTimeout, log)
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
```

- [ ] **Step 8: Rewrite client/tunnel.go with header read deadline and relay timeout**

Replace `internal/client/tunnel.go`:

```go
package client

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/user/rift/internal/config"
	"github.com/user/rift/internal/proto"
	"github.com/user/rift/internal/relay"
)

// streamHeaderTimeout is the deadline for reading the tunnel header sent by
// the server. Prevents stalled streams from holding goroutines indefinitely.
const streamHeaderTimeout = 10 * time.Second

func (c *Client) acceptDataStreams(ctx context.Context, conn *quic.Conn, tunnels map[uint32]config.TunnelSpec) error {
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
```

- [ ] **Step 9: Update http.go — header deadline in tunnelTransport + relay call signature**

In `internal/server/http.go`, update `tunnelTransport.RoundTrip` to add a header write deadline:

```go
func (t *tunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	stream, err := t.conn.OpenStreamSync(req.Context())
	if err != nil {
		return nil, fmt.Errorf("open QUIC stream: %w", err)
	}
	// Short deadline for header write; clear before proxying the request body.
	if err := stream.SetDeadline(time.Now().Add(streamHeaderTimeout)); err != nil {
		stream.Close()
		return nil, fmt.Errorf("set stream deadline: %w", err)
	}
	if err := proto.WriteHeader(stream, proto.TunnelHeader{TunnelID: t.tunnelID}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write header: %w", err)
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("clear stream deadline: %w", err)
	}
	if err := req.Write(stream); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(stream), req)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	resp.Body = &streamBody{ReadCloser: resp.Body, stream: stream}
	return resp, nil
}
```

Also update the relay call in `proxyWebSocket` to use the new signature (Task 10 will rewrite
the full function; for now just fix the call to compile):

```go
relay.Relay(clientConn, stream, h.streamTimeout, h.log)
```

Add `"time"` import to `http.go` if not already present.

- [ ] **Step 10: Build**

```bash
go build ./...
```
Expected: exits 0.

- [ ] **Step 11: Run all tests**

```bash
go test ./... -timeout 60s
```
Expected: all PASS.

---

## Task 6: TCP Tunnel Exposure Warning (Issue #3 — High)

**Context:** TCP tunnels bind `0.0.0.0:port` with no visitor authentication. Anyone who
discovers the port can connect and reach the backend service. Decision Q1-C: keep current
binding behaviour, emit conspicuous `Warn` logs at both registration and bind time.

**Files:**
- Modify: `internal/server/conn.go`
- Modify: `internal/server/tcp.go`

- [ ] **Step 1: Add warning at TCP registration in conn.go**

In the `"tcp":` case, after the `RegisterTCP` call and before the `TypeOK` response, add:

```go
h.log.Warn("TCP tunnel registered — publicly accessible, NO visitor authentication",
    zap.String("ip", ip),
    zap.Uint16("port", tun.Port),
    zap.String("addr", addr),
)
```

- [ ] **Step 2: Add warning at bind time in tcp.go**

In `serveTCPTunnel`, after `log.Info("TCP tunnel listener ready")`, add:

```go
log.Warn("TCP port bound on all interfaces (0.0.0.0) — no visitor authentication is enforced",
    zap.String("bind", fmt.Sprintf("0.0.0.0:%d", port)),
)
```

- [ ] **Step 3: Build**

```bash
go build ./...
```
Expected: exits 0.

---

## Task 7: `--force-insecure` Env Var Guard (Issue #7 — Medium)

**Context:** `--force-insecure` disables TLS certificate verification for any server, allowing
an MITM attacker to observe the bearer token. Requiring `RIFT_FORCE_INSECURE=yes` in the
environment alongside the flag prevents casual or habitual misuse against production servers.

**Files:**
- Modify: `internal/client/client.go`
- Create: `internal/client/client_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/client/client_test.go`:

```go
package client

import (
	"testing"
)

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"127.0.0.2", true},
		{"192.168.1.1", false},
		{"example.com", false},
		{"10.0.0.1", false},
	}
	for _, tc := range tests {
		if got := isLocalhost(tc.host); got != tc.want {
			t.Errorf("isLocalhost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestCheckInsecureFlagsForceInsecureNoEnv(t *testing.T) {
	t.Setenv("RIFT_FORCE_INSECURE", "")
	err := checkInsecureFlags(true, true, "external.example.com")
	if err == nil {
		t.Error("expected error when RIFT_FORCE_INSECURE unset, got nil")
	}
}

func TestCheckInsecureFlagsForceInsecureWithEnv(t *testing.T) {
	t.Setenv("RIFT_FORCE_INSECURE", "yes")
	err := checkInsecureFlags(true, true, "external.example.com")
	if err != nil {
		t.Errorf("expected nil with RIFT_FORCE_INSECURE=yes, got: %v", err)
	}
}

func TestCheckInsecureFlagsLocalhostNoForce(t *testing.T) {
	t.Setenv("RIFT_FORCE_INSECURE", "")
	err := checkInsecureFlags(true, false, "localhost")
	if err != nil {
		t.Errorf("localhost+insecure should not require env var, got: %v", err)
	}
}

func TestCheckInsecureFlagsNonLocalhostNoForce(t *testing.T) {
	t.Setenv("RIFT_FORCE_INSECURE", "")
	err := checkInsecureFlags(true, false, "external.example.com")
	if err == nil {
		t.Error("expected error for non-localhost without --force-insecure")
	}
}

func TestCheckInsecureFlagsNotInsecure(t *testing.T) {
	err := checkInsecureFlags(false, false, "any.host.com")
	if err != nil {
		t.Errorf("insecure=false should always pass, got: %v", err)
	}
}
```

- [ ] **Step 2: Run — expect compile error**

```bash
go test ./internal/client/ -run TestCheckInsecure -v 2>&1 | head -5
```
Expected: `undefined: checkInsecureFlags`

- [ ] **Step 3: Add checkInsecureFlags to client.go**

Add `"os"` to imports. Add the function before `connect`:

```go
// checkInsecureFlags validates the --insecure / --force-insecure combination.
// Separating this logic makes it testable without a real QUIC connection.
func checkInsecureFlags(insecure, forceInsecure bool, host string) error {
	if !insecure {
		return nil
	}
	if forceInsecure {
		if os.Getenv("RIFT_FORCE_INSECURE") != "yes" {
			return fmt.Errorf(
				"--force-insecure requires the environment variable RIFT_FORCE_INSECURE=yes " +
					"to prevent accidental TLS verification bypass on production servers",
			)
		}
		return nil
	}
	if !isLocalhost(host) {
		return fmt.Errorf(
			"--insecure is only allowed with localhost targets; "+
				"use --force-insecure (and set RIFT_FORCE_INSECURE=yes) for %q",
			host,
		)
	}
	return nil
}
```

Replace the inline insecure check in `connect` with a call to `checkInsecureFlags`. Also add a
loud `Warn` when force-insecure is active. The updated section of `connect`:

```go
host, _, _ := net.SplitHostPort(addr)
if err := checkInsecureFlags(c.cfg.Insecure, c.cfg.ForceInsecure, host); err != nil {
    return err
}
if c.cfg.Insecure && c.cfg.ForceInsecure {
    c.log.Warn("TLS certificate verification DISABLED — MITM attacks are possible",
        zap.String("server", addr),
    )
}
```

Remove the old inline `if c.cfg.Insecure && !c.cfg.ForceInsecure { ... }` block.

- [ ] **Step 4: Run client tests**

```bash
go test ./internal/client/ -v
```
Expected: all PASS.

- [ ] **Step 5: Build**

```bash
go build ./...
```
Expected: exits 0.

---

## Task 8: Dev Mode — Zero Token Immediately After Read (Issue #8 — Medium)

**Context:** In dev mode the server reads and discards the client token. The token field remains
set in `msg` after reading. Any future `zap.Any("msg", msg)` debug log would emit a production
token if a developer accidentally pointed a prod client at a dev server. Zero it immediately.

**Files:**
- Modify: `internal/server/conn.go`

- [ ] **Step 1: Zero msg.Token as the first line of the dev branch**

In `internal/server/conn.go`, inside the authentication block, the dev branch currently looks
like:

```go
if h.dev {
    if err := proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeAuthOK}); err != nil {
```

Update it to:

```go
if h.dev {
    msg.Token = "" // zero immediately — a prod client pointing at a dev server
                   // would send its real token; don't leave it in memory or logs
    if err := proto.WriteMsg(ctrl, &proto.ControlMsg{Type: proto.TypeAuthOK}); err != nil {
```

- [ ] **Step 2: Build**

```bash
go build ./...
```
Expected: exits 0.

---

## Task 9: Global Connection Limit + Registration Throttle (Issue #9 — Medium)

**Context:** `maxConnsPerIP = 5` does not protect against distributed floods (many IPs, one
connection each). A global cap (`MaxTotalConns`, default 500) provides a server-wide ceiling.
Additionally, the registration loop handles rejected registrations in a tight loop; a 100 ms
sleep on rejection prevents abuse.

**Files:**
- Modify: `internal/server/server.go`
- Modify: `internal/server/conn.go`

- [ ] **Step 1: Add totalConns to Server struct**

In `internal/server/server.go`, add `totalConns atomic.Int64` to the `Server` struct:

```go
type Server struct {
	cfg         config.ServerConfig
	ts          store.TokenStore
	reg         *Registry
	tlsCfg      *tls.Config
	acmeHandler http.Handler
	log         *zap.Logger
	wg          *worker.Group
	rl          *rateLimiter
	connByIP    sync.Map
	totalConns  atomic.Int64
}
```

- [ ] **Step 2: Enforce global limit and track count in acceptLoop**

In `acceptLoop`, add the global check immediately after `ip := extractIP(...)`, before the
per-IP `allowConn` check:

```go
maxTotal := int64(s.cfg.EffectiveMaxTotalConns())
if s.totalConns.Load() >= maxTotal {
    s.log.Warn("global connection limit reached — rejecting connection",
        zap.String("ip", ip),
        zap.Int64("current", s.totalConns.Load()),
        zap.Int64("max", maxTotal),
    )
    _ = conn.CloseWithError(1, "server at capacity")
    continue
}
```

Update the goroutine dispatch to track and release the counter (merge with the
`HandshakeComplete` wait added in Task 1):

```go
s.totalConns.Add(1)
s.wg.Go(fmt.Sprintf("conn-%s", conn.RemoteAddr()), func() {
    defer s.totalConns.Add(-1)
    defer s.releaseConn(ip)
    select {
    case <-conn.HandshakeComplete():
    case <-ctx.Done():
        return
    }
    h.run(ctx)
})
```

- [ ] **Step 3: Throttle rejected registrations in conn.go**

In `internal/server/conn.go`, add `"time"` to imports if not present. In the registration loop,
after the tunnel-limit error response:

```go
if tunnelCount >= maxTunnelsPerClient {
    h.log.Warn("tunnel limit reached",
        zap.String("ip", ip),
        zap.Int("max", maxTunnelsPerClient),
    )
    _ = proto.WriteMsg(ctrl, &proto.ControlMsg{
        Type:  proto.TypeError,
        Error: fmt.Sprintf("max %d tunnels per client", maxTunnelsPerClient),
    })
    time.Sleep(100 * time.Millisecond) // throttle tight-loop abuse
    continue
}
```

- [ ] **Step 4: Build**

```bash
go build ./...
```
Expected: exits 0.

---

## Task 10: WebSocket 101 Verification Before Relay (Issue #11 — Medium)

**Context:** Currently `proxyWebSocket` writes the upgrade request to the tunnel stream then
immediately hijacks the visitor connection and enters raw relay. If the backend rejects the
upgrade (returns `400`), the visitor's hijacked TCP connection receives raw HTTP bytes —
protocol corruption, silent failure.

**Fix:** Read and verify the backend's `101 Switching Protocols` response **before** hijacking
the visitor. Then forward the 101 to the visitor and relay raw frames.

**Buffering concern:** `bufio.NewReader(stream)` may buffer early WebSocket frames alongside the
101 response headers. `bufReadWriteCloser` drains those bytes back into the relay.

**Files:**
- Modify: `internal/server/http.go`

- [ ] **Step 1: Add relay helper types to http.go**

Add these two types to `internal/server/http.go` (place them after the `streamBody` type):

```go
// bufReadWriteCloser pairs a bufio.Reader (which may hold bytes buffered beyond
// the HTTP response headers) with an io.WriteCloser for the same stream.
// Ensures early WebSocket frames buffered during http.ReadResponse are not lost.
type bufReadWriteCloser struct {
	*bufio.Reader
	io.WriteCloser
}

func (b *bufReadWriteCloser) Close() error { return b.WriteCloser.Close() }

// readerWriteCloser combines an arbitrary io.Reader with an io.WriteCloser.
// Used when the visitor-side reader must drain a bufio buffer before the raw
// net.Conn (e.g. any bytes buffered from the HTTP upgrade request).
type readerWriteCloser struct {
	io.Reader
	io.WriteCloser
}

func (r *readerWriteCloser) Close() error { return r.WriteCloser.Close() }
```

- [ ] **Step 2: Rewrite proxyWebSocket**

Replace the entire `proxyWebSocket` method:

```go
func (h *httpHandler) proxyWebSocket(w http.ResponseWriter, r *http.Request, tun *Tunnel) {
	// 1. Open stream and write tunnel header with a short I/O deadline.
	stream, err := tun.Conn.OpenStreamSync(r.Context())
	if err != nil {
		h.log.Error("open QUIC stream for websocket", zap.Error(err))
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if err := stream.SetDeadline(time.Now().Add(streamHeaderTimeout)); err != nil {
		h.log.Error("set websocket stream deadline", zap.Error(err))
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if err := proto.WriteHeader(stream, proto.TunnelHeader{TunnelID: tun.ID}); err != nil {
		h.log.Error("write websocket tunnel header", zap.Error(err))
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		h.log.Error("clear websocket stream deadline", zap.Error(err))
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// 2. Forward the upgrade request. Body already limited by MaxBytesReader in ServeHTTP.
	if err := r.Write(stream); err != nil {
		h.log.Error("write websocket request to tunnel", zap.Error(err))
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// 3. Read and verify the backend's response BEFORE involving the visitor.
	// Use bufio.Reader — the backend may send WebSocket frames immediately after
	// the 101, which must be preserved for the relay (not discarded).
	streamBuf := bufio.NewReader(stream)
	resp, err := http.ReadResponse(streamBuf, r)
	if err != nil {
		h.log.Error("read websocket upgrade response from tunnel", zap.Error(err))
		stream.Close()
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	resp.Body.Close() // 101 has no body

	if resp.StatusCode != http.StatusSwitchingProtocols {
		h.log.Error("websocket upgrade rejected by backend",
			zap.Int("status", resp.StatusCode),
			zap.String("status_text", resp.Status),
		)
		stream.Close()
		http.Error(w, fmt.Sprintf("websocket upgrade rejected: %s", resp.Status), http.StatusBadGateway)
		return
	}

	// 4. Hijack the visitor connection now that we have a confirmed 101.
	hj, ok := w.(http.Hijacker)
	if !ok {
		h.log.Error("websocket upgrade not supported by ResponseWriter")
		stream.Close()
		http.Error(w, "websocket unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		h.log.Error("websocket hijack failed", zap.Error(err))
		stream.Close()
		return
	}
	defer clientConn.Close()

	// 5. Forward the 101 response to the visitor so it can complete its handshake.
	if err := resp.Write(clientBuf.Writer); err != nil {
		h.log.Error("write 101 to visitor", zap.Error(err))
		stream.Close()
		return
	}
	if err := clientBuf.Writer.Flush(); err != nil {
		h.log.Error("flush 101 to visitor", zap.Error(err))
		stream.Close()
		return
	}

	// 6. Relay raw WebSocket frames.
	// streamBuf may have buffered bytes beyond the 101 headers — must not discard.
	streamRWC := &bufReadWriteCloser{Reader: streamBuf, WriteCloser: stream}

	// clientBuf.Reader may have buffered bytes from the upgrade request — drain them.
	var clientReader io.Reader = clientConn
	if clientBuf.Reader.Buffered() > 0 {
		clientReader = io.MultiReader(clientBuf.Reader, clientConn)
	}
	clientRWC := &readerWriteCloser{Reader: clientReader, WriteCloser: clientConn}

	relay.Relay(clientRWC, streamRWC, h.streamTimeout, h.log)
}
```

- [ ] **Step 3: Build**

```bash
go build ./...
```
Expected: exits 0.

---

## Task 11: `crypto/rand` for Tunnel IDs (Issue #12 — Low)

**Context:** `math/rand.Uint32()` (even auto-seeded in Go 1.20+) is not a CSPRNG. Tunnel IDs
flow over the wire in every data stream header. Using `crypto/rand` removes predictability
and is consistent with subdomain generation. TCP port selection stays on `math/rand` — that
is genuinely not security-sensitive.

**Files:**
- Modify: `internal/server/registry.go`
- Modify: `internal/server/registry_test.go`

- [ ] **Step 1: Add ID uniqueness test**

Append to `internal/server/registry_test.go`:

```go
func TestNextIDNonZeroAndUnique(t *testing.T) {
	r := NewRegistry()
	seen := make(map[uint32]struct{}, 1000)
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < 1000; i++ {
		id := r.nextID()
		if id == 0 {
			t.Fatalf("nextID returned 0 at iteration %d", i)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("nextID returned duplicate %d at iteration %d", id, i)
		}
		seen[id] = struct{}{}
		r.byID[id] = &Tunnel{ID: id} // mark used so nextID won't re-pick it
	}
}
```

- [ ] **Step 2: Run test — expect pass (documents behaviour, passes before and after)**

```bash
go test ./internal/server/ -run TestNextID -v
```
Expected: PASS.

- [ ] **Step 3: Switch nextID to crypto/rand**

Update imports in `internal/server/registry.go`:

```go
import (
	crand     "crypto/rand"
	"encoding/binary"
	"errors"
	mathrand  "math/rand"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)
```

Replace `nextID`:

```go
// nextID returns a non-zero uint32 not currently in use, generated via
// crypto/rand. Must be called with mu held.
func (r *Registry) nextID() uint32 {
	var b [4]byte
	for {
		if _, err := crand.Read(b[:]); err != nil {
			// crypto/rand is a kernel interface; failure is unrecoverable.
			panic("crypto/rand unavailable: " + err.Error())
		}
		id := binary.BigEndian.Uint32(b[:])
		if id == 0 {
			continue
		}
		if _, exists := r.byID[id]; !exists {
			return id
		}
	}
}
```

Update the TCP port line to use the `mathrand` alias:

```go
p := uint16(10000 + mathrand.Intn(55536)) //nolint:gosec // random port, not security-sensitive
```

- [ ] **Step 4: Run all server tests**

```bash
go test ./internal/server/ -v
```
Expected: all PASS.

- [ ] **Step 5: Build**

```bash
go build ./...
```
Expected: exits 0.

---

## Task 12: `ControlMsg` Token Auto-Redaction via `zapcore.ObjectMarshaler` (Issue #13 — Low)

**Context:** `ControlMsg.Token` holds a bearer token. All current logging carefully uses
`tokenPrefix()`. However, any future `zap.Any("msg", msg)` or `zap.Object("msg", msg)` call
would emit the full token. Implementing `zapcore.ObjectMarshaler` makes safe logging the
**default** — `zap.Object` calls automatically redact the token.

`json.Marshal` (used by `WriteMsg` for the wire protocol) is **unaffected** because
`MarshalLogObject` is a separate interface from `json.Marshaler`.

`go.uber.org/zap/zapcore` is a sub-package of `go.uber.org/zap` already in go.mod — no new
dependency required.

**Files:**
- Modify: `internal/proto/proto.go`
- Create: `internal/proto/proto_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/proto/proto_test.go`:

```go
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
```

- [ ] **Step 2: Run — expect failure**

```bash
go test ./internal/proto/ -run TestControlMsg -v
```
Expected: `TestControlMsgTokenRedactedInLogs` FAIL (full token in output);
`TestControlMsgWireEncodingUnaffected` PASS.

- [ ] **Step 3: Add MarshalLogObject and redactToken to proto.go**

Add `"go.uber.org/zap/zapcore"` to imports in `internal/proto/proto.go`.

Add after the `ControlMsg` type definition:

```go
// redactToken returns the first 8 characters of token followed by "..." for
// safe use in log output. Returns "***" for tokens of 8 characters or fewer.
func redactToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "..."
}

// MarshalLogObject implements zapcore.ObjectMarshaler.
// The Token field is redacted to its first 8 characters, preventing accidental
// bearer-token leakage via zap.Object or zap.Any log calls.
// json.Marshal (used for wire encoding in WriteMsg) is NOT affected.
func (m *ControlMsg) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("type", m.Type)
	if m.Token != "" {
		enc.AddString("token_prefix", redactToken(m.Token))
	}
	if m.Port != 0 {
		enc.AddUint64("port", uint64(m.Port))
	}
	if m.Proto != "" {
		enc.AddString("proto", m.Proto)
	}
	if m.Name != "" {
		enc.AddString("name", m.Name)
	}
	if m.TunnelID != 0 {
		enc.AddUint64("tunnel_id", uint64(m.TunnelID))
	}
	if m.URL != "" {
		enc.AddString("url", m.URL)
	}
	if m.Addr != "" {
		enc.AddString("addr", m.Addr)
	}
	if m.Error != "" {
		enc.AddString("error", m.Error)
	}
	return nil
}
```

- [ ] **Step 4: Run proto tests**

```bash
go test ./internal/proto/ -v
```
Expected: both tests PASS.

- [ ] **Step 5: Build**

```bash
go build ./...
```
Expected: exits 0.

---

## Task 13: Per-Source-IP Visitor Rate Limit (Issue #14 — Info)

**Context:** Without per-IP rate limiting a single visitor IP can open and close the 50-slot
visitor quota rapidly, generating arbitrary backend load. A token bucket per source IP
(`golang.org/x/time/rate`) limits each IP to 100 req/s sustained with a burst of 200.

**Files:**
- Modify: `internal/server/http.go`
- Modify: `go.mod` / `go.sum`

- [ ] **Step 1: Add golang.org/x/time dependency**

```bash
go get golang.org/x/time@latest
```
Expected: `go.mod` and `go.sum` updated, `golang.org/x/time` added.

- [ ] **Step 2: Add visitorRateLimiter type to http.go**

Add the following imports to `internal/server/http.go`:
- `"sync"` (if not already present)
- `"golang.org/x/time/rate"`

Add the type after the existing `httpHandler` struct:

```go
const (
	// visitorRateLimit is the sustained request rate per visitor IP (requests/second).
	visitorRateLimit = 100
	// visitorRateBurst is the token bucket burst size per visitor IP.
	visitorRateBurst = 200
)

// visitorRateLimiter holds a per-source-IP token bucket.
type visitorRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rate.Limiter
}

func newVisitorRateLimiter() *visitorRateLimiter {
	return &visitorRateLimiter{buckets: make(map[string]*rate.Limiter)}
}

// Allow returns true if the given IP is within its rate limit.
func (v *visitorRateLimiter) Allow(ip string) bool {
	v.mu.Lock()
	l, ok := v.buckets[ip]
	if !ok {
		l = rate.NewLimiter(visitorRateLimit, visitorRateBurst)
		v.buckets[ip] = l
	}
	v.mu.Unlock()
	return l.Allow()
}
```

- [ ] **Step 3: Add visitorRL field to httpHandler and wire it**

Update `httpHandler`:

```go
type httpHandler struct {
	reg           *Registry
	log           *zap.Logger
	maxBodyBytes  int64
	streamTimeout time.Duration
	visitorRL     *visitorRateLimiter
}
```

Update `serveHTTPS` handler construction:

```go
Handler: &httpHandler{
    reg:           s.reg,
    log:           s.log,
    maxBodyBytes:  s.cfg.EffectiveMaxBodyBytes(),
    streamTimeout: s.cfg.EffectiveStreamTimeout(),
    visitorRL:     newVisitorRateLimiter(),
},
```

- [ ] **Step 4: Enforce rate limit at the top of ServeHTTP**

Add immediately before the tunnel lookup (before `host := r.Host`):

```go
visitorIP := clientIP(r.RemoteAddr)
if !h.visitorRL.Allow(visitorIP) {
    h.log.Debug("visitor rate limited", zap.String("ip", visitorIP))
    http.Error(w, "too many requests", http.StatusTooManyRequests)
    return
}
```

Note: `clientIP` is already defined in `http.go`. Remove the duplicate `visitorIP := clientIP(r.RemoteAddr)` from the `Director` closure since it already uses `clientIP(r.RemoteAddr)` inline.

- [ ] **Step 5: Build**

```bash
go build ./...
```
Expected: exits 0.

- [ ] **Step 6: Run full test suite with race detector**

```bash
go test ./... -timeout 120s -race
```
Expected: all PASS, no data races reported.

---

## Final verification

- [ ] **No 0-RTT auth bypass possible — both sides wait**

```bash
grep -n "HandshakeComplete" internal/server/server.go internal/client/client.go
```
Expected: one hit in each file.

- [ ] **No stray Allow0RTT removal — it should still be true**

```bash
grep -n "Allow0RTT" internal/server/server.go internal/client/client.go
```
Expected: `Allow0RTT: true` in both files.

- [ ] **No injected proxy header paths remain**

```bash
grep -n "X-Forwarded-For\|X-Real-IP" internal/server/http.go
```
Expected: only the `Del` and `Set` calls in the Director.

- [ ] **Build final binary**

```bash
go build -o rift ./cmd/rift && ./rift version
```
Expected: `rift dev`, exits 0.

---

## Architecture improvements (next plan)

Deferred to a separate plan after all security fixes are complete:

1. Protocol: add `Version uint8` to `ControlMsg` for future wire evolution
2. `TokenStore`: add `Revoke(ctx, token)` and `List(ctx)` — token revocation is missing
3. Observability: switch to `zap.NewProduction()` in non-dev mode; add `/metrics` endpoint
4. WebSocket helpers (`bufReadWriteCloser`, `readerWriteCloser`): move to `internal/relay`
5. Per-connection `worker.Group` for TCP visitor goroutines (panic isolation)
6. Client-side BadgerDB: replace with a plain JSON credentials file
7. Config file support (YAML/TOML) for production deployments
