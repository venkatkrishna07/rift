# TCP Tunnel Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the existing TCP tunnel implementation by adding proto constants, dangerous port blocking, bind error confirmation, and improved client logging.

**Architecture:** Fix 4 gaps in the current TCP tunnel code: replace magic string literals with typed constants, block dangerous local ports (SMTP/DNS) at the server conn handler, fix the silent bind failure bug by plumbing a confirmation channel from `serveTCPTunnel` back to the conn handler before sending `TypeOK`, and improve client-side tunnel-ready logging to distinguish HTTP vs TCP.

**Tech Stack:** Go 1.22+, quic-go, zap, internal/proto, internal/server, internal/client

---

### Task 1: Add ProtoHTTP and ProtoTCP constants to proto package

**Files:**
- Modify: `internal/proto/proto.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/proto/proto_test.go` (create if absent):

```go
package proto_test

import (
    "testing"
    "github.com/venkatkrishna07/rift/internal/proto"
)

func TestProtoConstants(t *testing.T) {
    if proto.ProtoHTTP != "http" {
        t.Fatalf("ProtoHTTP = %q, want %q", proto.ProtoHTTP, "http")
    }
    if proto.ProtoTCP != "tcp" {
        t.Fatalf("ProtoTCP = %q, want %q", proto.ProtoTCP, "tcp")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proto/ -run TestProtoConstants -v`
Expected: FAIL — `proto.ProtoHTTP undefined`

- [ ] **Step 3: Add constants to proto.go**

In `internal/proto/proto.go`, add after the existing type/const block:

```go
// Proto identifies the tunnel protocol.
const (
    ProtoHTTP = "http"
    ProtoTCP  = "tcp"
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proto/ -run TestProtoConstants -v`
Expected: PASS

- [ ] **Step 5: Verify build is clean**

Run: `go build ./...`
Expected: no output (clean build)

---

### Task 2: Replace magic string literals with proto constants

**Files:**
- Modify: `internal/server/registry.go`
- Modify: `internal/server/conn.go`
- Modify: `cmd/rift/main.go`

- [ ] **Step 1: Update registry.go**

In `internal/server/registry.go`, replace all `"http"` tunnel-type literals with `proto.ProtoHTTP` and `"tcp"` with `proto.ProtoTCP`. Add import `"github.com/venkatkrishna07/rift/internal/proto"` if not present.

Specifically, in `RegisterHTTP` the `Type` field assignment:
```go
tun := &Tunnel{
    ID:        nextID(),
    Type:      proto.ProtoHTTP,
    Subdomain: sub,
    // ...
}
```

In `RegisterTCP`:
```go
tun := &Tunnel{
    ID:   nextID(),
    Type: proto.ProtoTCP,
    Port: uint16(port),
}
```

- [ ] **Step 2: Update conn.go**

In `internal/server/conn.go`, replace `case "http":` and `case "tcp":` in the `handleRegistration` switch with `case proto.ProtoHTTP:` and `case proto.ProtoTCP:`. Add import if needed.

- [ ] **Step 3: Update main.go**

In `cmd/rift/main.go`, in `parseTunnelSpec`:

```go
import "github.com/venkatkrishna07/rift/internal/proto"

// replace:
if parts[1] != "http" && parts[1] != "tcp" {
// with:
if parts[1] != proto.ProtoHTTP && parts[1] != proto.ProtoTCP {
```

- [ ] **Step 4: Run tests and build**

Run: `go test ./... -timeout 60s`
Run: `go build ./...`
Expected: all pass, clean build

---

### Task 3: Block dangerous local ports (SMTP, DNS)

**Files:**
- Modify: `internal/server/conn.go`
- Modify: `internal/server/conn_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/server/conn_test.go`:

```go
func TestValidateTCPLocalPort(t *testing.T) {
    cases := []struct {
        port    uint16
        wantErr bool
    }{
        {port: 3000, wantErr: false},
        {port: 8080, wantErr: false},
        {port: 5432, wantErr: false},
        {port: 22,   wantErr: false}, // SSH allowed
        {port: 25,   wantErr: true},  // SMTP blocked
        {port: 53,   wantErr: true},  // DNS blocked
        {port: 465,  wantErr: true},  // SMTPS blocked
        {port: 587,  wantErr: true},  // SMTP submission blocked
        {port: 0,    wantErr: true},  // port 0 invalid
    }
    for _, tc := range cases {
        err := validateTCPLocalPort(tc.port)
        if (err != nil) != tc.wantErr {
            t.Errorf("validateTCPLocalPort(%d) error = %v, wantErr %v", tc.port, err, tc.wantErr)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -run TestValidateTCPLocalPort -v`
Expected: FAIL — `undefined: validateTCPLocalPort`

- [ ] **Step 3: Implement validateTCPLocalPort in conn.go**

Add to `internal/server/conn.go`:

```go
// blockedLocalPorts lists ports that must not be exposed as TCP tunnels.
// These are commonly abused for spam/amplification or are privileged services.
var blockedLocalPorts = map[uint16]string{
    25:  "SMTP",
    53:  "DNS",
    465: "SMTPS",
    587: "SMTP submission",
}

// validateTCPLocalPort returns an error if the port is 0 or on the blocked list.
func validateTCPLocalPort(port uint16) error {
    if port == 0 {
        return fmt.Errorf("port 0 is not allowed")
    }
    if svc, blocked := blockedLocalPorts[port]; blocked {
        return fmt.Errorf("port %d (%s) is not allowed as a TCP tunnel target", port, svc)
    }
    return nil
}
```

- [ ] **Step 4: Call validateTCPLocalPort in the TCP case of handleRegistration**

In `internal/server/conn.go`, inside `case proto.ProtoTCP:` before registering:

```go
case proto.ProtoTCP:
    if err := validateTCPLocalPort(msg.Port); err != nil {
        _ = writeControlMsg(s, ControlMsg{Type: TypeErr, Error: err.Error()})
        return
    }
    // ... existing registration code
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/server/ -run TestValidateTCPLocalPort -v`
Expected: PASS

- [ ] **Step 6: Run full test suite**

Run: `go test ./... -timeout 60s`
Expected: all pass

---

### Task 4: Fix silent TCP bind failure — plumb bindErr channel

**Files:**
- Modify: `internal/server/tcp.go`
- Modify: `internal/server/conn.go`

- [ ] **Step 1: Update serveTCPTunnel signature in tcp.go**

Change the function signature to accept a `bindErr chan<- error`:

```go
func serveTCPTunnel(
    ctx context.Context,
    conn quic.Connection,
    id string,
    port uint16,
    reg *Registry,
    streamTimeout time.Duration,
    bindErr chan<- error,
    log *zap.Logger,
) {
    ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        bindErr <- fmt.Errorf("bind TCP port %d: %w", port, err)
        return
    }
    bindErr <- nil  // signal success before entering accept loop

    log.Warn("TCP port bound on all interfaces (0.0.0.0) — no visitor authentication is enforced",
        zap.Uint16("port", port))
    defer ln.Close()
    // ... rest of existing accept loop unchanged
}
```

- [ ] **Step 2: Update conn.go to read bindErr before sending TypeOK**

In `internal/server/conn.go`, inside `case proto.ProtoTCP:`, replace the current `h.workers.Go(...)` dispatch with:

```go
case proto.ProtoTCP:
    if err := validateTCPLocalPort(msg.Port); err != nil {
        _ = writeControlMsg(s, ControlMsg{Type: TypeErr, Error: err.Error()})
        return
    }
    tun, err := h.reg.RegisterTCP(msg.Port)
    if err != nil {
        _ = writeControlMsg(s, ControlMsg{Type: TypeErr, Error: err.Error()})
        return
    }

    bindCh := make(chan error, 1)
    h.workers.Go(func() {
        serveTCPTunnel(ctx, h.conn, tun.ID, tun.Port, h.reg, h.streamTimeout, bindCh, h.log)
    })

    // Wait for bind result before confirming to client.
    if bindErr := <-bindCh; bindErr != nil {
        h.reg.Deregister(tun.ID)
        _ = writeControlMsg(s, ControlMsg{Type: TypeErr, Error: bindErr.Error()})
        return
    }

    _ = writeControlMsg(s, ControlMsg{
        Type: TypeOK,
        Addr: fmt.Sprintf(":%d", tun.Port),
    })
```

- [ ] **Step 3: Run full test suite**

Run: `go test ./... -timeout 60s`
Expected: all pass

- [ ] **Step 4: Verify build is clean**

Run: `go build ./...`
Expected: no output

---

### Task 5: Add TCP tunnel server tests

**Files:**
- Create: `internal/server/tcp_test.go`

- [ ] **Step 1: Write tests**

Create `internal/server/tcp_test.go`:

```go
package server

import (
    "context"
    "fmt"
    "net"
    "testing"
    "time"

    "go.uber.org/zap/zaptest"
)

// dialFreePort returns a free TCP port by briefly binding to :0.
func dialFreePort(t *testing.T) uint16 {
    t.Helper()
    ln, err := net.Listen("tcp", ":0")
    if err != nil {
        t.Fatalf("dialFreePort: %v", err)
    }
    port := uint16(ln.Addr().(*net.TCPAddr).Port)
    ln.Close()
    return port
}

func TestServeTCPTunnelBindSuccess(t *testing.T) {
    port := dialFreePort(t)
    reg := NewRegistry()
    bindCh := make(chan error, 1)
    log := zaptest.NewLogger(t)

    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    go serveTCPTunnel(ctx, nil, "test-id", port, reg, 5*time.Second, bindCh, log)

    select {
    case err := <-bindCh:
        if err != nil {
            t.Fatalf("expected bind success, got: %v", err)
        }
    case <-time.After(time.Second):
        t.Fatal("timeout waiting for bind confirmation")
    }
}

func TestServeTCPTunnelBindError(t *testing.T) {
    // Bind a port ourselves, then ask serveTCPTunnel to bind the same port.
    ln, err := net.Listen("tcp", ":0")
    if err != nil {
        t.Fatalf("setup: %v", err)
    }
    defer ln.Close()
    port := uint16(ln.Addr().(*net.TCPAddr).Port)

    reg := NewRegistry()
    bindCh := make(chan error, 1)
    log := zaptest.NewLogger(t)

    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    go serveTCPTunnel(ctx, nil, "test-id", port, reg, 5*time.Second, bindCh, log)

    select {
    case err := <-bindCh:
        if err == nil {
            t.Fatal("expected bind error, got nil")
        }
        if !containsPort(err.Error(), fmt.Sprint(port)) {
            t.Errorf("error %q does not mention port %d", err, port)
        }
    case <-time.After(time.Second):
        t.Fatal("timeout waiting for bind error")
    }
}

func containsPort(s, port string) bool {
    return len(s) > 0 && (s[len(s)-len(port):] == port || containsSubstr(s, port))
}

func containsSubstr(s, sub string) bool {
    for i := 0; i <= len(s)-len(sub); i++ {
        if s[i:i+len(sub)] == sub {
            return true
        }
    }
    return false
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/server/ -run TestServeTCPTunnel -v`
Expected: both tests PASS

- [ ] **Step 3: Run full test suite**

Run: `go test ./... -timeout 60s`
Expected: all pass

---

### Task 6: Improve client tunnel-ready logging

**Files:**
- Modify: `internal/client/client.go`

- [ ] **Step 1: Find current tunnel-ready log**

The current log in `client.go` after receiving `TypeOK` uses a single log line for both HTTP and TCP. It needs to switch on proto to display the right URL/address.

- [ ] **Step 2: Update tunnel-ready log**

In `internal/client/client.go`, in the section that handles a `TypeOK` response from the server, replace the single log statement with a switch on `spec.Proto`:

```go
import "github.com/venkatkrishna07/rift/internal/proto"

// After receiving TypeOK:
switch spec.Proto {
case proto.ProtoHTTP:
    c.log.Info("tunnel ready",
        zap.String("proto", "http"),
        zap.String("url", reg.URL),
        zap.Uint16("local_port", spec.LocalPort),
    )
case proto.ProtoTCP:
    c.log.Info("tunnel ready",
        zap.String("proto", "tcp"),
        zap.String("remote_addr", reg.Addr),
        zap.Uint16("local_port", spec.LocalPort),
    )
}
```

- [ ] **Step 3: Run tests and build**

Run: `go test ./internal/client/ -timeout 60s`
Run: `go build ./...`
Expected: all pass, clean build

- [ ] **Step 4: Run full test suite**

Run: `go test ./... -timeout 60s -race`
Expected: all pass

---

## Self-Review Checklist

- [x] All 4 gaps addressed: proto constants, dangerous port blocking, bind confirmation, client logging
- [x] No placeholder steps — all code shown inline
- [x] TDD: failing test → implement → passing test for Tasks 1, 3, 5
- [x] Type consistency: `validateTCPLocalPort(port uint16) error` consistent across Tasks 3 and 4
- [x] `bindErr chan<- error` signature consistent across Tasks 4 and 5
- [x] `proto.ProtoHTTP` / `proto.ProtoTCP` consistent across Tasks 1, 2, 4, 6
- [x] No git commands — user must confirm before any git operations
