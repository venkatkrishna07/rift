# Backlog

Items deferred from the architecture review. Not urgent for v1.0 but worth addressing before heavy production use.

---

## 1. Token revocation and listing

**Area:** Operations / Security
**Files:** `internal/store/badger.go`, `internal/store/store.go`

The `TokenStore` interface has no `Revoke(ctx, token)` or `List(ctx)` method. Once a token is issued via `--add-token`, it cannot be invalidated without wiping the entire BadgerDB store.

**Suggested change:**
- Add `Revoke(ctx context.Context, name string) error` and `List(ctx context.Context) ([]string, error)` to the `TokenStore` interface and `BadgerStore` implementation
- Add `rift server --revoke-token NAME` and `rift server --list-tokens` CLI subcommands

---

## 2. Wire protocol versioning

**Area:** Protocol design
**Files:** `internal/proto/proto.go`

`ControlMsg` has no version field. If the wire format needs to change (new field semantics, new required fields), old and new clients/servers have no way to negotiate compatibility.

**Suggested change:**
- Add `Version uint8 \`json:"v,omitempty"\`` to `ControlMsg` (zero value = v0, current behaviour)
- Server rejects connections with `Version > maxSupportedVersion`
- Document the current wire format as v0 in a `docs/protocol.md`

---

## 3. Make operational limits configurable

**Area:** Operations / Scalability
**Files:** `internal/server/server.go`, `internal/server/conn.go`, `internal/server/registry.go`

Three limits are hardcoded package-level constants, not exposed as CLI flags or `ServerConfig` fields:

| Constant | Location | Current value |
|----------|----------|---------------|
| `maxConnsPerIP` | `server.go:23` | 5 |
| `maxTunnelsPerClient` | `conn.go:21` | 10 |
| `maxVisitors` | `registry.go:24` | 50 per tunnel |

**Suggested change:**
- Add `MaxConnsPerIP`, `MaxTunnelsPerClient`, `MaxVisitorsPerTunnel int` fields to `config.ServerConfig`
- Wire them up to new `--max-conns-per-ip`, `--max-tunnels`, `--max-visitors` CLI flags in `main.go`
- Fall back to current default values when zero
