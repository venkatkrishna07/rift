<div align="center">

# rift

**A self-hosted tunnel for local development. One binary, one VPS, no accounts.**

Expose localhost to the internet over a single QUIC connection — on infrastructure you fully own. Built for sharing dev servers, testing webhooks, and demoing work in progress.

[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go)](https://go.dev) [![Go Reference](https://pkg.go.dev/badge/github.com/venkatkrishna07/rift.svg)](https://pkg.go.dev/github.com/venkatkrishna07/rift) [![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

```
  localhost:3000  ──── QUIC ────▶  https://myapp.tunnel.example.com
  localhost:5432  ──── QUIC ────▶  tunnel.example.com:10247
  localhost:9090  ──── QUIC ────▶  mcp.example.com (MCP server)
```

Two ways to use it:

```bash
# CLI
rift client --server tunnel.example.com --expose 3000:http:myapp
# → tunnel ready  https://myapp.tunnel.example.com
```

```go
// Library (embed in your own Go program)
import "github.com/venkatkrishna07/rift"
```

That's it. Your local dev server is now reachable on the internet, over HTTPS, through a server you run.

---

## Where rift fits

Self-hosted tunnels already exist — [frp](https://github.com/fatedier/frp), [bore](https://github.com/ekzhang/bore), [chisel](https://github.com/jpillora/chisel). They all ride on TCP. rift is the same idea, but built on QUIC, which gives you three things you can't get over TCP:

- **No head-of-line blocking between tunnels.** On TCP, a lost packet on one multiplexed stream stalls every other stream on the same connection until it's retransmitted. QUIC isolates streams, so a hiccup on your API tunnel doesn't freeze your database tunnel.
- **Connection migration.** Switch from Wi-Fi to a hotspot, toggle your VPN, change networks mid-session — the QUIC connection survives without reconnecting or re-authenticating.
- **TLS 1.3 is part of the handshake**, not layered on top. Encrypted from the first byte, in fewer round trips.

If your network blocks UDP/443 (some corporate and café networks do), TCP-based tools will punch through more reliably. Otherwise QUIC is a cleaner foundation for what tunnels actually do.

## Feature comparison

| | **rift** | ngrok | cloudflared | frp | bore |
|---|:---:|:---:|:---:|:---:|:---:|
| Self-hosted | ✅ | ❌ | ❌ | ✅ | ✅ |
| No account required | ✅ | ❌ | ❌¹ | ✅ | ✅ |
| Transport | QUIC | HTTP/2 | QUIC | TCP | TCP |
| HTTP + subdomains | ✅ | ✅² | ✅ | ✅ | ❌ |
| TCP tunnels | ✅ | ✅ | ✅ | ✅ | ✅ |
| MCP tunnels | ✅ | ❌ | ❌ | ❌ | ❌ |
| UDP tunnels | ⏳³ | ❌ | ❌ | ✅ | ❌ |
| WebSockets | ✅ | ✅ | ✅ | ✅ | ✅ |
| Auto TLS (Let's Encrypt) | ✅ | managed | managed | manual | ❌ |
| Open source | ✅ | ❌ | ✅ | ✅ | ✅ |

<sub>¹ Cloudflare Tunnel requires a Cloudflare account and a domain added to Cloudflare DNS .</sub>
<br>
<sub>² ngrok's free tier gives you one random `*.ngrok-free.app` subdomain. Persistent and custom subdomains are on paid plans </sub>
<br>
<sub>³ UDP tunnels are work in progress</sub>

## Quick start (local)

**Terminal 1 — server**
```bash
rift server --dev --listen :4443
```

**Terminal 2 — client**
```bash
rift client --server localhost:4443 --insecure --expose 3000:http:myapp
# → https://myapp.tunnel.localhost
```

To go public, swap `--dev` for a real domain and move the server to a VPS. See [Setup](#setup).

## Use as a Go library

rift is also a Go library. Embed a tunnel server or client directly in your own program — same QUIC engine as the CLI, no shell-out, full programmatic control over lifecycle, logging, and auth.

```bash
go get github.com/venkatkrishna07/rift
```

**Server:**

```go
package main

import (
    "context"
    "log"
    "log/slog"
    "os"

    "github.com/venkatkrishna07/rift"
)

func main() {
    tlsCfg, err := rift.DevTLSConfig("tunnel.localhost")
    if err != nil { log.Fatal(err) }

    srv, err := rift.NewServer(rift.ServerConfig{
        Domain:     "tunnel.localhost",
        ListenAddr: "127.0.0.1:4443",
        Dev:        true,
    },
        rift.WithTLSConfig(tlsCfg),
        rift.WithLogger(rift.SlogAdapter(slog.New(slog.NewTextHandler(os.Stderr, nil)))),
    )
    if err != nil { log.Fatal(err) }

    if err := srv.Run(context.Background()); err != nil {
        log.Fatal(err)
    }
}
```

**Client:**

```go
cli, err := rift.NewClient(rift.ClientConfig{
    Server:   "tunnel.example.com:443",
    Token:    "rift_xxx",
    Tunnels:  []rift.TunnelSpec{{LocalPort: 3000, Proto: rift.ProtoHTTP, Name: "app"}},
    Protocol: rift.ProtocolRift,
})
if err != nil { log.Fatal(err) }
defer cli.Close()

if err := cli.Connect(context.Background()); err != nil {
    log.Fatal(err)
}
```

**Highlights:**

- Functional options on both constructors — forward-compatible API.
- `Logger` interface (slog-shaped). Pass `rift.SlogAdapter(*slog.Logger)`, `rift.NopLogger()`, or any custom impl. No zap dep forced on consumers.
- Sentinel errors at the boundary — `errors.Is(err, rift.ErrAuthFailed)`, `ErrTokenExpired`, `ErrIPBlocked`, `ErrSubdomainTaken`, `ErrPortsExhausted`.
- `(*Server).Shutdown(ctx)` and `(*Client).Close()` for graceful lifecycle. `Server.Addr()` exposes the bound UDP address (useful with `:0`).
- TokenStore interface with a Badger implementation: `rift.OpenBadgerStore(path, log)`. Provision tokens via `rift.NewAdminSecretIssuer(...)` mounted with `rift.WithTokenIssuer(...)`.
- Single-use semantics: construct a fresh `Server`/`Client` per lifecycle.

Runnable examples in [`examples/`](examples/):

```bash
# Terminal 1 — embedded server (dev mode, no token auth)
go run ./examples/server -domain tunnel.localhost -listen 127.0.0.1:4443

# Terminal 2 — embedded client
go run ./examples/client -server 127.0.0.1:4443 -local 3000 -name myapp -insecure
```

Full reference: [pkg.go.dev/github.com/venkatkrishna07/rift](https://pkg.go.dev/github.com/venkatkrishna07/rift).

> **MCP support is opt-in.** The default build excludes the `caddy-mcp` dependency. Build or import with `-tags mcp` if you need MCP tunneling: `go get -tags mcp github.com/venkatkrishna07/rift` then `go build -tags mcp ./...`.

## How it works

```
  visitor ──HTTPS──▶  rift server  ──QUIC stream──▶  rift client  ──TCP──▶  localhost
           (your domain)   (your VPS)                   (your laptop)       (your app)
```

1. Client dials the server over QUIC and authenticates with a token.
2. Each `--expose` flag registers a tunnel — the server assigns a subdomain (HTTP) or a port (TCP).
3. A visitor hits the public URL. The server opens a new QUIC stream to the client, which forwards the request to the local service.
4. Response flows back along the same path.

One QUIC connection carries every tunnel, with no head-of-line blocking between them. Auth tokens are never sent in 0-RTT data, to prevent replay attacks.

## Setup

To use rift beyond `--dev` mode on your laptop, you'll need somewhere public for the server to live.

**What you need:**
- A VPS with a public IP (DigitalOcean, Hetzner, Linode, Fly.io, anything).
- A domain name.
- A wildcard DNS record: `*.tunnel.example.com → <your-server-ip>` (required for HTTP subdomain routing).
- Ports 80 and 443 open, plus a TCP range if you want TCP tunnels.

**Automatic TLS** via Let's Encrypt (default):

```bash
rift server \
  --domain tunnel.example.com \
  --db /var/lib/rift/db \
  --admin-secret "$RIFT_ADMIN_SECRET"
```

**Pre-provisioned certificate** (if you already have a wildcard cert):

```bash
rift server \
  --domain tunnel.example.com \
  --cert /path/to/fullchain.pem \
  --key  /path/to/privkey.pem
```


## Tokens

Clients authenticate with tokens. Default TTL is 1 hour — the connected client is disconnected when its token expires.

**Offline** (server stopped, direct DB access):
```bash
rift server --db /var/lib/rift/db --add-token alice
# → rift_4a7f...
```

**Online** via the loopback-only admin API:
```bash
curl -s -X POST \
  -H "Authorization: Bearer $RIFT_ADMIN_SECRET" \
  "http://localhost/_admin/tokens?name=alice&ttl=168h"
# → {"name":"alice","token":"rift_4a7f...","ttl":"168h0m0s"}
```

The admin endpoint only binds to `127.0.0.1` and `::1`, and rate-limits at 5 req/min/IP. To provision from elsewhere, SSH in first.

For tokens that never expire, start the server with `--token-ttl 0`.

## Client

**Multiple tunnels over one connection:**
```bash
rift client --server tunnel.example.com --token rift_... \
  --expose 3000:http:frontend \
  --expose 4000:http:api \
  --expose 5432:tcp
```

**Persistent tokens.** After the first run, the token is cached in `~/.local/share/rift` and picked up automatically on subsequent connections to the same server.

**Reconnection.** Exponential backoff from 1s up to 30s. Permanent errors (invalid token, expired token, blocked IP) exit immediately instead of looping.

## MCP tunnels

rift can tunnel MCP (Model Context Protocol) servers through [caddy-mcp](https://github.com/venkatkrishna07/caddy-mcp) — a Caddy plugin that exposes MCP servers via QUIC.

> MCP support requires the `mcp` build tag so the `caddy-mcp` dep is opt-in for non-MCP users. Build with `make build TAGS=mcp` (or `go build -tags mcp ./cmd/rift`). The default `rift` binary will reject `--protocol mcp` with a clear "MCP support not compiled in" error.

```bash
# Start your MCP server locally
./my-mcp-server --port 9090

# Connect through caddy-mcp
rift client --server mcp.example.com --protocol mcp --token mcp_... \
  --expose 9090:http:code-server
```

The `--protocol mcp` flag switches the wire protocol from `rift-v1` to `mcp-v1` (24-byte tunnel headers, MCP-aware registration). The MCP server is then accessible through Caddy's HTTP endpoint with full Streamable HTTP transport support — tools, resources, prompts, and SSE notifications all work through the tunnel.

**Dev mode:**
```bash
rift client --server localhost:4433 --protocol mcp --insecure \
  --expose 9090:http:code-server
```

> MCP tunnels currently support one tunnel per connection. The `--expose` format is `PORT:http:TUNNEL_NAME` where TUNNEL_NAME must match the tunnel name configured in caddy-mcp's Caddyfile.

## TCP tunnels

```bash
rift client --server tunnel.example.com --expose 5432:tcp
# → tunnel.example.com:10003

psql -h tunnel.example.com -p 10003 -U postgres mydb
```

The server's TCP port range is configurable via `--tcp-port-min` and `--tcp-port-max`.

> TCP tunnels relay raw bytes — there's no visitor authentication at the tunnel layer. Use your application's own auth or restrict access at the firewall.

Blocked local ports (to prevent accidental SMTP relay and similar): `25, 53, 135, 139, 445, 465, 587, 3389`.

## WebSockets

Proxied transparently through HTTP tunnels. No extra configuration needed.

## CLI reference

### `rift server`

| Flag | Default | Description |
|---|---|---|
| `--domain` | `tunnel.localhost` | Base domain for HTTP tunnels |
| `--listen` | `:443` | Listen address — QUIC (UDP) and HTTPS (TCP) share this port |
| `--http` | `:80` | HTTP address for ACME challenges |
| `--dev` | — | Dev mode: self-signed cert, no auth |
| `--cert` / `--key` | — | Pre-provisioned TLS cert + key PEM files |
| `--db` | `/var/lib/rift/db` | BadgerDB data directory |
| `--add-token` | — | Provision a token for NAME and exit |
| `--admin-secret` | `$RIFT_ADMIN_SECRET` | Bearer secret for `/_admin/tokens` |
| `--token-ttl` | `1h` | Default token lifetime; `0` = no expiry |
| `--max-body-bytes` | `100 MiB` | Max HTTP request/response body size |
| `--stream-timeout` | `5m` | Idle stream timeout |
| `--max-conns` | `500` | Max concurrent QUIC connections |
| `--tcp-port-min` | `10000` | TCP tunnel port range lower bound |
| `--tcp-port-max` | `65535` | TCP tunnel port range upper bound |

### `rift client`

| Flag | Default | Description |
|---|---|---|
| `--server` | — | Server host or host:port **(required)** |
| `--expose` | — | `PORT:PROTO[:NAME]` — repeatable **(required)** |
| `--token` | — | Auth token (overrides DB lookup) |
| `--protocol` | `rift` | Wire protocol: `rift` or `mcp` |
| `--db` | `~/.local/share/rift` | Local token store |
| `--stream-timeout` | `5m` | Idle stream timeout |
| `--insecure` | — | Skip TLS verification (dev server only) |
| `--force-insecure` | — | Allow `--insecure` for non-localhost servers (also requires `RIFT_FORCE_INSECURE=yes`) |

`--expose` format: `PORT:http`, `PORT:tcp`, `PORT:http:name` for a fixed subdomain, or `PORT:http:tunnel-name` with `--protocol mcp`.

### `/_admin/tokens` API

```
POST /_admin/tokens?name=<n>[&ttl=<duration>]
Authorization: Bearer <admin-secret>

200  {"name":"alice","token":"rift_...","ttl":"1h0m0s"}
400  name query param required
401  unauthorized
403  forbidden (non-loopback IP)
429  too many requests
```

## Status

rift started as a project to understand QUIC internals and tunnel architecture end-to-end. It works and is stable for personal and small-team use.

**What's solid:** HTTP and TCP tunneling, automatic TLS, token auth, reconnection, WebSockets, connection migration.



## Build from source

Go 1.22+ required.

```bash
git clone https://github.com/venkatkrishna07/rift
cd rift
make build

# With version metadata
make build VERSION=v1.0.0 COMMIT=$(git rev-parse --short HEAD) DATE=$(date -u +%Y-%m-%d)

# Dev server + client (two terminals)
make dev-server
make dev-client
```

## Docker

```bash
# Build image locally
make docker                    # default build
make docker-mcp                # with -tags mcp

# Or via docker directly
docker build -t rift:dev .
docker build -t rift:dev-mcp --build-arg TAGS=mcp .
```

The image is multi-stage Alpine — Go builder → minimal runtime. The container runs as a non-root user (`rift`) and writes BadgerDB + ACME cache under `/data` (declared volume). No default subcommand: pass `server …` or `client …` explicitly.

> **Run server and client in separate containers.** They have different roles, different network needs, different lifetimes — typically different machines too. Never collapse them into one container. The image's `ENTRYPOINT` accepts whichever subcommand you pass; one container = one subcommand.

**docker run — server:**

```bash
docker run -d --name rift \
  -p 443:443/udp -p 443:443/tcp -p 80:80/tcp \
  -p 10000-10010:10000-10010/tcp \
  -v rift-data:/data \
  -e RIFT_ADMIN_SECRET \
  rift:dev \
  server \
    --domain tunnel.example.com \
    --listen :443 --http :80 --db /data/db \
    --admin-secret "$RIFT_ADMIN_SECRET" \
    --tcp-port-min 10000 --tcp-port-max 10010
```

**docker run — client** (forward host port 3000 through tunnel):

```bash
docker run --rm \
  -e RIFT_TOKEN \
  rift:dev \
  client \
    --server tunnel.example.com \
    --token "$RIFT_TOKEN" \
    --expose 3000:http:myapp
```

**docker compose:**

- [`docker-compose.yml`](docker-compose.yml) — public rift server. Set `RIFT_ADMIN_SECRET` and `RIFT_DOMAIN` in a `.env`, then `docker compose up -d`. ACME cert cache persists under `/data/db/certs`.
- [`docker-compose.client.yml`](docker-compose.client.yml) — client side. Linux only (uses `network_mode: host` to reach loopback services on the host). On macOS / Windows / Docker Desktop run the client outside Docker, or run the upstream service inside the same Docker network as the client and target it by hostname.

```bash
docker compose up -d                                       # server
docker compose -f docker-compose.client.yml up             # client (Linux host)
```

> **Ports**: QUIC (UDP) and HTTPS (TCP) share `:443`. ACME HTTP-01 needs `:80`. TCP tunnel ports must be published to match `--tcp-port-min`/`--tcp-port-max`. The image only `EXPOSE`s 443 + 80 — bring your own `-p` for the TCP range.

## Contributing

Issues and PRs welcome. For larger changes, open an issue first so we can discuss the approach. Reproduction steps make bug reports much easier to act on.

## License

MIT — see [LICENSE](LICENSE).