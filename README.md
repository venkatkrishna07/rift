<div align="center">

# rift

**A self-hosted tunnel for local development. One binary, one VPS, no accounts.**

Expose localhost to the internet over a single QUIC connection — on infrastructure you fully own. Built for sharing dev servers, testing webhooks, and demoing work in progress.

[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

```
  localhost:3000  ──── QUIC ────▶  https://myapp.tunnel.example.com
  localhost:5432  ──── QUIC ────▶  tunnel.example.com:10247
```

```bash
rift client --server tunnel.example.com --expose 3000:http:myapp
# → tunnel ready  https://myapp.tunnel.example.com
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

Systemd unit example in [docs/systemd.md](docs/systemd.md).

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
| `--db` | `~/.local/share/rift` | Local token store |
| `--stream-timeout` | `5m` | Idle stream timeout |
| `--insecure` | — | Skip TLS verification (dev server only) |
| `--force-insecure` | — | Allow `--insecure` for non-localhost servers (also requires `RIFT_FORCE_INSECURE=yes`) |

`--expose` format: `PORT:http`, `PORT:tcp`, or `PORT:http:name` for a fixed subdomain.

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

## Contributing

Issues and PRs welcome. For larger changes, open an issue first so we can discuss the approach. Reproduction steps make bug reports much easier to act on.

## License

MIT — see [LICENSE](LICENSE).