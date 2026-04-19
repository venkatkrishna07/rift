# rift

A self-hosted tunnel server. Expose any local HTTP service or TCP port to the internet over a single QUIC connection — using infrastructure you control.

```
localhost:3000  ──── QUIC ────▶  https://myapp.tunnel.example.com
localhost:5432  ──── QUIC ────▶  tunnel.example.com:10247
```

---

If you've used **ngrok**, **Cloudflare Tunnel**, or **localtunnel**, rift does the same thing — except the server is yours. Your traffic doesn't pass through anyone else's infrastructure. There are no accounts, no dashboards, no monthly limits, and nothing phoning home.

The tradeoff: you need a VPS or a cloud VM to run the server side.

---

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Compared to alternatives](#compared-to-alternatives)
- [Production setup](#production-setup)
- [Token management](#token-management)
- [Client usage](#client-usage)
- [TCP tunnels](#tcp-tunnels)
- [WebSocket support](#websocket-support)
- [CLI reference](#cli-reference)
- [Building from source](#building-from-source)

---

## Quick start

Dev mode spins up with a self-signed certificate and no authentication. Good for local testing.

**Server**
```bash
rift server --dev --listen :4443
```

**Client** (different terminal or machine)
```bash
# HTTP tunnel — gets a random public subdomain
rift client --server localhost:4443 --insecure --expose 3000:http

# Named subdomain
rift client --server localhost:4443 --insecure --expose 3000:http:myapp

# Raw TCP (database, SSH, anything)
rift client --server localhost:4443 --insecure --expose 5432:tcp
```

Once registered, the client prints where the tunnel is available:

```
{"msg":"tunnel ready","proto":"http","url":"https://myapp.tunnel.localhost","local_port":3000}
{"msg":"tunnel ready","proto":"tcp","remote_addr":"tunnel.localhost:10001","local_port":5432}
```

---

## How it works

```
visitor ──HTTPS──▶ rift server (your VPS) ──QUIC stream──▶ rift client ──TCP──▶ localhost:PORT
```

1. The client dials your server over QUIC and authenticates with a token.
2. It registers each `--expose` flag — the server assigns a subdomain (HTTP) or port (TCP).
3. When a visitor hits the public URL, the server opens a new QUIC stream to the waiting client and relays the request.
4. The client forwards it to the local service and relays the response back.

**Why QUIC?**
One connection carries all tunnels with no head-of-line blocking. If your laptop switches networks, the connection migrates silently. Reconnects are fast. Auth tokens are never sent in 0-RTT data to prevent replay attacks.

---

## Compared to alternatives

Most tunnel tools in this space — ngrok, Cloudflare Tunnel, Tailscale Funnel, localtunnel — route your traffic through servers they operate. That works well and is often the right choice. Rift is for the cases where it isn't.

| | rift | ngrok | Cloudflare Tunnel | frp |
|---|---|---|---|---|
| Self-hosted | ✓ | ✗ | ✗ | ✓ |
| Transport | QUIC | HTTP/2 + TLS | QUIC (MASQUE) | TCP |
| HTTP tunnels | ✓ | ✓ | ✓ | ✓ |
| TCP tunnels | ✓ | paid | ✗ | ✓ |
| TLS termination | automatic (ACME) | managed | managed | manual |
| Account required | ✗ | ✓ | ✓ | ✗ |
| Token auth | ✓ | ✓ | ✓ | ✓ |
| WebSocket support | ✓ | ✓ | ✓ | ✓ |
| Open source | ✓ | partially | ✗ | ✓ |

> This table reflects publicly documented behaviour and is best-effort. Features change.

### Why QUIC matters for tunnels

Most tunnel tools layer their multiplexing on top of TCP. TCP has a fundamental limitation here: a single lost packet stalls every stream sharing the connection until it's retransmitted — head-of-line blocking. For tunnels carrying multiple services over one connection, this means a blip in one service can introduce latency in all the others.

QUIC is built on UDP and handles each stream independently. A dropped packet only stalls the stream it belongs to. The rest keep moving.

A few other things QUIC gets right for this use case:

- **Connection migration.** If your laptop changes IP (switching from Wi-Fi to a hotspot, or a VPN toggling), the QUIC connection continues without renegotiation. TCP would require a full reconnect.
- **Built-in TLS 1.3.** The encryption handshake is part of the transport layer, not layered on top of it — so the connection is encrypted from the first byte.
- **0-RTT resumption.** Reconnects are fast. Rift intentionally sends auth frames only after the full 1-RTT handshake to avoid replaying tokens in 0-RTT data.

frp is a popular self-hosted alternative with a larger feature set. Its tunnel connections run over TCP, which is simpler to operate in constrained network environments (some firewalls block UDP). If UDP/443 is a problem on your network, frp may suit you better. If it isn't, QUIC gives you a cleaner multiplexing model.

---

## Production setup

### What you need

- A server with a public IP (any VPS — DigitalOcean, Hetzner, Linode, etc.)
- A domain name
- A wildcard DNS record: `*.tunnel.example.com → your-server-ip`
  (required for HTTP subdomain routing)
- Ports `80` and `443` open, plus whatever TCP port range you want for TCP tunnels

### TLS

**Automatic (Let's Encrypt)** — the default. Rift handles ACME HTTP-01 challenges and caches certificates automatically.

```bash
rift server --domain tunnel.example.com --db /var/lib/rift/db
```

**Pre-provisioned certificate** — if you already have a wildcard cert:

```bash
rift server \
  --domain tunnel.example.com \
  --cert /path/to/fullchain.pem \
  --key  /path/to/privkey.pem
```

### Running as a service

Any process supervisor works. Example with systemd:

```ini
[Unit]
Description=rift tunnel server
After=network-online.target

[Service]
ExecStart=/usr/local/bin/rift server \
  --domain tunnel.example.com \
  --db /var/lib/rift/db \
  --admin-secret ${RIFT_ADMIN_SECRET}
EnvironmentFile=/etc/rift/env
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## Token management

Clients authenticate with tokens. Tokens have a default TTL of 1 hour and expire automatically — the connected client is disconnected when its token expires.

### Provisioning tokens

**While the server is stopped** (accesses the DB directly):

```bash
rift server --db /var/lib/rift/db --add-token alice
# Token for "alice":
# rift_4a7f...
```

**While the server is running** (via the admin HTTP API):

```bash
# Set a secret — keep it in an env file or secrets manager
export RIFT_ADMIN_SECRET=$(openssl rand -hex 32)

# Start server with the secret
rift server --domain tunnel.example.com --admin-secret "$RIFT_ADMIN_SECRET"

# Provision a token from the same host
curl -s -X POST \
  -H "Authorization: Bearer $RIFT_ADMIN_SECRET" \
  "http://localhost/_admin/tokens?name=alice"
# → {"name":"alice","token":"rift_4a7f...","ttl":"1h0m0s"}
```

Custom TTL or no expiry:

```bash
# 7-day token
curl ... "http://localhost/_admin/tokens?name=ci-runner&ttl=168h"

# Token that never expires (start server with --token-ttl 0)
rift server --domain tunnel.example.com --token-ttl 0
```

> The `/_admin/tokens` endpoint is only reachable from loopback (`127.0.0.1`, `::1`). It accepts at most 5 requests per minute per IP.

---

## Client usage

### Multiple tunnels in one connection

```bash
rift client \
  --server tunnel.example.com \
  --token rift_4a7f... \
  --expose 3000:http:frontend \
  --expose 4000:http:api \
  --expose 5432:tcp
```

### Token persistence

After the first run, the token is saved locally (`~/.local/share/rift`). Subsequent connections to the same server pick it up automatically:

```bash
# First run — provide the token
rift client --server tunnel.example.com --token rift_4a7f... --expose 3000:http

# Later — token loaded automatically
rift client --server tunnel.example.com --expose 3000:http
```

### Reconnection

The client reconnects automatically after transient failures using exponential backoff (1 s → 2 s → … → 30 s cap). On permanent errors — invalid token, expired token, IP blocked — it exits immediately without retrying.

---

## TCP tunnels

TCP tunnels proxy raw bytes. The server allocates a port and accepts connections at `<domain>:<port>`.

```bash
rift client --server tunnel.example.com --token rift_... --expose 5432:tcp
# tunnel ready  remote_addr=tunnel.example.com:10003  local_port=5432

psql -h tunnel.example.com -p 10003 -U postgres mydb
```

The server's TCP port range is configurable:

```bash
rift server --domain tunnel.example.com --tcp-port-min 10000 --tcp-port-max 10010
```

> TCP tunnels carry raw bytes — there is no visitor authentication at the tunnel layer. For anything sensitive, rely on the application's own authentication or restrict access at the firewall.

The following local ports cannot be used as TCP targets: `25` (SMTP), `53` (DNS), `135` (RPC), `139` (NetBIOS), `445` (SMB), `465/587` (SMTP), `3389` (RDP).

---

## WebSocket support

WebSocket connections are proxied transparently through HTTP tunnels — no extra configuration needed.

---

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
POST /_admin/tokens?name=<name>[&ttl=<duration>]
Authorization: Bearer <admin-secret>

200  {"name":"alice","token":"rift_...","ttl":"1h0m0s"}
400  name query param required
401  unauthorized
403  forbidden (non-loopback IP)
429  too many requests
```

---

## Building from source

Requires Go 1.22+.

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

---

## License

MIT
