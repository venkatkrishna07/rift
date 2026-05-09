# Configuration

`rift` reads optional TOML configuration files for both the `server` and `client`
subcommands. Configuration is layered, with later sources overriding earlier ones:

1. Built-in defaults
2. Config file (lowest precedence among user inputs)
3. Environment variables (`$RIFT_ADMIN_SECRET`, `$RIFT_FORCE_INSECURE`)
4. Command-line flags (highest precedence)

A flag set on the command line **always** overrides the same key in the file.
A flag _not_ passed falls back to the file value, then to the default.

## Locating the config file

Resolved in this order:

1. `--config <path>` flag
2. `$RIFT_CONFIG` environment variable
3. (none — only built-in defaults + flags are used)

There is no implicit search path. You must point at the file explicitly.

## Server configuration

See [`examples/server.toml`](examples/server.toml) for a complete example.

| Section / key            | Type     | Default               | Notes                                          |
| ------------------------ | -------- | --------------------- | ---------------------------------------------- |
| `server.domain`          | string   | `tunnel.localhost`    | Base domain for HTTP tunnels                   |
| `server.listen`          | string   | `:443`                | QUIC (UDP) + HTTPS (TCP) share this port       |
| `server.http`            | string   | `:80`                 | HTTP-01 ACME challenge listener                |
| `server.db`              | string   | `/var/lib/rift/db`    | BadgerDB data directory                        |
| `server.max-body-bytes`  | int      | `104857600` (100 MiB) | Max HTTP body proxied through an HTTP tunnel   |
| `server.stream-timeout`  | duration | `"5m"`                | Idle timeout per data stream                   |
| `server.max-conns`       | int      | `500`                 | Server-wide concurrent QUIC connections        |
| `server.tcp-port-min`    | uint16   | `10000`               | Lower bound of TCP tunnel port range           |
| `server.tcp-port-max`    | uint16   | `65535`               | Upper bound of TCP tunnel port range           |
| `server.token-ttl`       | duration | `"1h"`                | Default token lifetime; `"0s"` = no expiry     |
| `server.admin-secret`    | string   | _empty_               | Bearer secret for `/_admin/tokens`             |
| `tls.cert`               | string   | _empty_               | Pre-provisioned wildcard cert PEM              |
| `tls.key`                | string   | _empty_               | Required when `tls.cert` is set                |

`--dev` and `--add-token` are intentionally **flag-only** and have no config-file
equivalent. `--dev` controls a security boundary; `--add-token` is a one-shot
operation.

Durations use Go's `time.ParseDuration` format: `"5m"`, `"1h30m"`, `"500ms"`.

## Client configuration

See [`examples/client.toml`](examples/client.toml) for a complete example.

| Section / key             | Type     | Default                  | Notes                                          |
| ------------------------- | -------- | ------------------------ | ---------------------------------------------- |
| `client.server`           | string   | _required_               | Server host or `host:port`                     |
| `client.token`            | string   | _empty_                  | Auth token; falls back to saved DB             |
| `client.db`               | string   | `~/.local/share/rift`    | Token DB path; `~` is expanded                 |
| `client.insecure`         | bool     | `false`                  | Skip TLS verification (dev only)               |
| `client.force-insecure`   | bool     | `false`                  | Allow `insecure` against non-localhost servers |
| `client.stream-timeout`   | duration | `"5m"`                   | Idle timeout per data stream                   |
| `client.protocol`         | string   | `"rift"`                 | `"rift"` or `"mcp"`                            |
| `[[tunnels]].local-port`  | uint16   | _required_               | Local TCP port to forward                      |
| `[[tunnels]].proto`       | string   | _required_               | `"http"`, `"tcp"`, or `"mcp"`                  |
| `[[tunnels]].name`        | string   | _empty_                  | Subdomain (HTTP) or label                      |

`[[tunnels]]` blocks are **additive** with `--expose` flags. Tunnels declared in
the file are registered alongside any tunnels supplied via flags.

## Unknown keys are errors

Any key the loader does not recognise (typo, removed option) causes startup to
fail with the exact key name. This catches `domian = "..."` style mistakes
before they silently fall through to defaults.
