# TR Proxy — Specification

Status: draft, pre-implementation. Config schema version: 1.

## 1. Purpose

TR Proxy is a container that exposes SOCKS5 and HTTP proxy listeners and
routes each incoming connection, by destination hostname or IP address, to one
of several egress paths:

- a userspace WireGuard tunnel (any number of them, each in its own process),
- an upstream HTTP proxy,
- a direct connection,
- or nowhere (block).

It is in the spirit of wireproxy, but with many tunnels, rule-based routing,
health monitoring with automatic restart, and a web UI for configuration and
live status. It is meant to run on a workstation as well as on servers and in
cloud stacks (e.g. AWS), always inside a container.

## 2. Principles

- Always runs in a container; never directly from the command line.
- Unprivileged: no TUN device, no `NET_ADMIN`, no kernel WireGuard.
- No SQL database. One JSON config file on a volume; runtime state in memory.
- Configuration is done through the HTTP admin API/UI, not by hand-editing
  WireGuard config files. The JSON file is visible on the host through the
  volume and may be pre-seeded for automated deployments.
- Robust: every tunnel is monitored and restarted when stuck.
- Extensible: other VPN types may be added later as new egress kinds.

## 3. Stack

- **Language:** Go, one static binary, distroless (or scratch) image.
- **WireGuard:** `wireguard-go` with the gVisor netstack (userspace TCP/IP).
- **UI:** plain HTML/CSS plus Alpine.js vendored as a single file, embedded in
  the binary. No Node toolchain, no build step.
- **Realtime:** WebSocket, server to client only.

## 4. Process model

One binary, two roles.

**Supervisor** (PID 1 in the container):

- loads, validates and saves the config,
- runs the proxy listeners and the rule engine,
- runs the admin API, the UI and the WebSocket,
- spawns one worker per WireGuard connection, monitors them, restarts them
  with exponential backoff, and reaps child processes,
- applies config changes by restarting only the affected workers and
  listeners.

**Worker** (one per WireGuard connection):

- owns one WireGuard device and its netstack,
- exposes a dialer to the supervisor over a unix socket
  (`/run/tr-proxy/<name>.sock`); the supervisor hands it a destination
  (hostname or IP, plus port) and the worker resolves hostnames with the
  tunnel's DNS servers and connects through the tunnel,
- reports status and a heartbeat to the supervisor (handshake age, rx/tx
  counters, probe results, last error).

The supervisor sends the worker its connection spec, including the secret
key, as one JSON line on stdin; secrets never appear in arguments or the
environment. Status reports are JSON lines on the worker's stdout. The
supervisor keeps stdin open for the worker's whole life, and a worker exits
when stdin closes, so workers never outlive the supervisor.

To open a connection through a tunnel the supervisor connects to the worker's
unix socket and sends one JSON line, `{"host": "...", "port": N}`. The worker
answers with one JSON line, `{}` on success or `{"error": "..."}`, and after
a success the socket carries the raw byte stream to the destination. One
socket connection is one proxied connection.

A worker reports `starting` until the first WireGuard handshake, `up` while
the last handshake is younger than three minutes, and `degraded` after that.
The supervisor adds `restarting` while a dead worker waits for its backoff.

Separate processes are for fault isolation: a hung or crashed tunnel is killed
and restarted without touching the others.

## 5. Configuration

Stored at `/config/config.json`. Written atomically (temp file, fsync,
rename). Carries a `version` field. A save is validated as a whole and rejected
as a whole.

```json
{
  "version": 1,
  "keys": [
    { "name": "home-key", "secretKey": "..." }
  ],
  "wireguard": [
    {
      "name": "Private",
      "localKey": "home-key",
      "addresses": ["10.8.0.5/32"],
      "peer": {
        "publicKey": "...",
        "endpoint": "vpn.example.com:51820",
        "presharedKey": null,
        "keepalive": 25
      },
      "dns": ["10.8.0.1"],
      "mtu": 1420,
      "probe": { "type": "dns", "interval": 15, "timeout": 5, "failures": 3 }
    }
  ],
  "upstreams": [
    {
      "name": "H-Proxy",
      "type": "http",
      "url": "https://hproxy.example.com/",
      "auth": { "type": "basic", "username": "...", "password": "..." }
    }
  ],
  "listeners": [
    {
      "name": "main-socks",
      "type": "socks5",
      "port": 1080,
      "auth": { "users": [{ "username": "alice", "password": "..." }] }
    },
    {
      "name": "office-http",
      "type": "http",
      "port": 1081,
      "auth": null,
      "default": "Office1"
    }
  ],
  "rules": [
    {
      "name": "corp",
      "match": ["*.corp.example.com", "10.20.0.0/16"],
      "via": ["Office1", "Office2"]
    },
    {
      "name": "special-range",
      "match": ["1.2.3.4-1.2.3.7"],
      "via": "H-Proxy",
      "exceptListeners": ["office-http"]
    },
    {
      "name": "ads",
      "match": ["ads.example.net"],
      "via": "block"
    }
  ],
  "default": "direct"
}
```

### 5.1 Keys

- `name` is unique. `secretKey` is a base64 WireGuard private key.
- The API can generate a key pair. The secret is write-only; the API returns
  the derived public key only.
- One key may be used by several connections to different peers.

### 5.2 WireGuard connections

- `name`: unique across `wireguard` and `upstreams` (they share the `via`
  namespace); `direct` and `block` are reserved.
- `localKey`: name of an entry in `keys`.
- `addresses`: required. The tunnel-local address(es) the peer expects for
  this key. Not auto-assigned.
- `peer.publicKey`, `peer.endpoint` (`host:port`, host may be a DNS name,
  re-resolved on every worker start), optional `peer.presharedKey`,
  `peer.keepalive` in seconds (default 25).
- `dns`: resolvers reached through the tunnel, used for every hostname routed
  via this connection.
- `mtu`: default 1420.
- `probe`: see section 8.

All destination traffic is allowed into the tunnel (`AllowedIPs` is
effectively `0.0.0.0/0`); selection is done by the rule engine, not by IP
routing.

### 5.3 Upstream proxies

- `type`: `http` (v1). The URL scheme selects plain or TLS to the proxy.
- `auth`: `null`, `{ "type": "basic", ... }` or `{ "type": "bearer", "token": "..." }`.
  Secrets are write-only in the API.
- Connections use `CONNECT`.

### 5.4 Listeners

- `type`: `socks5` or `http` (HTTP proxy with `CONNECT` and plain-HTTP
  forwarding).
- `port`: must be inside `PROXY_PORT_RANGE` (section 9). The listener binds
  all interfaces inside the container; exposure is decided by how the port is
  published.
- `auth`: per listener. `null` means open. Otherwise a list of users:
  SOCKS5 username/password (RFC 1929) or HTTP `Proxy-Authorization: Basic`.
  Passwords are write-only in the API and compared in constant time.
- `default`: optional; overrides the global `default` for this listener.

### 5.5 Rules

- One global, ordered rule list. First match wins; if nothing matches, the
  listener's `default` applies, else the global `default`.
- `name`: unique, used in the UI, status view and logs.
- `match`: list of matchers, any of which matches:
  - exact hostname: `host.example.com`
  - suffix wildcard: `*.example.com` (matches subdomains, not the apex)
  - IP address: `1.2.3.4`
  - CIDR network: `1.2.3.0/24`
  - IP range: `1.2.3.4-1.2.3.7`
- `via`: `direct`, `block`, the name of a WireGuard connection or upstream, or
  a list of names meaning failover in order (first healthy one is used). If
  none is healthy, the connection fails closed; it never falls through to
  `direct` unless `direct` is itself an entry of the list. `block` cannot be
  part of a list.
- Listener scoping, optional and mutually exclusive:
  - `onlyListeners`: the rule applies to these listeners only,
  - `exceptListeners`: the rule is skipped for these listeners.

Matching uses what the client sent. A client that sends an IP address can only
match IP matchers; a client that sends a hostname (SOCKS5 with remote DNS,
HTTP `CONNECT`) is matched on the hostname, and the hostname is then resolved
on the chosen egress path: tunnel DNS for WireGuard, the upstream itself for
HTTP proxies, the container resolver for `direct`.

## 6. Admin API and UI

### 6.1 Authentication

- Credentials come from the environment: `ADMIN_USERNAME`, `ADMIN_PASSWORD`,
  optional `ADMIN_TOTP_SECRET` (base32). The process refuses to start without
  username and password.
- Login form: username, password, and the TOTP code when a secret is set.
- Session cookie: `HttpOnly`, `SameSite=Strict`; sessions are in memory and
  are lost on restart.
- Login attempts are rate limited. A TOTP code is accepted once.
- Origin is checked on every mutating request and on the WebSocket upgrade.
- `/healthz` is unauthenticated and returns process health only (for Docker
  health checks and load balancers).

The admin port speaks plain HTTP. When it is exposed beyond localhost it must
sit behind a TLS-terminating reverse proxy.

### 6.2 REST

All under `/api`, JSON, session required.

- `POST /api/login`, `POST /api/logout`
- `GET /api/config`, `PUT /api/config` (whole config, secrets redacted on
  read; a redacted secret in a write means "keep the stored value")
- CRUD per collection: `/api/keys`, `/api/wireguard`, `/api/upstreams`,
  `/api/listeners`, `/api/rules` (including reordering)
- `POST /api/keys/generate`
- `POST /api/wireguard/{name}/restart`
- `GET /api/status`
- `POST /api/test-route` — given listener and destination, returns the rule
  and egress that would be used

### 6.3 WebSocket

`/api/ws`, server to client only:

- `status`: a full status snapshot, about once per second while a client is
  connected,
- `config-changed`: a nudge; the page refetches the config,
- `event`: a log entry (worker restart, probe failure, auth failure, ...).

### 6.4 Status view

- Per tunnel: state (starting, up, degraded, down, restarting), last handshake
  age, rx/tx bytes, probe latency, restart count, last error.
- Per upstream: reachability, last error.
- Per listener: active connections, auth failures.
- Active connections: listener, client, destination, matched rule, egress,
  bytes, age.
- Recent events, held in memory in a bounded ring.

## 7. Request flow

1. A client connects to a listener and authenticates if the listener requires
   it.
2. The supervisor reads the destination (hostname or IP, and port).
3. The rule engine picks the first matching rule in scope for that listener,
   or the default.
4. The egress is resolved: `block` refuses; `direct` dials from the container;
   an upstream is asked to `CONNECT`; a WireGuard connection is dialed through
   its worker's unix socket. A failover list takes the first healthy entry.
5. Bytes are relayed both ways; counters feed the status view.

SOCKS5 listeners implement `CONNECT` with IPv4, IPv6 and domain-name
destinations. Other commands are refused. Failures are reported with SOCKS
reply codes: "not allowed by ruleset" for `block`, "general failure" when no
egress is healthy, "host unreachable" when the dial fails.

A clean end of one direction is passed on as a half-close; an error closes
both directions.

## 8. Health monitoring

Each WireGuard connection has a configurable probe:

| `type`      | Check                                                        |
|-------------|--------------------------------------------------------------|
| `dns`       | DNS query to the tunnel's first `dns` server (default when `dns` is set) |
| `tcp`       | TCP connect to `target` (`host:port`) through the tunnel     |
| `icmp`      | Ping `target` through the tunnel (e.g. the peer's inner gateway) |
| `handshake` | Passive only: handshake age and counters (default without `dns`) |

- Common fields: `interval`, `timeout`, `failures` (consecutive failures
  before the tunnel is marked down), optional `target`.
- Handshake age is always tracked as well, whatever the probe type.
- A tunnel marked down is restarted with exponential backoff (capped). A
  worker that stops sending heartbeats is killed and restarted.
- While a tunnel is down, rules that point only at it fail closed; failover
  lists skip it.

## 9. Deployment

```
dc/
  docker-compose.yaml.EXAMPLE   committed
  docker-compose.yaml           gitignored
  volumes/                      contents gitignored
    config/                     mounted at /config
```

Environment:

| Variable            | Meaning                                         |
|---------------------|-------------------------------------------------|
| `ADMIN_USERNAME`    | required                                        |
| `ADMIN_PASSWORD`    | required                                        |
| `ADMIN_TOTP_SECRET` | optional, base32                                |
| `ADMIN_PORT`        | admin UI/API port, default 8080                 |
| `PROXY_PORT_RANGE`  | ports listeners may use, default `1080-1099`    |
| `CONFIG_PATH`       | config file, default `/config/config.json`      |
| `RUN_DIR`           | worker sockets, default `/run/tr-proxy`         |

The image is built entirely in containers (multi-stage Dockerfile); the host
needs Docker only. It runs as uid 65532 with all capabilities dropped and
carries its own health check (`/tr-proxy healthcheck`, which asks
`/healthz`). On Linux hosts the config directory must be writable for that
uid.

Docker publishes ports statically, so the compose file publishes the admin
port and the whole proxy port range, and listeners are confined to that range.
The example publishes on `127.0.0.1`; publishing on other interfaces is a
deployment choice and should go together with listener auth.

## 10. Security notes

- The config file holds WireGuard secret keys and proxy passwords in clear
  text; protect the volume accordingly.
- Secrets never leave through the API or the WebSocket.
- Listener auth is per listener and is the access control for the proxy
  itself; open listeners are intended for localhost-only publishing.

## 11. Backlog (not in v1)

- SOCKS5 UDP ASSOCIATE
- IPv6 (inside tunnels and on listeners)
- SOCKS5 upstream proxies
- Chaining an upstream proxy through a tunnel
- Other VPN types as egress kinds
- TLS on the admin port
- Hashed listener passwords
- SNI/Host sniffing for clients that send bare IP addresses
