# TR Proxy — Specification

Status: implemented, except the items in section 11. Config schema version: 1.

## 1. Purpose

TR Proxy is a container that exposes SOCKS5 and HTTP proxy listeners and
routes each incoming connection, by destination hostname or IP address, to one
of several egress paths:

- a userspace WireGuard tunnel (any number of them, each in its own process),
- an upstream proxy (HTTP or SOCKS5),
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
- **UI:** plain HTML/CSS plus Alpine.js vendored as a single file
  (`internal/admin/ui/VENDOR.md`), embedded in the binary. No Node toolchain,
  no build step.
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

Every status line carries the tunnel state (section 8), the probe result,
the last handshake time and the byte counters.

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
      "default": "Office1",
      "disabled": false
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
  "default": "direct",
  "limits": {
    "maxConnections": 1024,
    "idleTimeout": 3600,
    "drainTimeout": 5,
    "allowLocalDirect": false
  }
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

An upstream is another proxy used as a route. Two kinds are supported:

| `type`   | `url`                                              | Login (`auth`)              |
|----------|----------------------------------------------------|-----------------------------|
| `http`   | `http://host[:port]/` or `https://host[:port]/`; default port 80 or 443 | `basic` or `bearer` |
| `socks5` | `socks5://host[:port]`; default port 1080. `socks5h://` is accepted and means the same. | `basic` only |

- `auth`: `null`, `{ "type": "basic", "username": "...", "password": "..." }`
  or, for `http` only, `{ "type": "bearer", "token": "..." }`. Secrets are
  write-only in the API. A login is given under `auth`, never inside the URL.
- An `http` upstream is used with `CONNECT` for every connection, plain-HTTP
  requests included (`CONNECT host:80`). An upstream that refuses `CONNECT`
  to port 80 cannot carry plain HTTP. With an `https` URL the connection to
  the upstream itself is TLS, verified against the system certificate roots.
- A `socks5` upstream is used with the SOCKS5 `CONNECT` command (RFC 1928).
  With a `basic` login the username/password method (RFC 1929) is offered
  alongside "no authentication", and both fields must be 1 to 255 bytes.
  The connection to the upstream is not encrypted.
- The upstream is reached directly from the container, at whatever address
  it has, loopback included.
- The destination is handed to the upstream as the client gave it. A
  hostname is therefore resolved by the upstream, not by the container,
  which is also what makes names that only the upstream knows work (for
  instance `.onion` names with a Tor client as the upstream).
- A refusal by the upstream, or a destination it cannot reach, is reported
  to the client as a failed dial (section 7).

### 5.4 Listeners

- `type`: `socks5` or `http` (HTTP proxy with `CONNECT` and plain-HTTP
  forwarding).
- `port`: must be inside `PROXY_PORT_RANGE` (section 9). The listener binds
  all interfaces inside the container; exposure is decided by how the port is
  published.
- `auth`: per listener. `null` means open. Otherwise a list of users:
  SOCKS5 username/password (RFC 1929) or HTTP `Proxy-Authorization: Basic`.
  Passwords are write-only in the API and compared in constant time.
  A SOCKS5 client that does not offer username/password is refused; an HTTP
  client without valid credentials gets a 407. Rejected credentials are
  counted per listener and logged with the client address and username; a
  request that carries no credentials at all is not counted.
- `default`: optional; overrides the global `default` for this listener.
- `disabled`: optional. A disabled listener stays in the config, users and
  all, but its port is not opened. Disabling a running listener closes the
  port; connections it already accepted stay open. Its port stays reserved:
  no other listener may use it. The setting is part of the config, so it
  survives a restart.

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

### 5.6 Limits

`limits` and each of its fields are optional; a field left out takes its
default. Changes apply to the running proxy at once, without reopening
listeners or interrupting connections.

| Field              | Default | Meaning                                    |
|--------------------|---------|--------------------------------------------|
| `maxConnections`   | 1024    | Client connections one listener serves at a time. A connection beyond that is closed as soon as it is accepted, and counted. Connections still in their handshake count too. |
| `idleTimeout`      | 3600    | Seconds. A proxied connection on which no byte has moved in either direction for this long is closed. So is one whose write has been stuck that long. 0 means never. |
| `drainTimeout`     | 5       | Seconds that shutdown waits for open connections; 0 means not at all. |
| `allowLocalDirect` | false   | Whether `direct` may connect to loopback, link-local, multicast and unspecified addresses and to the container's own addresses. |

A quiet direction does not time out while the other one is busy: a long
download with a silent client stays up.

Unless `allowLocalDirect` is set, `direct` refuses those addresses, and the
addresses of the container's own network interfaces, judged by the address
actually connected to after name resolution, and the client gets the same
answer as for a `block` rule. This keeps proxy clients from the container's
own admin API and listeners, which listen on every interface and so are also
reachable on the container's network address, and from a cloud host's
metadata service. With host networking the host's addresses are the
container's own, so they are refused too. It applies to destinations of `direct` only: an upstream proxy or a
WireGuard endpoint on such an address is still used, and private networks
are not refused.

## 6. Admin API and UI

### 6.1 Authentication

- Credentials come from the environment: `ADMIN_USERNAME`, `ADMIN_PASSWORD`,
  optional `ADMIN_TOTP_SECRET` (base32). The process refuses to start without
  username and password.
- `POST /api/login` takes `{"username", "password", "totp"}` and sets the
  session cookie `tr_proxy_session`: `HttpOnly`, `SameSite=Strict`, and
  `Secure` when the request arrived over TLS or carries
  `X-Forwarded-Proto: https`.
- Sessions live in memory for twelve hours and are lost on restart.
- TOTP is RFC 6238 (SHA-1, six digits, 30-second steps). The code of the
  current step or a neighbouring one is accepted, and each code works once.
  A wrong password does not use a code up.
- Ten failed logins within a minute lock the login for everyone until the
  minute has passed (HTTP 429). The limit is global, not per client, because
  behind Docker's port publishing clients share a source address.
- Requests that change something, and the login itself, are refused with 403
  when a browser sent them from another origin (`Origin` host differs from
  `Host`, or `Sec-Fetch-Site` says cross-site). Requests without browser
  headers, such as scripts, pass this check and still need a session.
- `/healthz` is unauthenticated and returns process health only (for Docker
  health checks and load balancers).
- Login attempts are written to the event log.

The admin port speaks plain HTTP. When it is exposed beyond localhost it must
sit behind a TLS-terminating reverse proxy.

### 6.2 REST

All under `/api`, JSON in and out. Unknown fields in a request body are an
error. Everything except the three session endpoints needs a session and
answers 401 without one.

Session:

| Request             | Answer                                             |
|---------------------|----------------------------------------------------|
| `GET /api/session`  | `{"authenticated": bool, "totp": bool}`; `totp` says whether login needs a code |
| `POST /api/login`   | 200 and the cookie, 401 on bad credentials, 429 when locked |
| `POST /api/logout`  | Ends the session                                   |

Configuration:

| Request                              | Effect                                   |
|--------------------------------------|------------------------------------------|
| `GET /api/config`                    | The whole config, secrets redacted       |
| `PUT /api/config`                    | Replace the whole config                 |
| `GET /api/<collection>`              | List                                     |
| `POST /api/<collection>`             | Add an entry; 409 if the name exists     |
| `GET /api/<collection>/{name}`       | One entry                                |
| `PUT /api/<collection>/{name}`       | Replace an entry (it may be renamed)     |
| `DELETE /api/<collection>/{name}`    | Remove an entry                          |
| `POST /api/rules/order`              | Reorder: body is the list of all rule names |
| `POST /api/keys/generate`            | Body `{"name"}`: create a key pair       |
| `POST /api/listeners/{name}/disable` | Close the listener's port, keep its entry |
| `POST /api/listeners/{name}/enable`  | Open it again                            |

`<collection>` is `keys`, `wireguard`, `upstreams`, `listeners` or `rules`.

- Every change, whole-config or single entry, goes the same way: the
  resulting config is validated as a whole, saved atomically, then applied.
  A config that fails validation is refused with 400 and
  `{"error", "problems": [...]}`, and nothing changes. Removing something
  that is still referenced fails this way.
- Secrets are never returned. In answers they read `<redacted>`, and each
  key carries a derived `publicKey`. A write that sends `<redacted>` back
  keeps the stored value, found by name: the key's name, the connection's
  name (preshared key), the upstream's name (password, token), or the
  listener's name plus username. A placeholder with nothing stored behind
  it, for instance after a rename, is refused.
- `publicKey` is ignored on input and not stored.

Applying a config touches only what changed:

- A worker is restarted when its connection or its key changed, stopped when
  the connection was removed and started when it is new. Other tunnels keep
  running.
- A listener is reopened when its type, port or users changed. Connections
  it already accepted continue.
- Rules, defaults and upstreams take effect for new connections at once.

Actions and status:

| Request                               | Effect                                  |
|---------------------------------------|-----------------------------------------|
| `POST /api/wireguard/{name}/restart`  | Restart one tunnel's worker             |
| `POST /api/test-route`                | Body `{"listener", "host"}`: answers `{"rule", "via", "egress", "error"}` for how that destination would be routed right now |
| `GET /api/status`                     | Live status, see 6.4                    |

If the config file exists at start-up but cannot be parsed or fails
validation, the supervisor does not exit: it runs on an empty config, leaves
the file untouched, and reports the problem as `configError` in the status
until a config is saved through the API.

### 6.3 WebSocket

`GET /api/ws` upgrades to a WebSocket. It needs a session and the same
origin. The server sends JSON messages; the client sends nothing.

| `type`           | Content                                                  |
|------------------|----------------------------------------------------------|
| `status`         | `status`: a status snapshot (6.4) without the event log, once per second |
| `events`         | `events`: event log entries the client has not seen yet; the backlog comes first |
| `config-changed` | Nothing more: the config was changed, refetch it         |

The stream is closed when the session ends.

### 6.4 Status view

`GET /api/status` returns:

- `tunnels`: per tunnel the state, worker pid, restart count, last error,
  last heartbeat, last handshake, rx/tx bytes, the endpoint and the probe
  (type, ok, latency in ms, consecutive failures, error).
- `upstreams`: reachability, last error and time of the last check.
- `listeners`: type, port, whether auth is on, whether it is disabled,
  active connections, rejected logins, connections refused at the connection
  limit, and the error if the port could not be opened.
- `connections`: listener, client, destination, matched rule, egress, bytes
  up and down, start time.
- `events`: the most recent 200 events (tunnel state changes and restarts,
  listener failures, rejected proxy logins, admin logins, config changes, a
  listener reaching its connection limit), held in memory. Of the
  connections refused at the limit, the first and then every thousandth is
  logged, so that a flood cannot push everything else out.
- `configError`, if the config file was not usable at start-up.

### 6.5 Web UI

The admin port serves a single page at `/` with its files under `/ui/`. The
page itself is public and holds nothing but the sign-in form until a session
exists; all data comes from the API.

- Sign in, with the code field shown when TOTP is on.
- Status: tunnels (state, peer, handshake age, probe, traffic, restarts,
  restart button), upstream proxies, listeners, open connections and the
  event log, kept live over the WebSocket.
- Tunnels: WireGuard connections and local keys. Keys are generated or
  pasted, and their public key can be copied; they are not edited.
- Upstream proxies, Listeners (with their users, and a button to disable
  or enable each one) and Rules (ordering, the
  global default route, and a form that shows how a destination would be
  routed).
- Config as JSON: the whole config in a text box, saved through
  `PUT /api/config`.

Problems the server finds with a change are shown in the form and nothing is
saved. Every response of the admin port carries a content security policy
that allows same-origin resources only (scripts additionally `unsafe-eval`,
which Alpine.js needs), and forbids framing.

------------------------------------|
| `status`         | `status`: a status snapshot (6.4) without the event log, once per second |
| `events`         | `events`: event log entries the client has not seen yet; the backlog comes first |
| `config-changed` | Nothing more: the config was changed, refetch it         |

The stream is closed when the session ends.

### 6.4 Status view

`GET /api/status` returns:

- `tunnels`: per tunnel the state, worker pid, restart count, last error,
  last heartbeat, last handshake, rx/tx bytes, the endpoint and the probe
  (type, ok, latency in ms, consecutive failures, error).
- `upstreams`: reachability, last error and time of the last check.
- `listeners`: type, port, whether auth is on, whether it is disabled,
  active connections, rejected logins, connections refused at the connection
  limit, and the error if the port could not be opened.
- `connections`: listener, client, destination, matched rule, egress, bytes
  up and down, start time.
- `events`: the most recent 200 events (tunnel state changes and restarts,
  listener failures, rejected proxy logins, admin logins, config changes, a
  listener reaching its connection limit), held in memory. Of the
  connections refused at the limit, the first and then every thousandth is
  logged, so that a flood cannot push everything else out.
- `configError`, if the config file was not usable at start-up.

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

HTTP listeners accept `CONNECT host:port` tunnels and plain-HTTP requests
with an absolute `http://` URL. A `CONNECT` tunnel carries any TCP protocol,
SSH included. The success line is sent in the client's HTTP version
(`HTTP/1.0 200` to an HTTP/1.0 request), because some clients, macOS `nc`
among them, accept nothing else. Each forwarded plain-HTTP request is routed
on its own and uses its own upstream connection; `Proxy-*` headers are not
passed on and no `X-Forwarded-*` headers are added. Failures are reported as
403 for `block`, 503 when no egress is healthy and 502 when the dial fails.
Any other request to the port gets a 400.

A clean end of one direction is passed on as a half-close; an error closes
both directions.

### 7.1 Reload and shutdown

A config change never interrupts a connection that is already open, with one
exception: a connection through a tunnel whose worker the change restarts.
A connection keeps the route it was given when it was opened, even if the
rules now say otherwise, and a listener that is closed, disabled or reopened
leaves the connections it accepted alone.

On shutdown (SIGTERM or SIGINT) the supervisor:

1. closes the listeners and the admin server, so nothing new comes in;
2. waits up to `drainTimeout` for open connections to finish, with the
   tunnel workers still running;
3. closes whatever is left and stops the workers.

It exits as soon as the last connection is gone; the timeout is only the
upper bound. The container's stop grace period must be longer than
`drainTimeout`, or Docker kills the process mid-drain.

## 8. Health monitoring

Each WireGuard connection has a configurable probe, run by its worker:

| `type`      | Check                                                        |
|-------------|--------------------------------------------------------------|
| `dns`       | DNS query to the tunnel's first `dns` server; any answer counts (default when `dns` is set) |
| `tcp`       | TCP connect to `target` (`host:port`) through the tunnel     |
| `icmp`      | Ping `target` (address or hostname) through the tunnel, e.g. the peer's inner gateway |
| `handshake` | Passive: the last handshake must be younger than three minutes (default without `dns`) |

- Fields: `interval` (seconds, default 15), `timeout` (seconds, default 5),
  `failures` (consecutive failures before the tunnel is down, default 3) and
  `target` for `tcp` and `icmp`.
- With keepalive disabled a `handshake` probe has nothing to judge, because
  WireGuard then handshakes only on traffic; such a tunnel counts as up.

Tunnel states:

| State        | Meaning                                                    | Routing            |
|--------------|------------------------------------------------------------|--------------------|
| `starting`   | Running, no probe has succeeded yet                        | not used           |
| `up`         | The last probe succeeded                                   | used               |
| `degraded`   | Probes are failing, fewer than `failures` in a row         | used as last resort |
| `down`       | `failures` probes failed in a row                          | not used           |
| `restarting` | The worker is not running and waits for its backoff        | not used           |

- A tunnel that has never passed a probe is probed every second and is
  declared down after `interval` × `failures` seconds.
- A tunnel declared down is restarted. So is a worker that exits or sends no
  heartbeat for ten seconds. Restarts back off exponentially from one second
  to one minute; the delay starts over once a tunnel has been up.
- A rule's egress list is searched for the first `up` entry, then for the
  first `degraded` one. If there is neither, the connection fails closed.

Upstream proxies of both kinds are checked every 15 seconds by the
supervisor: a TCP connection and, for an `https` upstream, the TLS
handshake. No request is sent through them. An upstream whose last check
failed is skipped like a down tunnel; one that has not been checked yet is
used.

## 9. Deployment

Released images are on Docker Hub as `timorinne/tr-proxy:<version>` and
`:latest`, for `linux/amd64` and `linux/arm64`. A release build carries its
version: `tr-proxy version` prints it, it is logged at start-up, and it is
in the status as `version`. A build not made by the release script reports
`dev`. Releases are cut with `scripts/publish.sh`; see the README.

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
needs Docker only. It runs as uid 65532 with all capabilities dropped, on a
read-only root filesystem (it writes only to the config volume and `RUN_DIR`), and
carries its own health check (`/tr-proxy healthcheck`, which asks
`/healthz`). On Linux hosts the config directory must be writable for that
uid; a named volume is, because the image's `/config` belongs to that
uid. The same goes for `RUN_DIR`: a tmpfs mounted there needs
`uid=65532,gid=65532,mode=0700`, as in the compose example, and the
supervisor refuses to start if it cannot write there.

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
- With `direct` as an egress, proxy clients can reach whatever the container
  can, except loopback and link-local addresses and the container's own
  addresses (5.6). That includes the rest of the Docker network and private
  networks; use `block` rules where that is not wanted.
- A destination must be an IP address without a zone or a hostname of
  letters, digits, hyphens and underscores whose last label is not all
  digits. Anything else is refused before routing (HTTP 400, SOCKS5 reply 8),
  so that a client cannot put CR, LF or other bytes into the `CONNECT` line
  or SOCKS5 request sent to an upstream, into the logs, or past the rules.
- No secret is written to the logs, the event log or the status: not keys,
  not passwords, not tokens, and not the passwords that failed logins tried.
  A rejected proxy login is logged with the username and client address.

## 11. Backlog (not in v1)

- SOCKS5 UDP ASSOCIATE
- IPv6 (inside tunnels and on listeners)
- Reaching an upstream proxy through a tunnel
- Other VPN types as egress kinds
- TLS on the admin port
- Hashed listener passwords
- SNI/Host sniffing for clients that send bare IP addresses
