# TR Proxy

A proxy in a container. It offers SOCKS5 and HTTP proxy ports and sends each
connection, by destination hostname or IP address, down one of several
routes:

- a WireGuard tunnel (as many as you configure, each in its own process),
- another HTTP proxy,
- directly out of the container,
- or nowhere (block).

Tunnels are watched and restarted when they stop working. Everything is
configured in a web UI or over its HTTP API; there are no WireGuard config
files to write. The WireGuard side runs entirely in userspace, so the
container needs no privileges, no TUN device and no kernel module.

`SPEC.md` is the full specification. This file is how to run it.

## Quick start

You need Docker with Compose. Nothing else: the image is built in a
container too.

```bash
cd dc
cp docker-compose.yaml.EXAMPLE docker-compose.yaml
```

Edit `docker-compose.yaml` and set `ADMIN_PASSWORD`. Then:

```bash
docker compose up -d --build
```

Open http://127.0.0.1:8080/ and sign in. A first set-up goes like this:

1. **Tunnels**: add a local key (generate one and give its public key to the
   VPN server, or paste the secret key you already have), then add a
   WireGuard connection with the peer's public key and endpoint and the
   tunnel address the peer has assigned to you.
2. **Listeners**: add a SOCKS5 or HTTP listener on a port between 1080 and
   1099.
3. **Rules**: say which destinations go where, and pick the default route
   for everything else. "Try a destination" shows what a hostname would do.

Then point a client at the listener:

```bash
curl -x socks5h://127.0.0.1:1080 https://example.com/
curl -x http://127.0.0.1:1081 https://example.com/
```

Use `socks5h`, not `socks5`, with curl: it makes the proxy resolve the name,
which is what hostname rules and tunnel DNS need. SSH works through either
kind of listener:

```
Host inside.example.com
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

## How routing works

- Rules are tried in order and the first match decides. A rule matches
  hostnames (`host.example.com`, `*.example.com`) or addresses (`1.2.3.4`,
  `1.2.3.0/24`, `1.2.3.4-1.2.3.7`). A hostname is only compared with
  hostname matchers and an address only with address matchers, so clients
  should send names.
- A rule's route can be a list. The first healthy entry is used. If none is
  healthy the connection is refused; it never falls back to a direct
  connection unless `direct` is in the list.
- A rule can be limited to some listeners or excluded from some, and a
  listener can have its own default route.
- A hostname is resolved where the connection leaves: by the tunnel's DNS
  servers, by the upstream proxy, or by the container for `direct`.

## Configuration

The config is one JSON file, `dc/volumes/config/config.json`, written by the
admin UI and API. You can also edit it by hand or provision it before the
first start; it is read at start-up. Secrets (WireGuard keys, passwords) are
stored there in clear text, so protect the directory. The API never returns
them.

Settings that come from the environment, in the compose file:

| Variable            | Meaning                                         |
|---------------------|-------------------------------------------------|
| `ADMIN_USERNAME`    | required                                        |
| `ADMIN_PASSWORD`    | required                                        |
| `ADMIN_TOTP_SECRET` | optional, base32: sign-in then also needs a code from an authenticator app |
| `ADMIN_PORT`        | admin UI and API, default 8080                  |
| `PROXY_PORT_RANGE`  | ports listeners may use, default `1080-1099`    |

Docker publishes ports when the container starts, so the compose file
publishes the whole proxy port range and listeners must stay inside it. To
use other ports, change `PROXY_PORT_RANGE` and the published range together.

Limits, set under `limits` in the config (in the UI: Config as JSON):

| Field              | Default | Meaning                                    |
|--------------------|---------|--------------------------------------------|
| `maxConnections`   | 1024    | Client connections per listener; more are closed at once |
| `idleTimeout`      | 3600    | Seconds without a byte in either direction before a connection is closed; 0 means never |
| `drainTimeout`     | 5       | Seconds that a stop waits for open connections |
| `allowLocalDirect` | false   | Let the direct route reach loopback and link-local addresses |

## Running it on a server

The example publishes everything on `127.0.0.1`. To offer the proxy to other
machines:

- Publish the proxy ports on the interface you want, and give every such
  listener users. A listener without users serves anyone who can reach it.
- Keep the admin port on localhost, or put a reverse proxy with TLS in front
  of it. It speaks plain HTTP. Behind such a proxy, pass
  `X-Forwarded-Proto: https` so that the session cookie is marked secure.
- Set `ADMIN_TOTP_SECRET`.
- On Linux the container runs as uid 65532 and must be able to write the
  config directory:

  ```bash
  mkdir -p volumes/config && sudo chown 65532:65532 volumes/config
  ```

- The load balancer or orchestrator health check is `GET /healthz` on the
  admin port; it needs no login. The image has a Docker health check built
  in.
- Outgoing, the container needs UDP to the WireGuard peers and TCP to
  wherever `direct` and upstream proxies go. Incoming, only the ports you
  publish.

The direct route refuses loopback and link-local destinations by default.
That keeps proxy clients away from the container's own admin API and, on a
cloud host, from the metadata service at 169.254.169.254. Private networks
(10.0.0.0/8 and the like) are not refused: block them with rules if clients
should not reach them.

## Watching it

The Status page shows each tunnel's state, last handshake, health probe and
traffic, the upstream proxies, the listeners, every open connection with the
rule and route it took, and a log of recent events. The same data is at
`GET /api/status`.

A tunnel is `up` when its last probe succeeded, `degraded` while probes are
failing but below the threshold, and `down` after that, at which point it is
restarted. The probe is a DNS query to the tunnel's DNS server by default;
it can also be a TCP connect or a ping to a target of your choice, or just
the age of the last handshake.

Logs go to the container's output:

```bash
docker compose logs -f
```

## Stopping and updating

```bash
docker compose down
docker compose up -d --build
```

On stop, listeners close at once and open connections get `drainTimeout`
seconds to finish. Admin sessions do not survive a restart; the config does.

## Development

All Go tooling runs in containers:

```bash
make test
make vet
make fmt
make build
```

The tests bring up real WireGuard tunnels against a peer built into the test
code, so they need no VPN server.

## Not there yet

- SOCKS5 UDP
- IPv6
- SOCKS5 upstream proxies, and reaching an upstream proxy through a tunnel
- TLS on the admin port itself
