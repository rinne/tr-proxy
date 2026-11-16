# tr-proxy

Containerized SOCKS5/HTTP proxy that routes by hostname or IP through multiple userspace WireGuard tunnels, upstream proxies or direct, with health monitoring and a web UI.

`tr-proxy` is one unprivileged container. WireGuard runs entirely in userspace, one process per tunnel, so there is no TUN device, no kernel module, no `NET_ADMIN` and no WireGuard config file to write. Everything is set up in a web UI or over its HTTP API and kept in one JSON file.

## Features

- SOCKS5 and HTTP proxy listeners, as many as you like, each optionally with its own users.
- Any number of **WireGuard tunnels**, each in its own process, each with its own DNS.
- Routing **by destination hostname or IP address**: exact names, `*.suffix`, addresses, networks and ranges.
- Routes: a tunnel, an upstream HTTP proxy, direct, or block. A rule can name **several routes for failover** and fails closed when none is healthy.
- Rules can be limited to some listeners or excluded from some; a listener can have its own default route.
- **Health monitoring**: each tunnel is probed (DNS, TCP, ping or handshake age) and restarted when it stops working.
- **Web UI** with live status: tunnels, handshakes, traffic, every open connection and the route it took, recent events.
- **HTTP API** for everything the UI does, with secrets never returned.
- Config changes apply live and restart only what they touch. Open connections are not interrupted.
- Runs as a non-root user on a read-only root filesystem with all capabilities dropped.
- Optional TOTP for the admin login.

## Image Tags

| Tag                            | Contents                                              |
|---|---|
| `timorinne/tr-proxy:<version>` | One release. Pin this for reproducible deployments.   |
| `timorinne/tr-proxy:latest`    | Moving tag that points at the most recent release.    |

Images are built for `linux/amd64` and `linux/arm64`.

## Quick Start

Create `docker-compose.yaml`:

```yaml
services:
  tr-proxy:
    image: timorinne/tr-proxy:latest
    restart: unless-stopped
    environment:
      ADMIN_USERNAME: admin
      ADMIN_PASSWORD: change-me
    ports:
      - "127.0.0.1:8080:8080"            # admin UI and API
      - "127.0.0.1:1080-1099:1080-1099"  # proxy listeners
    volumes:
      - tr_proxy_config:/config
    tmpfs:
      - /run/tr-proxy:uid=65532,gid=65532,mode=0700
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    stop_grace_period: 15s

volumes:
  tr_proxy_config:
```

Set a real `ADMIN_PASSWORD`, then:

```bash
docker compose up -d
```

Open http://127.0.0.1:8080/ and sign in. A first set-up goes like this:

1. **Tunnels**: add a local key (generate one and give its public key to the VPN server, or paste the secret key you already have), then add a WireGuard connection with the peer's public key and endpoint and the tunnel address the peer has assigned to you.
2. **Listeners**: add a SOCKS5 or HTTP listener on a port between 1080 and 1099.
3. **Rules**: say which destinations go where, and pick the default route for everything else. "Try a destination" shows what a hostname would do.

Then point a client at the listener:

```bash
curl -x socks5h://127.0.0.1:1080 https://example.com/
curl -x http://127.0.0.1:1081 https://example.com/
```

Use `socks5h`, not `socks5`, with curl: it makes the proxy resolve the name, which is what hostname rules and tunnel DNS need. SSH works through either kind of listener:

```
Host inside.example.com
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

The same without compose, for a quick look (no hardening, config lost with the container):

```bash
docker run --rm -p 127.0.0.1:8080:8080 -p 127.0.0.1:1080-1099:1080-1099 \
  -e ADMIN_USERNAME=admin -e ADMIN_PASSWORD=change-me timorinne/tr-proxy:latest
```

## How Routing Works

- Rules are tried in order and the first match decides. A rule matches hostnames (`host.example.com`, `*.example.com`) or addresses (`1.2.3.4`, `1.2.3.0/24`, `1.2.3.4-1.2.3.7`). A hostname is only compared with hostname matchers and an address only with address matchers, so clients should send names.
- A rule's route can be a list. The first healthy entry is used. If none is healthy the connection is refused; it never falls back to a direct connection unless `direct` is in the list.
- A rule can be limited to some listeners or excluded from some, and a listener can have its own default route.
- A hostname is resolved where the connection leaves: by the tunnel's DNS servers, by the upstream proxy, or by the container for `direct`.

## Configuration

The config is one JSON file, `/config/config.json`, written by the admin UI and API. You can also edit it by hand or provision it before the first start; it is read at start-up. Secrets (WireGuard keys, passwords) are stored there in clear text, so protect the volume. The API never returns them.

The full schema, with every field, is in [SPEC.md](https://github.com/rinne/tr-proxy/blob/main/SPEC.md), section 5. A small example:

```json
{
  "version": 1,
  "keys": [{ "name": "office-key", "secretKey": "..." }],
  "wireguard": [{
    "name": "Office",
    "localKey": "office-key",
    "addresses": ["10.8.0.5/32"],
    "peer": { "publicKey": "...", "endpoint": "vpn.example.com:51820" },
    "dns": ["10.8.0.1"]
  }],
  "upstreams": [],
  "listeners": [
    { "name": "main-socks", "type": "socks5", "port": 1080 },
    { "name": "main-http", "type": "http", "port": 1081,
      "auth": { "users": [{ "username": "alice", "password": "..." }] } }
  ],
  "rules": [
    { "name": "corp", "match": ["*.corp.example.com", "10.20.0.0/16"], "via": ["Office", "direct"] },
    { "name": "ads", "match": ["ads.example.net"], "via": "block" }
  ],
  "default": "direct"
}
```

Settings that come from the environment:

| Variable            | Meaning                                         |
|---------------------|-------------------------------------------------|
| `ADMIN_USERNAME`    | required                                        |
| `ADMIN_PASSWORD`    | required                                        |
| `ADMIN_TOTP_SECRET` | optional, base32: sign-in then also needs a code from an authenticator app |
| `ADMIN_PORT`        | admin UI and API, default 8080                  |
| `PROXY_PORT_RANGE`  | ports listeners may use, default `1080-1099`    |

Docker publishes ports when the container starts, so the compose file publishes the whole proxy port range and listeners must stay inside it. To use other ports, change `PROXY_PORT_RANGE` and the published range together.

Limits, set under `limits` in the config (in the UI: Config as JSON):

| Field              | Default | Meaning                                    |
|--------------------|---------|--------------------------------------------|
| `maxConnections`   | 1024    | Client connections per listener; more are closed at once |
| `idleTimeout`      | 3600    | Seconds without a byte in either direction before a connection is closed; 0 means never |
| `drainTimeout`     | 5       | Seconds that a stop waits for open connections |
| `allowLocalDirect` | false   | Let the direct route reach loopback and link-local addresses |

## HTTP API

Everything the UI does goes through a JSON API under `/api` on the admin port: sign in with `POST /api/login`, read and replace the whole config with `GET` and `PUT /api/config`, or work on one entry at a time under `/api/keys`, `/api/wireguard`, `/api/upstreams`, `/api/listeners` and `/api/rules`. `GET /api/status` is the live status and `POST /api/test-route` says how a destination would be routed. Every change is validated as a whole, saved, and applied to the running proxy. The reference is [SPEC.md](https://github.com/rinne/tr-proxy/blob/main/SPEC.md), section 6.

```bash
curl -c jar -d '{"username":"admin","password":"change-me"}' http://127.0.0.1:8080/api/login
curl -b jar http://127.0.0.1:8080/api/status
```

## Running In Production

The quick start publishes everything on `127.0.0.1`. To offer the proxy to other machines:

- Publish the proxy ports on the interface you want, and give every such listener users. A listener without users serves anyone who can reach it.
- Keep the admin port on localhost, or put a reverse proxy with TLS in front of it. It speaks plain HTTP. Behind such a proxy, pass `X-Forwarded-Proto: https` so that the session cookie is marked secure.
- Set `ADMIN_TOTP_SECRET`.
- Pin a version tag instead of `latest`.
- Back up the `/config` volume. It holds the whole configuration, keys included.
- The health check for a load balancer or orchestrator is `GET /healthz` on the admin port; it needs no login. The image has a Docker health check built in.
- Outgoing, the container needs UDP to the WireGuard peers and TCP to wherever `direct` and upstream proxies go. Incoming, only the ports you publish.

If you mount a host directory on `/config` instead of a named volume, it must be writable for uid 65532, the user the container runs as:

```bash
mkdir -p config && sudo chown 65532:65532 config
```

The direct route refuses loopback and link-local destinations by default. That keeps proxy clients away from the container's own admin API and, on a cloud host, from the metadata service at 169.254.169.254. Private networks (10.0.0.0/8 and the like) are not refused: block them with rules if clients should not reach them.

### Watching it

The Status page shows each tunnel's state, last handshake, health probe and traffic, the upstream proxies, the listeners, every open connection with the rule and route it took, and a log of recent events. The same data is at `GET /api/status`.

A tunnel is `up` when its last probe succeeded, `degraded` while probes are failing but below the threshold, and `down` after that, at which point it is restarted. The probe is a DNS query to the tunnel's DNS server by default; it can also be a TCP connect or a ping to a target of your choice, or just the age of the last handshake.

Logs go to the container's output:

```bash
docker compose logs -f
```

### Stopping

On stop, listeners close at once and open connections get `drainTimeout` seconds to finish. Keep the container's stop grace period above that. Admin sessions do not survive a restart; the config does.

## Upgrading

Pull the new image and recreate the container:

```bash
docker compose pull
docker compose up -d
```

The config file carries a schema version and is read by newer releases as it is. Release notes are in [CHANGELOG.md](https://github.com/rinne/tr-proxy/blob/main/CHANGELOG.md).

## Versioning And Compatibility

This project follows [Semantic Versioning](https://semver.org/). While the version is below 1.0.0 a minor release may change behaviour or the config format; the changelog says so when one does. Patch releases carry fixes only.

## Build

Nothing but Docker is needed; the Go toolchain runs in a container too.

```bash
docker build --pull -t tr-proxy:local .
```

To run from the source tree, with the config in `dc/volumes/config`:

```bash
cd dc
cp docker-compose.yaml.EXAMPLE docker-compose.yaml
docker compose up -d --build
```

On Linux make that directory writable for the container first, as described under [Running In Production](#running-in-production).

## Test

```bash
make check
make test
tests/smoke.sh
```

`make test` runs the Go tests in a container. They bring up real WireGuard tunnels against a peer built into the test code, so they need no VPN server, and they cover routing, failover, health monitoring, the admin API and shutdown. `tests/smoke.sh` builds the image and drives it from outside the way a deployment would: read-only root filesystem, no capabilities, a named volume, then the admin API, both listener types, rules, listener login, a tunnel worker, a restart and a clean stop. `scripts/publish.sh` runs all three before publishing.

## Publish To Docker Hub

Releases are cut by hand with `scripts/publish.sh`. The script runs the tests, builds one multi-arch image (`linux/amd64`, `linux/arm64`) and publishes from one git revision:

| Tag          | When                 |
|---|---|
| `:<version>` | always               |
| `:latest`    | unless `--no-latest` |

```bash
docker login
scripts/publish.sh 0.1.0
```

In order:

1. Guards: on `main`, clean working tree, a `CHANGELOG.md` entry for the version, no git tag and no registry tag of that version yet.
2. Pull the current base images, then `make check`, `make test` and `tests/smoke.sh`.
3. Build and push `:<version>`.
4. Promote `:latest` with `buildx imagetools create` (manifest only, no rebuild).
5. `git tag v<version>` and push the tag.

The build passes `--pull`, so the published image always starts from the registry's current base images. `:latest` only moves once the versioned tag has been pushed.

Useful flags:

- `--dry-run` — run the guards and the tests and build for all platforms, but push nothing and create no git tag.
- `--no-latest` — push only the versioned tag (for back-port releases that must not move `latest`).
- `--force` — skip the clean-tree, `main`-branch, changelog and upstream-tag-presence guards (use sparingly).
- `--retag-latest-only` — re-promote `:latest` from the existing versioned tag without rebuilding (recovery path when step 4 failed). Requires `--force`.

Useful environment overrides:

- `IMAGE` — Docker Hub image name (default `timorinne/tr-proxy`).
- `PLATFORMS` — buildx target platforms (default `linux/amd64,linux/arm64`).

The CI workflow at `.github/workflows/ci.yml` runs the checks, the Go tests and the smoke test on pushes and pull requests; it does not publish.

## Repository Layout

```text
.github/workflows/     CI workflow
cmd/tr-proxy/          the binary's entry point
internal/              the Go packages (supervisor, worker, proxy, admin API and UI, ...)
dc/                    example docker-compose.yaml for running from source
scripts/publish.sh     manual Docker Hub release helper
tests/smoke.sh         end-to-end Docker smoke test of the image
Dockerfile             multi-stage, multi-arch build
SPEC.md                the specification
CHANGELOG.md           release notes
```

## Not There Yet

- SOCKS5 UDP
- IPv6
- SOCKS5 upstream proxies, and reaching an upstream proxy through a tunnel
- TLS on the admin port itself

## License

Copyright © 2026 Timo J. Rinne <tri@iki.fi>. All rights reserved.

tr-proxy is released under the MIT License. The full text is in [LICENSE](https://github.com/rinne/tr-proxy/blob/main/LICENSE), and the same text is kept as [MIT-RINNE](https://github.com/rinne/tr-proxy/blob/main/MIT-RINNE).

It includes and builds on other people's work, under their own licenses:

| Component                                   | License      |
|---------------------------------------------|--------------|
| Alpine.js (vendored in `internal/admin/ui`) | MIT, see `internal/admin/ui/alpine.LICENSE.md` |
| wireguard-go (`golang.zx2c4.com/wireguard`) | MIT          |
| gVisor (`gvisor.dev/gvisor`)                | Apache 2.0   |
| `github.com/coder/websocket`                | ISC          |
| `golang.org/x/net`, `crypto`, `sys`, `time` | BSD 3-Clause |
| `github.com/google/btree`                   | Apache 2.0   |

WireGuard is a registered trademark of Jason A. Donenfeld. This project is not affiliated with or endorsed by the WireGuard project.
