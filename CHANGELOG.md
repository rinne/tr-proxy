# Changelog

All notable changes to `tr-proxy` are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-11-22

### Security

- **A removed proxy user could keep using an HTTP listener.** When a listener's config changed (a user removed, a password changed, auth turned on), its kept-alive HTTP connections went on serving requests with the old settings. When an HTTP listener is closed or reopened, its idle connections are now closed and active ones after their current request. CONNECT tunnels already open are not interrupted, as before.
- **A login in the URL of an http upstream was accepted and shown.** It was never used, but the admin API returned it unredacted. Such URLs are now refused like for SOCKS5 upstreams; give the login under `auth`. A config file that has one is loaded with the login removed and a warning in the log and the event log.
- Updated `golang.org/x/net`, `x/crypto`, `x/sys`, `x/time` and gVisor. `govulncheck` reported no vulnerability that tr-proxy's code reaches, but 37 in the old module versions; it reports none now.

### Changed

- CI and `scripts/publish.sh` run `govulncheck` (`make vulncheck`).
- SPEC.md: removed a duplicated part of section 6.

## [0.2.1] - 2026-11-22

### Security

- **The admin API was reachable through the proxy.** The direct route refused loopback and link-local destinations, but the admin API and the listeners listen on every interface, so a proxy client could reach them at the container's own network address (for example `172.17.0.2:8080`). The direct route now also refuses the addresses of the container's own interfaces, unless `allowLocalDirect` is set.
- **Destination names are validated.** A SOCKS5 domain name was used as sent, so a client could put CR and LF into the `CONNECT` request sent to an HTTP upstream proxy (adding headers or a second request), into SOCKS5 requests to upstreams, and into the logs, and names such as `127.1` got past IP rules. A destination must now be an IP address without a zone or a valid hostname whose last label is not all digits; anything else is refused before routing with HTTP 400 or SOCKS5 reply 8 (address type not supported).

## [0.2.0] - 2026-11-16

### Added

- **SOCKS5 upstream proxies.** An upstream proxy can now be of type `socks5` (`"url": "socks5://host[:port]"`, default port 1080) as well as `http`. It can log in with a username and password, hands hostnames to the upstream to resolve, is checked for reachability, and can be used in rules and failover lists like any other route. This makes anything with a SOCKS5 port usable as a route, for instance a Tor client in a sidecar container. The UI's upstream form has a type selector.

### Changed

- Upstream validation is stricter: the URL scheme must match the type, the port must be valid, a login must be given under `auth` rather than inside the URL of a SOCKS5 upstream, and a bearer token is refused for SOCKS5. Existing `http` upstreams are unaffected.
- `scripts/publish.sh` accepts a release tag that was created beforehand, provided it names the commit being released, and pushes it after the image.

## [0.1.0] - 2026-11-16

First public release.

### Added

- SOCKS5 listeners (`CONNECT`, with IPv4, IPv6 and domain-name destinations) and HTTP proxy listeners (`CONNECT` tunnels and plain-HTTP forwarding), any number of each, each optionally with its own users.
- WireGuard tunnels in userspace (`wireguard-go` on a gVisor network stack), one process per tunnel, with per-tunnel DNS. No TUN device, kernel module or privileges are needed.
- Upstream HTTP proxies as a route, over plain or TLS connections, with basic or bearer authentication.
- Rule-based routing by destination: exact hostnames, `*.suffix` wildcards, IP addresses, CIDR networks and address ranges; first match wins. Rules can be limited to some listeners or excluded from some, and a listener can have its own default route.
- Failover lists in a rule's route. The first healthy entry is used, and a connection is refused rather than sent direct when none is.
- Health monitoring per tunnel with a configurable probe (DNS query, TCP connect, ping, or handshake age), tunnel states, and automatic restart with backoff. Upstream proxies are checked for reachability.
- Web UI with live status over a WebSocket: tunnels, upstream proxies, listeners, open connections with the rule and route each took, and an event log. Forms for keys, WireGuard connections, upstream proxies, listeners and rules, a route tester, and the whole config as JSON.
- HTTP API for everything the UI does. Secrets are never returned, and a write that sends the redaction placeholder back keeps the stored value.
- Admin login with username and password from the environment, optional TOTP, in-memory sessions, a login rate limit and cross-origin request refusal.
- Live config reload: a change is validated as a whole, saved atomically and applied by restarting only the tunnels and listeners it touches. Open connections are not interrupted.
- Listeners can be disabled without deleting them.
- Limits: connections per listener, an idle timeout, and draining of open connections on shutdown.
- The direct route refuses loopback and link-local destinations unless allowed, which keeps proxy clients from the container's own admin API and from a cloud host's metadata service.
- Image for `linux/amd64` and `linux/arm64` that runs as a non-root user on a read-only root filesystem with all capabilities dropped, with a built-in health check.
