#!/bin/bash
# End-to-end smoke test of the image.
#
# Builds the image, runs it the way the compose example does (read-only root
# filesystem, no capabilities, tmpfs for the worker sockets, a named volume
# for the config) and drives it from outside: admin API, both listener
# types, rules, listener login, a tunnel worker, persistence over a restart
# and a clean stop.
#
# The Go tests (make test) cover the logic, WireGuard tunnels included. This
# covers what they cannot: the image itself and how it is run.
#
# Needs docker with compose, and curl. Ports can be moved with ADMIN_PORT,
# SOCKS_PORT, HTTP_PORT and AUTH_PORT.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.tmp-smoke.XXXXXX")"
COMPOSE_FILE="$TMP_DIR/docker-compose.yaml"
IMAGE="${IMAGE:-tr-proxy:smoke}"
ADMIN_PORT="${ADMIN_PORT:-18080}"
SOCKS_PORT="${SOCKS_PORT:-18090}"
HTTP_PORT="${HTTP_PORT:-18091}"
AUTH_PORT="${AUTH_PORT:-18092}"
ADMIN="http://127.0.0.1:$ADMIN_PORT"
JAR="$TMP_DIR/cookies"
BODY="$TMP_DIR/body"
ADMIN_PASSWORD="smoke-admin-password"
USER_PASSWORD="smoke-listener-password"

if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose -p "trproxysmoke$$" -f "$COMPOSE_FILE")
else
    COMPOSE=(docker compose -p "trproxysmoke$$" -f "$COMPOSE_FILE")
fi

cleanup() {
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    echo "--- last answer:" >&2
    [ -f "$BODY" ] && head -c 2000 "$BODY" >&2
    echo >&2
    echo "--- container log:" >&2
    "${COMPOSE[@]}" logs --tail 40 proxy >&2 || true
    exit 1
}

pass() { echo "ok: $*"; }

# api METHOD PATH [JSON] -> prints the status code, leaves the body in $BODY
api() {
    if [ $# -ge 3 ]; then
        curl -sS -m 20 -b "$JAR" -c "$JAR" -X "$1" -H 'Content-Type: application/json' \
            -d "$3" -o "$BODY" -w '%{http_code}' "$ADMIN$2" || true
    else
        curl -sS -m 20 -b "$JAR" -c "$JAR" -X "$1" -o "$BODY" -w '%{http_code}' "$ADMIN$2" || true
    fi
}

# expect CODE METHOD PATH [JSON]
expect() {
    local want="$1"; shift
    local got
    got="$(api "$@")"
    [ "$got" = "$want" ] || fail "$1 $2: status $got, want $want"
}

body_has() { grep -q -- "$1" "$BODY" || fail "$2"; }
body_lacks() { if grep -q -- "$1" "$BODY"; then fail "$2"; fi; }

# via PROXY-URL URL [curl options] -> prints "<status code> <body>"
via() {
    local proxy="$1" url="$2"; shift 2
    curl -sS -m 20 -x "$proxy" "$@" -o "$TMP_DIR/proxied" -w '%{http_code}' "$url" 2>/dev/null || true
    printf ' '
    [ -f "$TMP_DIR/proxied" ] && head -c 200 "$TMP_DIR/proxied" | tr -d '\n'
    rm -f "$TMP_DIR/proxied"
}

wait_for() { # DESCRIPTION COMMAND...
    local what="$1"; shift
    local i
    for i in $(seq 1 40); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    fail "timed out waiting for $what"
}

socks_ok() { [ "$(via "socks5h://127.0.0.1:$SOCKS_PORT" http://backend:8080/healthz)" = "200 ok" ]; }
web_ok() { [ "$(via "http://127.0.0.1:$HTTP_PORT" http://backend:8080/healthz)" = "200 ok" ]; }
healthy() { [ "$(curl -s -m 3 -o /dev/null -w '%{http_code}' "$ADMIN/healthz")" = "200" ]; }
login() { expect 200 POST /api/login "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}"; }

echo "==> building $IMAGE"
docker build -q --build-arg IMAGE_VERSION=smoke-test \
    --build-arg IMAGE_REVISION=smoke-revision -t "$IMAGE" "$ROOT_DIR" >/dev/null

cat > "$COMPOSE_FILE" <<YAML
services:
  proxy:
    image: "$IMAGE"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    stop_grace_period: 15s
    environment:
      ADMIN_USERNAME: admin
      ADMIN_PASSWORD: "$ADMIN_PASSWORD"
    ports:
      - "127.0.0.1:$ADMIN_PORT:8080"
      - "127.0.0.1:$SOCKS_PORT:1080"
      - "127.0.0.1:$HTTP_PORT:1081"
      - "127.0.0.1:$AUTH_PORT:1082"
    volumes:
      - config:/config
    tmpfs:
      - /run/tr-proxy:uid=65532,gid=65532,mode=0700

  # Something to proxy to: a second instance, whose /healthz answers "ok".
  backend:
    image: "$IMAGE"
    environment:
      ADMIN_USERNAME: backend
      ADMIN_PASSWORD: backend-password

volumes:
  config:
YAML

echo "==> image"
[ "$(docker run --rm "$IMAGE" version)" = "smoke-test" ] || fail "the image does not report its version"
[ "$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$IMAGE")" = "smoke-test" ] \
    || fail "the version label is missing"
[ "$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")" = "smoke-revision" ] \
    || fail "the revision label is missing"
case "$(docker inspect -f '{{.Config.User}}' "$IMAGE")" in
    ""|0|root|0:0|root:root) fail "the image runs as root" ;;
esac
if docker run --rm "$IMAGE" >"$BODY" 2>&1; then fail "started without admin credentials"; fi
body_has "ADMIN_USERNAME and ADMIN_PASSWORD must be set" "no clear error without admin credentials"
pass "version, labels, non-root user, refuses to start without credentials"

echo "==> starting"
"${COMPOSE[@]}" up -d >/dev/null 2>&1
wait_for "the admin port" healthy
pass "starts on a read-only root filesystem with an empty named volume"

echo "==> admin API"
expect 401 GET /api/config
expect 200 GET /
body_has "<title>TR Proxy</title>" "the UI page is not served"
expect 401 POST /api/login '{"username":"admin","password":"wrong"}'
login
expect 200 GET /api/status
body_has '"version":"smoke-test"' "the status lacks the version"
pass "UI served, login required, login works"

echo "==> configuration through the API"
expect 201 POST /api/listeners '{"name":"socks","type":"socks5","port":1080}'
expect 201 POST /api/listeners '{"name":"web","type":"http","port":1081}'
expect 201 POST /api/listeners "{\"name\":\"authed\",\"type\":\"http\",\"port\":1082,\"auth\":{\"users\":[{\"username\":\"alice\",\"password\":\"$USER_PASSWORD\"}]}}"
expect 400 POST /api/listeners '{"name":"outside","type":"http","port":9999}'
body_has "outside PROXY_PORT_RANGE" "a port outside the range was not refused with a reason"
expect 201 POST /api/rules '{"name":"blocked","match":["blocked.test","*.blocked.test"],"via":"block"}'
pass "listeners and a rule added; an invalid entry refused"

echo "==> proxying"
[ "$(via "socks5h://127.0.0.1:$SOCKS_PORT" http://backend:8080/healthz)" = "200 ok" ] || fail "SOCKS5 listener"
[ "$(via "http://127.0.0.1:$HTTP_PORT" http://backend:8080/healthz)" = "200 ok" ] || fail "HTTP listener, plain request"
[ "$(via "http://127.0.0.1:$HTTP_PORT" http://backend:8080/healthz -p)" = "200 ok" ] || fail "HTTP listener, CONNECT"
pass "SOCKS5, HTTP forwarding and CONNECT reach the backend"

case "$(via "http://127.0.0.1:$HTTP_PORT" http://x.blocked.test/)" in 403*) ;; *) fail "the block rule did not answer 403" ;; esac
case "$(via "http://127.0.0.1:$HTTP_PORT" http://127.0.0.1:8080/healthz)" in 403*) ;; *) fail "the proxy's own loopback was reachable" ;; esac
case "$(via "socks5h://127.0.0.1:$SOCKS_PORT" http://127.0.0.1:8080/healthz)" in "200 ok") fail "the proxy's own loopback was reachable over SOCKS5" ;; esac
pass "block rule and loopback refusal"

case "$(via "http://127.0.0.1:$AUTH_PORT" http://backend:8080/healthz)" in 407*) ;; *) fail "a listener with users served a client without credentials" ;; esac
case "$(via "http://alice:wrong@127.0.0.1:$AUTH_PORT" http://backend:8080/healthz)" in 407*) ;; *) fail "a wrong listener password was accepted" ;; esac
[ "$(via "http://alice:$USER_PASSWORD@127.0.0.1:$AUTH_PORT" http://backend:8080/healthz)" = "200 ok" ] || fail "listener login"
pass "listener login"

expect 200 POST /api/listeners/web/disable
case "$(via "http://127.0.0.1:$HTTP_PORT" http://backend:8080/healthz)" in "200 ok") fail "a disabled listener still serves" ;; esac
expect 200 POST /api/listeners/web/enable
wait_for "the listener to come back" web_ok
pass "disable and enable a listener"

echo "==> tunnel worker"
expect 201 POST /api/keys/generate '{"name":"smoke-key"}'
PUBLIC_KEY="$(sed -n 's/.*"publicKey":"\([^"]*\)".*/\1/p' "$BODY")"
[ -n "$PUBLIC_KEY" ] || fail "no public key in the answer to key generation"
body_lacks '"secretKey":"[A-Za-z0-9+/]\{43\}="' "the generated secret key was returned"
# The peer does not exist, so the tunnel never comes up; what matters here is
# that the worker process starts and stays, which needs the socket directory
# and the endpoint lookup to work inside the container.
expect 201 POST /api/wireguard "{\"name\":\"Tunnel\",\"localKey\":\"smoke-key\",\"addresses\":[\"10.8.0.2/32\"],\"peer\":{\"publicKey\":\"$PUBLIC_KEY\",\"endpoint\":\"backend:51820\"}}"
tunnel_running() {
    api GET /api/status >/dev/null
    grep -q '"name":"Tunnel","state":"starting","pid":[0-9]' "$BODY"
}
wait_for "the tunnel worker" tunnel_running
sleep 3
tunnel_running || fail "the tunnel worker did not stay up"
body_has '"restarts":0' "the tunnel worker was restarted"
"${COMPOSE[@]}" logs proxy 2>&1 | grep -q 'msg="tunnel up".*connection=Tunnel' || fail "the worker did not log that its tunnel is up"
pass "a tunnel worker starts and stays up"

echo "==> secrets"
expect 200 GET /api/config
body_lacks "$USER_PASSWORD" "the listener password is in the config answer"
body_has 'u003credacted' "secrets are not shown as redacted"
if "${COMPOSE[@]}" logs proxy 2>&1 | grep -q -e "$USER_PASSWORD" -e "$ADMIN_PASSWORD"; then
    fail "a password is in the container log"
fi
pass "secrets are redacted in the API and absent from the log"

echo "==> restart"
"${COMPOSE[@]}" restart proxy >/dev/null 2>&1
wait_for "the admin port after the restart" healthy
expect 401 GET /api/config
login
expect 200 GET /api/config
body_has '"name":"socks"' "the config did not survive the restart"
body_has '"name":"Tunnel"' "the connection did not survive the restart"
wait_for "the SOCKS5 listener after the restart" socks_ok
[ "$(via "http://alice:$USER_PASSWORD@127.0.0.1:$AUTH_PORT" http://backend:8080/healthz)" = "200 ok" ] || fail "listener login after the restart"
pass "config, secrets included, survives a restart; sessions do not"

echo "==> health and stop"
container="$("${COMPOSE[@]}" ps -q proxy)"
container_healthy() { [ "$(docker inspect -f '{{.State.Health.Status}}' "$container")" = "healthy" ]; }
wait_for "the container health check" container_healthy
"${COMPOSE[@]}" stop proxy >/dev/null 2>&1
[ "$(docker inspect -f '{{.State.ExitCode}}' "$container")" = "0" ] || fail "the container did not exit cleanly"
pass "health check passes; stops cleanly"

echo "==> smoke test passed"
