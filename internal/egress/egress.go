// Package egress holds the ways a proxied connection can leave: directly, or
// through a WireGuard worker.
package egress

import (
	"context"
	"net"
	"strconv"
	"time"

	"tr-proxy/internal/ipc"
)

// DialTimeout bounds one outgoing connection attempt.
const DialTimeout = ipc.DialTimeout

// Dialer opens a connection to host:port. host is a hostname or an IP
// address; where the hostname gets resolved depends on the egress.
type Dialer interface {
	Dial(ctx context.Context, host string, port int) (net.Conn, error)
}

// Direct connects from the container itself, resolving with its resolver.
type Direct struct{}

func (Direct) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// Worker connects through a WireGuard worker's tunnel; the hostname is
// resolved inside the tunnel.
type Worker struct {
	Socket string
}

func (w Worker) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	return ipc.Dial(ctx, w.Socket, host, port)
}
