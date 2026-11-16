// Package egress holds the ways a proxied connection can leave: directly, or
// through a WireGuard worker.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
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

// ErrLocalDestination is returned by Direct for a destination on loopback
// or a link-local network.
var ErrLocalDestination = errors.New("destination is a local address, which the direct route does not reach")

// Direct connects from the container itself, resolving with its resolver.
//
// Unless AllowLocal is set it refuses loopback, link-local, multicast and
// unspecified addresses, so that proxy clients cannot reach the container's
// own services (the admin API, other listeners) or a cloud host's metadata
// service at 169.254.169.254. The check is made on the address actually
// connected to, after name resolution.
type Direct struct {
	AllowLocal bool
}

func (d Direct) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	nd := net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}
	if !d.AllowLocal {
		nd.Control = refuseLocal
	}
	return nd.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

func refuseLocal(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("unexpected dial address %q", address)
	}
	ip := ap.Addr().Unmap().WithZone("")
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return ErrLocalDestination
	}
	return nil
}

// Worker connects through a WireGuard worker's tunnel; the hostname is
// resolved inside the tunnel.
type Worker struct {
	Socket string
}

func (w Worker) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	return ipc.Dial(ctx, w.Socket, host, port)
}
