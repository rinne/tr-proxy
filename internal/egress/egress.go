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
	"sync"
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

// ErrLocalDestination is returned by Direct for a destination on loopback,
// a link-local network, or an address of the container itself.
var ErrLocalDestination = errors.New("destination is a local address, which the direct route does not reach")

// ErrRuledAddress is returned by Direct when its Check refuses the address
// a hostname resolved to.
var ErrRuledAddress = errors.New("destination resolves to an address that the rules do not send direct")

// Direct connects from the container itself, resolving with its resolver.
//
// Unless AllowLocal is set it refuses loopback, link-local, multicast and
// unspecified addresses and the addresses of the container's own network
// interfaces, so that proxy clients cannot reach the container's own
// services (the admin API, other listeners), which listen on every
// interface, or a cloud host's metadata service at 169.254.169.254. The
// check is made on the address actually connected to, after name
// resolution.
//
// Check, if set, is asked about every address connected to, after name
// resolution, and refuses it by returning an error (which should wrap
// ErrRuledAddress).
type Direct struct {
	AllowLocal bool
	Check      func(netip.Addr) error
}

func (d Direct) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	nd := net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}
	if !d.AllowLocal || d.Check != nil {
		nd.Control = d.control
	}
	return nd.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

func (d Direct) control(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("unexpected dial address %q", address)
	}
	ip := ap.Addr().Unmap().WithZone("")
	if !d.AllowLocal && (ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ownAddresses.has(ip)) {
		return ErrLocalDestination
	}
	if d.Check != nil {
		return d.Check(ip)
	}
	return nil
}

// ownAddresses are the addresses of the container's network interfaces,
// read again after a while, since interfaces can come and go. If they
// cannot be read, the last known ones are used.
var ownAddresses = &addrCache{ttl: 10 * time.Second, read: interfaceAddrs}

type addrCache struct {
	ttl   time.Duration
	read  func() ([]netip.Addr, error)
	mu    sync.Mutex
	at    time.Time
	addrs map[netip.Addr]bool
}

func (c *addrCache) has(ip netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.addrs == nil || time.Since(c.at) >= c.ttl {
		if list, err := c.read(); err == nil {
			m := make(map[netip.Addr]bool, len(list))
			for _, a := range list {
				m[a.Unmap().WithZone("")] = true
			}
			c.addrs = m
		}
		c.at = time.Now()
	}
	return c.addrs[ip]
}

func interfaceAddrs() ([]netip.Addr, error) {
	list, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(list))
	for _, a := range list {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out, nil
}

// Worker connects through a WireGuard worker's tunnel; the hostname is
// resolved inside the tunnel.
type Worker struct {
	Socket string
}

func (w Worker) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	return ipc.Dial(ctx, w.Socket, host, port)
}
