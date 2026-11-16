// Package tunnel runs one userspace WireGuard tunnel: a wireguard-go device
// on top of a gVisor netstack. Nothing here needs a TUN device or
// privileges.
package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"tr-proxy/internal/config"
	"tr-proxy/internal/wgkey"
)

type Tunnel struct {
	dev    *device.Device
	net    *netstack.Net
	hasDNS bool
}

// Stats is a snapshot of the tunnel's peer.
type Stats struct {
	LastHandshake time.Time // zero if there has been none
	Rx, Tx        uint64
}

// Up brings the tunnel up. The endpoint hostname, if any, is resolved here,
// so a restart picks up a changed address.
func Up(ctx context.Context, c config.WireGuard, secretKey string, log *slog.Logger) (*Tunnel, error) {
	var addrs []netip.Addr
	for _, a := range c.Addresses {
		if p, err := netip.ParsePrefix(a); err == nil {
			addrs = append(addrs, p.Addr())
		} else if ip, err := netip.ParseAddr(a); err == nil {
			addrs = append(addrs, ip)
		} else {
			return nil, fmt.Errorf("address %q: not an IP address or CIDR", a)
		}
	}
	var dns []netip.Addr
	for _, d := range c.DNS {
		ip, err := netip.ParseAddr(d)
		if err != nil {
			return nil, fmt.Errorf("dns %q: %w", d, err)
		}
		dns = append(dns, ip)
	}
	mtu := c.MTU
	if mtu == 0 {
		mtu = config.DefaultMTU
	}

	uapi, err := uapiConfig(ctx, c, secretKey)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, fmt.Errorf("create netstack: %w", err)
	}
	// wireguard-go's default logger writes to stdout, which a worker uses
	// for status lines.
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf: func(format string, args ...any) {
			log.Warn("wireguard: " + fmt.Sprintf(format, args...))
		},
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring device up: %w", err)
	}
	return &Tunnel{dev: dev, net: tnet, hasDNS: len(dns) > 0}, nil
}

func uapiConfig(ctx context.Context, c config.WireGuard, secretKey string) (string, error) {
	private, err := wgkey.Hex(secretKey)
	if err != nil {
		return "", fmt.Errorf("secret key: %w", err)
	}
	public, err := wgkey.Hex(c.Peer.PublicKey)
	if err != nil {
		return "", fmt.Errorf("peer public key: %w", err)
	}
	endpoint, err := resolveEndpoint(ctx, c.Peer.Endpoint)
	if err != nil {
		return "", err
	}
	keepalive := config.DefaultKeepalive
	if c.Peer.Keepalive != nil {
		keepalive = *c.Peer.Keepalive
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", private)
	fmt.Fprintf(&b, "public_key=%s\n", public)
	if c.Peer.PresharedKey != "" {
		psk, err := wgkey.Hex(c.Peer.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("preshared key: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	// Everything may go into the tunnel; the rule engine decides what does.
	b.WriteString("allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n")
	return b.String(), nil
}

func resolveEndpoint(ctx context.Context, endpoint string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q: bad port", endpoint)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip, uint16(port)), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve endpoint %q: %w", host, err)
	}
	pick := ips[0]
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			pick = ip
			break
		}
	}
	return netip.AddrPortFrom(pick.Unmap(), uint16(port)), nil
}

// Dial connects to host:port through the tunnel. A hostname is resolved with
// the tunnel's DNS servers.
func (t *Tunnel) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return t.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, uint16(port)))
	}
	if !t.hasDNS {
		return nil, fmt.Errorf("cannot resolve %q: this connection has no dns servers", host)
	}
	return t.net.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// Net exposes the tunnel's network stack, for probes.
func (t *Tunnel) Net() *netstack.Net { return t.net }

// Stats reads the peer's handshake time and byte counters.
func (t *Tunnel) Stats() (Stats, error) {
	var s Stats
	raw, err := t.dev.IpcGet()
	if err != nil {
		return s, err
	}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		n, _ := strconv.ParseUint(v, 10, 64)
		switch k {
		case "last_handshake_time_sec":
			if n > 0 {
				s.LastHandshake = time.Unix(int64(n), 0)
			}
		case "rx_bytes":
			s.Rx = n
		case "tx_bytes":
			s.Tx = n
		}
	}
	return s, nil
}

func (t *Tunnel) Close() { t.dev.Close() }
