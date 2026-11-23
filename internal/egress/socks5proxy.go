package egress

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/proxy"

	"tr-proxy/internal/config"
)

// Upstream is an egress through another proxy. Besides dialing through it,
// it can say whether the proxy itself is reachable.
type Upstream interface {
	Dialer
	// Check reports whether the upstream accepts connections. It sends no
	// request through it.
	Check(ctx context.Context) error
}

// NewUpstream builds the egress for a configured upstream proxy.
func NewUpstream(u config.Upstream) (Upstream, error) {
	switch u.Type {
	case config.UpstreamHTTP:
		return NewHTTPProxy(u)
	case config.UpstreamSOCKS5:
		return NewSOCKS5Proxy(u)
	}
	return nil, fmt.Errorf("upstream %s: unsupported type %q", u.Name, u.Type)
}

// SOCKS5Proxy connects through an upstream SOCKS5 proxy (RFC 1928), with
// username/password authentication (RFC 1929) when credentials are
// configured. The upstream is reached directly from the container. The
// destination is passed to it as it was given, so a hostname is resolved by
// the upstream.
type SOCKS5Proxy struct {
	addr string // host:port of the upstream
	auth *proxy.Auth
}

// NewSOCKS5Proxy builds the egress for a configured SOCKS5 upstream.
func NewSOCKS5Proxy(u config.Upstream) (*SOCKS5Proxy, error) {
	pu, err := url.Parse(u.URL)
	if err != nil {
		return nil, err
	}
	if pu.Scheme != "socks5" && pu.Scheme != "socks5h" {
		return nil, fmt.Errorf("upstream %s: unsupported scheme %q", u.Name, pu.Scheme)
	}
	port := pu.Port()
	if port == "" {
		port = "1080"
	}
	p := &SOCKS5Proxy{addr: net.JoinHostPort(pu.Hostname(), port)}
	if a := u.Auth; a != nil && a.Type == "basic" {
		p.auth = &proxy.Auth{User: a.Username, Password: a.Password}
	}
	return p, nil
}

func (p *SOCKS5Proxy) forward() *net.Dialer {
	return &net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}
}

// Check reports whether the upstream accepts a TCP connection.
func (p *SOCKS5Proxy) Check(ctx context.Context) error {
	c, err := p.forward().DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return fmt.Errorf("upstream proxy: %w", err)
	}
	return c.Close()
}

func (p *SOCKS5Proxy) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	fwd := &rawDialer{d: p.forward()}
	d, err := proxy.SOCKS5("tcp", p.addr, p.auth, fwd)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	c, err := d.(proxy.ContextDialer).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	if raw, ok := fwd.conn.(closeWriter); ok {
		return halfCloseConn{Conn: c, raw: raw}, nil
	}
	return c, nil
}

type closeWriter interface {
	CloseWrite() error
}

// rawDialer remembers the TCP connection to the upstream. The connection
// that the SOCKS5 client returns wraps it without its CloseWrite, so a
// client's half-close would otherwise become a full close.
type rawDialer struct {
	d    *net.Dialer
	conn net.Conn
}

func (r *rawDialer) Dial(network, addr string) (net.Conn, error) {
	return r.DialContext(context.Background(), network, addr)
}

func (r *rawDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := r.d.DialContext(ctx, network, addr)
	r.conn = c
	return c, err
}

// halfCloseConn is a connection through the SOCKS5 upstream that can end
// its sending direction: after the handshake the stream is the plain TCP
// connection.
type halfCloseConn struct {
	net.Conn
	raw closeWriter
}

func (c halfCloseConn) CloseWrite() error { return c.raw.CloseWrite() }
