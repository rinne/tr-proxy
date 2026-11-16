package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"tr-proxy/internal/config"
)

// HTTPProxy connects through an upstream HTTP proxy with CONNECT. The
// upstream is reached directly from the container, over TLS when its URL is
// https. The hostname is resolved by the upstream.
type HTTPProxy struct {
	addr       string // host:port of the upstream
	tlsName    string // server name when the upstream speaks TLS; empty for plain
	authHeader string // Proxy-Authorization value; empty for none

	// TLSConfig overrides the TLS settings for the upstream; nil means the
	// system roots.
	TLSConfig *tls.Config
}

// NewHTTPProxy builds the egress for a configured upstream.
func NewHTTPProxy(u config.Upstream) (*HTTPProxy, error) {
	pu, err := url.Parse(u.URL)
	if err != nil {
		return nil, err
	}
	p := &HTTPProxy{}
	port := pu.Port()
	switch pu.Scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
		p.tlsName = pu.Hostname()
	default:
		return nil, fmt.Errorf("upstream %s: unsupported scheme %q", u.Name, pu.Scheme)
	}
	p.addr = net.JoinHostPort(pu.Hostname(), port)

	if a := u.Auth; a != nil {
		switch a.Type {
		case "basic":
			p.authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(a.Username+":"+a.Password))
		case "bearer":
			p.authHeader = "Bearer " + a.Token
		}
	}
	return p, nil
}

// Check reports whether the upstream itself can be reached: a TCP connection
// and, for an https upstream, the TLS handshake. It sends no request.
func (p *HTTPProxy) Check(ctx context.Context) error {
	c, err := p.open(ctx)
	if err != nil {
		return err
	}
	return c.Close()
}

// open connects to the upstream and completes TLS if it uses it.
func (p *HTTPProxy) open(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	if p.tlsName == "" {
		return c, nil
	}
	cfg := &tls.Config{}
	if p.TLSConfig != nil {
		cfg = p.TLSConfig.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = p.tlsName
	}
	tc := tls.Client(c, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}
	return tc, nil
}

func (p *HTTPProxy) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	c, err := p.open(ctx)
	if err != nil {
		return nil, err
	}
	// Bound the CONNECT exchange by ctx.
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	fail := func(err error) (net.Conn, error) {
		stop()
		c.Close()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, fmt.Errorf("upstream proxy: %w", err)
	}

	target := net.JoinHostPort(host, strconv.Itoa(port))
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if p.authHeader != "" {
		req += "Proxy-Authorization: " + p.authHeader + "\r\n"
	}
	if _, err := c.Write([]byte(req + "\r\n")); err != nil {
		return fail(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fail(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("CONNECT refused: %s", resp.Status))
	}
	if !stop() {
		return fail(ctx.Err())
	}
	return &bufferedConn{Conn: c, r: br}, nil
}

// bufferedConn reads through the reader that parsed the CONNECT response,
// which may already hold bytes of the stream.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
