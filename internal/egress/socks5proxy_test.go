package egress

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"tr-proxy/internal/config"
	"tr-proxy/internal/netutil"
)

func TestNewUpstream(t *testing.T) {
	h, err := NewUpstream(config.Upstream{Name: "h", Type: "http", URL: "https://proxy.example.com/"})
	if _, ok := h.(*HTTPProxy); err != nil || !ok {
		t.Errorf("http: got %T, %v", h, err)
	}
	s, err := NewUpstream(config.Upstream{Name: "s", Type: "socks5", URL: "socks5://proxy.example.com"})
	sp, ok := s.(*SOCKS5Proxy)
	if err != nil || !ok {
		t.Fatalf("socks5: got %T, %v", s, err)
	}
	if sp.addr != "proxy.example.com:1080" || sp.auth != nil {
		t.Errorf("socks5 defaults: addr %q, auth %v", sp.addr, sp.auth)
	}

	withLogin, _ := NewSOCKS5Proxy(config.Upstream{Name: "s", Type: "socks5", URL: "socks5h://[::1]:9050",
		Auth: &config.UpstreamAuth{Type: "basic", Username: "u", Password: "p"}})
	if withLogin.addr != "[::1]:9050" || withLogin.auth == nil || withLogin.auth.User != "u" || withLogin.auth.Password != "p" {
		t.Errorf("socks5 with login: addr %q, auth %+v", withLogin.addr, withLogin.auth)
	}

	if _, err := NewUpstream(config.Upstream{Name: "x", Type: "socks4", URL: "socks4://x"}); err == nil {
		t.Error("an unknown type was accepted")
	}
	if _, err := NewSOCKS5Proxy(config.Upstream{Name: "x", Type: "socks5", URL: "http://x"}); err == nil {
		t.Error("an http url was accepted for a socks5 upstream")
	}
}

func TestSOCKS5ProxyCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := fmt.Sprintf("socks5://%s", ln.Addr())
	p, _ := NewSOCKS5Proxy(config.Upstream{Name: "s", Type: "socks5", URL: url})
	if err := p.Check(ctx); err != nil {
		t.Errorf("check against a listening port: %v", err)
	}
	ln.Close()
	if err := p.Check(ctx); err == nil {
		t.Error("check against a closed port succeeded")
	}
	if _, err := p.Dial(ctx, "example.com", 80); err == nil {
		t.Error("dial through a proxy that is not there succeeded")
	}
}

// socks5Server is a minimal SOCKS5 proxy (no authentication, CONNECT to an
// IPv4 address) that relays with half-closes.
func socks5Server(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 262)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				if _, err := io.ReadFull(c, buf[:buf[1]]); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:4]); err != nil || buf[3] != 1 {
					return
				}
				if _, err := io.ReadFull(c, buf[:6]); err != nil {
					return
				}
				addr := net.JoinHostPort(net.IP(buf[:4]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(buf[4:6]))))
				up, err := net.Dial("tcp", addr)
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				netutil.Relay(c, up, 0)
			}()
		}
	}()
	return ln.Addr().String()
}

// A client that sends its request and then closes its sending side still
// gets the answer through a SOCKS5 upstream.
func TestSOCKS5ProxyKeepsHalfClose(t *testing.T) {
	// The destination answers once it has read everything.
	dest, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	go func() {
		c, err := dest.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		fmt.Fprintf(c, "got %q", b)
	}()

	p, _ := NewSOCKS5Proxy(config.Upstream{Name: "s", Type: "socks5", URL: "socks5://" + socks5Server(t)})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	up, err := p.Dial(ctx, "127.0.0.1", dest.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}

	// The proxy side: a client connection relayed to the upstream.
	cl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	go func() {
		c, err := cl.Accept()
		if err != nil {
			return
		}
		netutil.Relay(c, up, 0)
	}()
	client, err := net.Dial("tcp", cl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(client, "hello")
	client.(*net.TCPConn).CloseWrite()
	answer, err := io.ReadAll(client)
	if string(answer) != `got "hello"` {
		t.Fatalf("answer %q, %v; want the reply after a half-close", answer, err)
	}
}
