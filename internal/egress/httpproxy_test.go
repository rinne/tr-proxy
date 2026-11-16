package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tr-proxy/internal/config"
)

// connectProxy is a minimal upstream proxy: it accepts CONNECT when the
// Proxy-Authorization header equals wantAuth.
func connectProxy(wantAuth string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Proxy-Authorization") != wantAuth {
			http.Error(w, "no", http.StatusProxyAuthRequired)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer up.Close()
		c, buf, _ := w.(http.Hijacker).Hijack()
		defer c.Close()
		buf.WriteString("HTTP/1.1 200 OK\r\n\r\n")
		buf.Flush()
		go io.Copy(up, c)
		io.Copy(c, up)
	})
}

func echoServer(t *testing.T) (string, int) {
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
				io.Copy(c, c)
			}()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

func echo(d Dialer, host string, port int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.Dial(ctx, host, port)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "ping")
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		return fmt.Errorf("echo: %q %v", got, err)
	}
	return nil
}

func TestHTTPProxy(t *testing.T) {
	host, port := echoServer(t)

	t.Run("plain, no auth", func(t *testing.T) {
		srv := httptest.NewServer(connectProxy(""))
		defer srv.Close()
		p, err := NewHTTPProxy(config.Upstream{Name: "u", Type: "http", URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		if err := echo(p, host, port); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("basic auth", func(t *testing.T) {
		srv := httptest.NewServer(connectProxy("Basic dXNlcjpwYXNz")) // user:pass
		defer srv.Close()
		good, _ := NewHTTPProxy(config.Upstream{Name: "u", Type: "http", URL: srv.URL,
			Auth: &config.UpstreamAuth{Type: "basic", Username: "user", Password: "pass"}})
		if err := echo(good, host, port); err != nil {
			t.Fatal(err)
		}
		bad, _ := NewHTTPProxy(config.Upstream{Name: "u", Type: "http", URL: srv.URL,
			Auth: &config.UpstreamAuth{Type: "basic", Username: "user", Password: "wrong"}})
		if err := echo(bad, host, port); err == nil || !strings.Contains(err.Error(), "407") {
			t.Fatalf("wrong password: got %v, want a 407 refusal", err)
		}
	})

	t.Run("bearer auth over tls", func(t *testing.T) {
		srv := httptest.NewTLSServer(connectProxy("Bearer sesame"))
		defer srv.Close()
		roots := x509.NewCertPool()
		roots.AddCert(srv.Certificate())

		p, _ := NewHTTPProxy(config.Upstream{Name: "u", Type: "http", URL: srv.URL,
			Auth: &config.UpstreamAuth{Type: "bearer", Token: "sesame"}})
		if err := echo(p, host, port); err == nil {
			t.Fatal("connected although the upstream's certificate is not trusted")
		}
		// httptest's certificate is issued for example.com and 127.0.0.1.
		p.TLSConfig = &tls.Config{RootCAs: roots}
		if err := echo(p, host, port); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("upstream cannot reach the destination", func(t *testing.T) {
		srv := httptest.NewServer(connectProxy(""))
		defer srv.Close()
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		closed := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		p, _ := NewHTTPProxy(config.Upstream{Name: "u", Type: "http", URL: srv.URL})
		if err := echo(p, host, closed); err == nil || !strings.Contains(err.Error(), "502") {
			t.Fatalf("got %v, want a 502 refusal", err)
		}
	})

	t.Run("upstream is down", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		url := "http://" + ln.Addr().String()
		ln.Close()
		p, _ := NewHTTPProxy(config.Upstream{Name: "u", Type: "http", URL: url})
		if err := echo(p, host, port); err == nil {
			t.Fatal("connected through a proxy that is not there")
		}
	})
}
