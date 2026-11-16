package egress

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"tr-proxy/internal/config"
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
