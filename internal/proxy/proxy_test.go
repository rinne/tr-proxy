package proxy

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"tr-proxy/internal/egress"
)

// recordingRouter remembers the hosts it was asked about and refuses them
// all, so that nothing is dialled.
type recordingRouter struct {
	mu    sync.Mutex
	hosts []string
}

func (r *recordingRouter) Route(listener, host string) (Route, error) {
	r.mu.Lock()
	r.hosts = append(r.hosts, host)
	r.mu.Unlock()
	return Route{}, ErrBlocked
}

func (r *recordingRouter) asked() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.hosts...)
}

func startServer(t *testing.T, socks bool) (string, *recordingRouter) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rr := &recordingRouter{}
	s := &Server{
		Name:    "test",
		Router:  rr,
		Tracker: NewTracker(),
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); ln.Close() })
	if socks {
		go s.ServeSOCKS5(ctx, ln)
	} else {
		go s.ServeHTTP(ctx, ln)
	}
	return ln.Addr().String(), rr
}

// socksConnect sends a SOCKS5 CONNECT for a domain name without
// authentication and returns the reply code.
func socksConnect(t *testing.T, addr, domain string) byte {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	req := []byte{5, 1, 0}
	req = append(req, 5, 1, 0, 3, byte(len(domain)))
	req = append(req, domain...)
	req = append(req, 0, 80)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	return reply[1]
}

func TestSOCKS5RefusesInvalidDomainNames(t *testing.T) {
	addr, rr := startServer(t, true)
	for _, d := range []string{
		"example.com:80 HTTP/1.1\r\nHost: x\r\n\r\nGET /admin",
		"evil.com\r\nProxy-Authorization: x",
		"a b.example",
		"127.1",
		"user@example.com",
	} {
		if code := socksConnect(t, addr, d); code != socksAddrNotSupported {
			t.Errorf("%q: reply %d, want %d", d, code, socksAddrNotSupported)
		}
	}
	if code := socksConnect(t, addr, "Example.COM."); code != socksNotAllowed {
		t.Errorf("valid name: reply %d, want %d (blocked by the router)", code, socksNotAllowed)
	}
	if got := rr.asked(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("router asked about %q, want only the valid name", got)
	}
}

func TestHTTPConnectRefusesInvalidHosts(t *testing.T) {
	addr, rr := startServer(t, false)
	status := func(target string) string {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		line, _ := bufio.NewReader(c).ReadString('\n')
		return strings.TrimSpace(line)
	}
	for _, target := range []string{"127.1:80", "[fe80::1%25eth0]:80", "2130706433:443"} {
		if got := status(target); !strings.HasPrefix(got, "HTTP/1.1 400") {
			t.Errorf("%s: %q, want 400", target, got)
		}
	}
	if got := status("example.com:443"); !strings.HasPrefix(got, "HTTP/1.1 403") {
		t.Errorf("valid host: %q, want 403 from the router", got)
	}
	if got := rr.asked(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("router asked about %q, want only the valid host", got)
	}
}

func TestHTTPKeepAliveEndsWhenListenerCloses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Name:    "test",
		Router:  &recordingRouter{},
		Tracker: NewTracker(),
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth:    func(u, p string) bool { return u == "a" && p == "b" },
	}
	done := make(chan struct{})
	go func() { s.ServeHTTP(context.Background(), ln); close(done) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	req := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic YTpi\r\n\r\n"
	io.WriteString(c, req)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Close {
		t.Fatalf("first request: %d close=%v, want 403 on a kept-alive connection", resp.StatusCode, resp.Close)
	}

	ln.Close()
	<-done
	// The idle connection is closed instead of serving another request
	// with the old credentials.
	io.WriteString(c, req)
	if resp, err := http.ReadResponse(br, nil); err == nil {
		t.Fatalf("request after the listener closed was answered: %d", resp.StatusCode)
	}
}

// directRouter sends everything out directly, local addresses included.
type directRouter struct{}

func (directRouter) Route(listener, host string) (Route, error) {
	return Route{Egress: "direct", Dialer: egress.Direct{AllowLocal: true}}, nil
}

func TestHTTPForwardKeepsQuery(t *testing.T) {
	queries := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries <- r.URL.RawQuery
	}))
	defer origin.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s := &Server{
		Name:    "test",
		Router:  directRouter{},
		Tracker: NewTracker(),
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	go s.ServeHTTP(context.Background(), ln)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	for _, q := range []string{"a=1;b=2", "x=%zz&y=2", "plain=1&b=%20"} {
		resp, err := client.Get(origin.URL + "/p?" + q)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := <-queries; got != q {
			t.Errorf("query %q arrived as %q", q, got)
		}
	}
}
