package supervisor

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/proxy"

	"tr-proxy/internal/config"
)

func TestListenerAuth(t *testing.T) {
	cfg := config.New()
	users := &config.ListenerAuth{Users: []config.User{
		{Username: "alice", Password: "alice-pw"},
		{Username: "bob", Password: "bob:pw with spaces"},
	}}
	socksPort, httpPort, openPort := freePort(t), freePort(t), freePort(t)
	cfg.Listeners = []config.Listener{
		{Name: "socks", Type: "socks5", Port: socksPort, Auth: users},
		{Name: "web", Type: "http", Port: httpPort, Auth: users},
		{Name: "open", Type: "socks5", Port: openPort},
	}
	s := startServer(t, cfg)
	host, port := localEcho(t)

	t.Run("socks5", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			auth *proxy.Auth
			ok   bool
		}{
			{"alice", &proxy.Auth{User: "alice", Password: "alice-pw"}, true},
			{"bob", &proxy.Auth{User: "bob", Password: "bob:pw with spaces"}, true},
			{"wrong password", &proxy.Auth{User: "alice", Password: "bob:pw with spaces"}, false},
			{"unknown user", &proxy.Auth{User: "mallory", Password: "alice-pw"}, false},
			{"no credentials", nil, false},
		} {
			err := echoVia(socksDialer(t, socksPort, tc.auth), host, port)
			if (err == nil) != tc.ok {
				t.Errorf("%s: err = %v, want success = %v", tc.name, err, tc.ok)
			}
		}
		if got := s.tracker.AuthFailures("socks"); got != 2 {
			t.Errorf("auth failures = %d, want 2 (missing credentials do not count)", got)
		}
	})

	t.Run("open listener needs none", func(t *testing.T) {
		if err := echoVia(socksDialer(t, openPort, nil), host, port); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("http", func(t *testing.T) {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "origin saw auth: "+r.Header.Get("Proxy-Authorization"))
		}))
		defer origin.Close()
		secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "secure")
		}))
		defer secure.Close()

		via := func(user *url.Userinfo) *http.Transport {
			tr := proxyTransport(httpPort)
			u := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", httpPort), User: user}
			tr.Proxy = http.ProxyURL(u)
			return tr
		}

		// Plain forwarding: 200 with credentials, 407 without or with wrong ones.
		status, body, err := httpGet(via(url.UserPassword("bob", "bob:pw with spaces")), origin.URL)
		if err != nil || status != 200 || body != "origin saw auth: " {
			t.Errorf("good credentials: %d %q %v", status, body, err)
		}
		status, _, err = httpGet(via(nil), origin.URL)
		if err != nil || status != 407 {
			t.Errorf("no credentials: %d %v, want 407", status, err)
		}
		status, _, err = httpGet(via(url.UserPassword("alice", "nope")), origin.URL)
		if err != nil || status != 407 {
			t.Errorf("wrong password: %d %v, want 407", status, err)
		}

		// CONNECT.
		status, body, err = httpGet(via(url.UserPassword("alice", "alice-pw")), secure.URL)
		if err != nil || status != 200 || body != "secure" {
			t.Errorf("CONNECT with good credentials: %d %q %v", status, body, err)
		}
		_, _, err = httpGet(via(url.UserPassword("alice", "nope")), secure.URL)
		if err == nil || !strings.Contains(err.Error(), "407") && !strings.Contains(err.Error(), "Proxy Authentication Required") {
			t.Errorf("CONNECT with wrong password: err = %v, want a 407", err)
		}

		if got := s.tracker.AuthFailures("web"); got != 2 {
			t.Errorf("auth failures = %d, want 2", got)
		}
	})
}

func TestUpstreamEgress(t *testing.T) {
	// The upstream is another tr-proxy HTTP listener, with auth, in its own
	// server.
	upCfg := config.New()
	upPort := freePort(t)
	upCfg.Listeners = []config.Listener{{Name: "up", Type: "http", Port: upPort,
		Auth: &config.ListenerAuth{Users: []config.User{{Username: "chain", Password: "link"}}}}}
	up := startServer(t, upCfg)

	cfg := config.New()
	cfg.Upstreams = []config.Upstream{
		{Name: "H-Proxy", Type: "http", URL: fmt.Sprintf("http://127.0.0.1:%d/", upPort),
			Auth: &config.UpstreamAuth{Type: "basic", Username: "chain", Password: "link"}},
		{Name: "H-BadAuth", Type: "http", URL: fmt.Sprintf("http://127.0.0.1:%d/", upPort),
			Auth: &config.UpstreamAuth{Type: "basic", Username: "chain", Password: "wrong"}},
	}
	socksPort := freePort(t)
	cfg.Listeners = []config.Listener{{Name: "socks", Type: "socks5", Port: socksPort}}
	cfg.Rules = []config.Rule{{Name: "bad", Match: []string{"localhost"}, Via: config.Via{"H-BadAuth"}}}
	cfg.Default = "H-Proxy"
	s := startServer(t, cfg)

	host, port := localEcho(t)
	d := socksDialer(t, socksPort, nil)

	c, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "ping")
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo through upstream: %q %v", got, err)
	}
	// Both servers saw the connection: ours via the upstream, the upstream's
	// going direct.
	if snap := s.tracker.Snapshot(); len(snap) != 1 || snap[0].Egress != "H-Proxy" {
		t.Errorf("our tracker: %+v", snap)
	}
	if snap := up.tracker.Snapshot(); len(snap) != 1 || snap[0].Egress != "direct" {
		t.Errorf("upstream's tracker: %+v", snap)
	}

	if err := echoVia(d, "localhost", port); err == nil {
		t.Error("connected through an upstream that rejects our credentials")
	}
	if got := up.tracker.AuthFailures("up"); got != 1 {
		t.Errorf("upstream auth failures = %d, want 1", got)
	}
}
