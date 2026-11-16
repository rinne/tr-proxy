package supervisor

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"tr-proxy/internal/config"
	"tr-proxy/internal/testpeer"
)

// TestSOCKS5Upstream chains two servers: the one under test routes through
// SOCKS5 upstreams, which are the listeners of a second server. That second
// server owns a WireGuard tunnel whose peer is the only place the test
// hostnames resolve, so a request that arrives there proves that the
// hostname, not an address, was handed to the upstream.
func TestSOCKS5Upstream(t *testing.T) {
	old := upstreamCheckInterval
	upstreamCheckInterval = 200 * time.Millisecond
	t.Cleanup(func() { upstreamCheckInterval = old })

	// The far server: an open and a login-protected SOCKS5 listener.
	fx := newTunnelFixture(t, "T1")
	far := config.New()
	far.Keys = []config.Key{fx.key}
	far.WireGuard = []config.WireGuard{fx.conn}
	openPort, authPort := freePort(t), freePort(t)
	far.Listeners = []config.Listener{
		{Name: "open", Type: "socks5", Port: openPort},
		{Name: "authed", Type: "socks5", Port: authPort,
			Auth: &config.ListenerAuth{Users: []config.User{{Username: "chain", Password: "link"}}}},
	}
	far.Rules = []config.Rule{{Name: "tunnel", Match: []string{testpeer.HTTPHost, testpeer.EchoHost}, Via: config.Via{"T1"}}}
	farServer := startServer(t, far)
	farServer.waitUp(t, "T1")

	// The server under test.
	socks := func(port int) string { return fmt.Sprintf("socks5://127.0.0.1:%d", port) }
	login := func(password string) *config.UpstreamAuth {
		return &config.UpstreamAuth{Type: "basic", Username: "chain", Password: password}
	}
	cfg := config.New()
	cfg.Upstreams = []config.Upstream{
		{Name: "S-Open", Type: "socks5", URL: socks(openPort)},
		{Name: "S-Auth", Type: "socks5", URL: socks(authPort), Auth: login("link")},
		{Name: "S-BadAuth", Type: "socks5", URL: socks(authPort), Auth: login("wrong")},
		{Name: "S-NoAuth", Type: "socks5", URL: socks(authPort)},
		{Name: "S-Dead", Type: "socks5", URL: socks(freePort(t))},
	}
	socksPort, webPort := freePort(t), freePort(t)
	cfg.Listeners = []config.Listener{
		{Name: "socks", Type: "socks5", Port: socksPort},
		{Name: "web", Type: "http", Port: webPort},
	}
	cfg.Rules = []config.Rule{
		{Name: "open", Match: []string{testpeer.HTTPHost}, Via: config.Via{"S-Open"}},
		{Name: "auth", Match: []string{testpeer.EchoHost}, Via: config.Via{"S-Auth"}},
		{Name: "bad", Match: []string{"bad.test"}, Via: config.Via{"S-BadAuth"}},
		{Name: "none", Match: []string{"none.test"}, Via: config.Via{"S-NoAuth"}},
		{Name: "dead", Match: []string{"dead.test"}, Via: config.Via{"S-Dead"}},
		{Name: "failover", Match: []string{"127.0.0.1"}, Via: config.Via{"S-Dead", "S-Open"}},
	}
	cfg.Default = "block"
	s := startServer(t, cfg)
	d := socksDialer(t, socksPort, nil)

	t.Run("hostname is resolved at the far end", func(t *testing.T) {
		for name, tr := range map[string]func() (int, string, error){
			"http listener":   func() (int, string, error) { return httpGet(proxyTransport(webPort), "http://"+testpeer.HTTPHost+"/x") },
			"socks5 listener": func() (int, string, error) { return httpGet(socksTransport(d), "http://"+testpeer.HTTPHost+"/x") },
		} {
			status, body, err := tr()
			if err != nil || status != 200 || body != "T1 "+testpeer.HTTPHost+" /x" {
				t.Errorf("%s: %d %q %v", name, status, body, err)
			}
		}
	})

	t.Run("login", func(t *testing.T) {
		c, err := d.Dial("tcp", fmt.Sprintf("%s:%d", testpeer.EchoHost, testpeer.EchoPort))
		if err != nil {
			t.Fatalf("with the right password: %v", err)
		}
		defer c.Close()
		if err := roundTrip(c, "through a socks5 upstream"); err != nil {
			t.Fatal(err)
		}
		// Both ends show the connection, each with its own route.
		if snap := s.tracker.Snapshot(); len(snap) != 1 || snap[0].Egress != "S-Auth" || snap[0].Rule != "auth" {
			t.Errorf("our tracker: %+v", snap)
		}
		if snap := farServer.tracker.Snapshot(); len(snap) != 1 || snap[0].Egress != "T1" || snap[0].Listener != "authed" {
			t.Errorf("the far server's tracker: %+v", snap)
		}

		if err := echoVia(d, "bad.test", 80); err == nil {
			t.Error("connected through an upstream that rejects our password")
		}
		if got := farServer.tracker.AuthFailures("authed"); got != 1 {
			t.Errorf("far server's rejected logins = %d, want 1", got)
		}
		if err := echoVia(d, "none.test", 80); err == nil {
			t.Error("connected without a login through an upstream that requires one")
		}
	})

	t.Run("address destination and failover", func(t *testing.T) {
		waitFor(t, "the dead upstream to be found unreachable", 5*time.Second, func() bool {
			st := s.upstreams.Status("S-Dead")
			return !st.Checked.IsZero() && !st.Reachable
		})
		if st := s.upstreams.Status("S-Open"); !st.Reachable {
			t.Errorf("the live upstream is reported unreachable: %+v", st)
		}
		host, port := localEcho(t)
		c, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := roundTrip(c, "by address"); err != nil {
			t.Fatal(err)
		}
		snap := s.tracker.Snapshot()
		if last := snap[len(snap)-1]; last.Egress != "S-Open" || last.Rule != "failover" {
			t.Errorf("tracked as %+v, want the second entry of the failover list", last)
		}
	})

	t.Run("fails closed when the only upstream is down", func(t *testing.T) {
		status, _, err := httpGet(proxyTransport(webPort), "http://dead.test/")
		if err != nil || status != 503 {
			t.Errorf("got %d %v, want 503", status, err)
		}
	})

	t.Run("the far end's refusal is passed on", func(t *testing.T) {
		// The far server reaches a closed local port directly and fails.
		status, c, err := connectVia(webPort, fmt.Sprintf("127.0.0.1:%d", freePort(t)))
		if err != nil || !strings.Contains(status, " 502 ") {
			t.Errorf("got %q %v, want 502", status, err)
		}
		if c != nil {
			io.Copy(io.Discard, c)
			c.Close()
		}
	})

	t.Run("managed through the api with the secret kept", func(t *testing.T) {
		c := newAPIClient(t, s)
		c.login("")
		var got config.Upstream
		raw := c.want(200, "GET", "/api/upstreams/S-Auth", nil, &got)
		if got.Type != "socks5" || got.Auth.Password != config.Redacted || strings.Contains(string(raw), `"link"`) {
			t.Errorf("upstream as returned: %s", raw)
		}
		// Send it back unchanged: the stored password stays.
		c.want(200, "PUT", "/api/upstreams/S-Auth", got, nil)
		if err := echoVia(d, testpeer.EchoHost, testpeer.EchoPort); err != nil {
			t.Errorf("after an update that kept the password: %v", err)
		}
		// A token is not a SOCKS5 login.
		got.Auth = &config.UpstreamAuth{Type: "bearer", Token: "t"}
		c.want(400, "PUT", "/api/upstreams/S-Auth", got, nil)
		c.want(201, "POST", "/api/upstreams", config.Upstream{Name: "S-New", Type: "socks5", URL: "socks5h://tor:9050"}, nil)
		c.want(400, "POST", "/api/upstreams", config.Upstream{Name: "S-Bad", Type: "socks5", URL: "https://x/"}, nil)
	})
}
