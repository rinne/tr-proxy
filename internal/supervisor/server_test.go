package supervisor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"tr-proxy/internal/config"
	"tr-proxy/internal/ipc"
	"tr-proxy/internal/testpeer"
)

// freePort returns a TCP port that was free a moment ago.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// newTestEnv returns an environment rooted in a fresh temp dir.
func newTestEnv(t *testing.T) *Env {
	t.Helper()
	dir := t.TempDir()
	return &Env{
		AdminUsername: "admin",
		AdminPassword: "test-password",
		AdminPort:     freePort(t),
		ProxyPorts:    config.PortRange{Lo: 1, Hi: 65535},
		ConfigPath:    filepath.Join(dir, "config.json"),
		RunDir:        filepath.Join(dir, "run"),
	}
}

// runServer runs a supervisor on env until the test ends.
func runServer(t *testing.T, env *Env) *Server {
	t.Helper()
	s, err := New(env, testLog(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		s.Shutdown()
	})
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

// startServer writes cfg to a temp dir and runs a supervisor on it.
func startServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	env := newTestEnv(t)
	if err := config.Validate(cfg, env.ProxyPorts); err != nil {
		t.Fatalf("test config is invalid:\n%v", err)
	}
	if err := config.Save(env.ConfigPath, cfg); err != nil {
		t.Fatal(err)
	}
	return runServer(t, env)
}

func (s *Server) waitUp(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		waitFor(t, "tunnel "+name, 15*time.Second, func() bool {
			return workerStatus(s.workers, name).State == ipc.StateUp
		})
	}
}

// localEcho is an echo server on loopback, reachable only directly.
func localEcho(t *testing.T) (host string, port int) {
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
				io.Copy(c, c)
			}()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

func socksDialer(t *testing.T, port int, auth *proxy.Auth) proxy.Dialer {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), auth, &net.Dialer{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// echoVia checks an echo round trip through a dialer.
func echoVia(d proxy.Dialer, host string, port int) error {
	// Bounded, so that tests of unreachable destinations do not sit out the
	// proxy's own dial timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.(proxy.ContextDialer).DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	msg := "hello through the proxy"
	if _, err := io.WriteString(c, msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if string(got) != msg {
		return fmt.Errorf("echo returned %q", got)
	}
	return nil
}

// httpGet fetches a URL with the given transport and returns the body.
func httpGet(tr *http.Transport, url string) (int, string, error) {
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	defer tr.CloseIdleConnections()
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func TestSOCKS5Direct(t *testing.T) {
	cfg := config.New()
	cfg.Listeners = []config.Listener{{Name: "socks", Type: "socks5", Port: freePort(t)}}
	s := startServer(t, cfg)
	d := socksDialer(t, cfg.Listeners[0].Port, nil)

	host, port := localEcho(t)
	if err := echoVia(d, host, port); err != nil {
		t.Fatal(err)
	}
	if err := echoVia(d, "localhost", port); err != nil {
		t.Fatalf("by hostname: %v", err)
	}
	if err := echoVia(d, host, freePort(t)); err == nil {
		t.Fatal("connect to a closed port succeeded")
	}

	// A held connection shows up in the tracker with its route.
	c, err := d.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "12345")
	waitFor(t, "tracked connection", 5*time.Second, func() bool {
		snap := s.tracker.Snapshot()
		return len(snap) == 1 && snap[0].Listener == "socks" && snap[0].Egress == "direct" && snap[0].BytesUp == 5
	})
	c.Close()
	waitFor(t, "connection to be forgotten", 5*time.Second, func() bool {
		return len(s.tracker.Snapshot()) == 0
	})
}

func TestSOCKS5ThroughTunnel(t *testing.T) {
	fx := newTunnelFixture(t, "T1")
	cfg := config.New()
	cfg.Keys = []config.Key{fx.key}
	cfg.WireGuard = []config.WireGuard{fx.conn}
	cfg.Listeners = []config.Listener{{Name: "socks", Type: "socks5", Port: freePort(t)}}
	cfg.Default = "T1"
	s := startServer(t, cfg)
	s.waitUp(t, "T1")
	d := socksDialer(t, cfg.Listeners[0].Port, nil)

	if err := echoVia(d, fx.peer.Addr.String(), testpeer.EchoPort); err != nil {
		t.Fatalf("by address: %v", err)
	}
	if err := echoVia(d, testpeer.EchoHost, testpeer.EchoPort); err != nil {
		t.Fatalf("by hostname: %v", err)
	}

	// HTTP through the proxy reaches the peer's web server by a name only
	// the peer's DNS knows.
	status, body, err := httpGet(&http.Transport{Dial: d.Dial}, "http://"+testpeer.HTTPHost+"/x")
	if err != nil || status != 200 || body != "T1 "+testpeer.HTTPHost+" /x" {
		t.Fatalf("GET via tunnel: %d %q %v", status, body, err)
	}

	// Loopback of this machine is not reachable through the tunnel, which
	// shows the traffic really leaves through it.
	host, port := localEcho(t)
	if err := echoVia(d, host, port); err == nil {
		t.Fatal("local echo was reachable through the tunnel")
	}
}

func TestSOCKS5Block(t *testing.T) {
	cfg := config.New()
	cfg.Listeners = []config.Listener{{Name: "socks", Type: "socks5", Port: freePort(t)}}
	cfg.Default = "block"
	startServer(t, cfg)
	d := socksDialer(t, cfg.Listeners[0].Port, nil)

	host, port := localEcho(t)
	if err := echoVia(d, host, port); err == nil {
		t.Fatal("connection was allowed although the default is block")
	}
}
