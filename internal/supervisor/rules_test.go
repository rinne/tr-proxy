package supervisor

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"tr-proxy/internal/config"
	"tr-proxy/internal/testpeer"
)

// rulesFixture is a server with two tunnels, a connection whose peer does
// not exist, and one listener of each type plus a scoped one.
type rulesFixture struct {
	s                  *Server
	socks, web, office int // listener ports
	t1, t2             tunnelFixture
}

func newRulesFixture(t *testing.T) rulesFixture {
	t.Helper()
	fx := rulesFixture{
		t1: newTunnelFixture(t, "T1"), t2: newTunnelFixture(t, "T2"),
		socks: freePort(t), web: freePort(t), office: freePort(t),
	}
	// A connection to nothing: it never completes a handshake.
	dead := fx.t1.conn
	dead.Name = "Dead"
	dead.Peer.Endpoint = fmt.Sprintf("127.0.0.1:%d", freePort(t))

	cfg := config.New()
	cfg.Keys = []config.Key{fx.t1.key, fx.t2.key}
	cfg.WireGuard = []config.WireGuard{fx.t1.conn, fx.t2.conn, dead}
	cfg.Listeners = []config.Listener{
		{Name: "socks", Type: "socks5", Port: fx.socks},
		{Name: "web", Type: "http", Port: fx.web},
		{Name: "office", Type: "http", Port: fx.office, Default: "T2"},
	}
	cfg.Rules = []config.Rule{
		{Name: "www", Match: []string{testpeer.HTTPHost}, Via: config.Via{"T1"}, ExceptListeners: []string{"office"}},
		{Name: "peer-ip", Match: []string{"10.99.0.0/24"}, Via: config.Via{"T2"}},
		{Name: "failover", Match: []string{testpeer.EchoHost}, Via: config.Via{"Dead", "T1"}},
		{Name: "dead-only", Match: []string{"dead.test"}, Via: config.Via{"Dead"}},
		{Name: "ads", Match: []string{"*.ads.test"}, Via: config.Via{"block"}},
	}
	fx.s = startServer(t, cfg)
	fx.s.waitUp(t, "T1", "T2")
	return fx
}

func proxyTransport(port int) *http.Transport {
	u, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	return &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
}

// connectVia opens a CONNECT tunnel by hand and returns the status line and
// the connection.
func connectVia(port int, target string) (string, net.Conn, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return "", nil, err
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	// Unbuffered reads up to the blank line, so no tunnel bytes are lost.
	var head []byte
	b := make([]byte, 1)
	for !strings.HasSuffix(string(head), "\r\n\r\n") {
		if _, err := io.ReadFull(c, b); err != nil {
			c.Close()
			return "", nil, err
		}
		head = append(head, b[0])
	}
	status, _ := bufio.NewReader(strings.NewReader(string(head))).ReadString('\n')
	return strings.TrimSpace(status), c, nil
}

func TestRules(t *testing.T) {
	fx := newRulesFixture(t)
	socks := socksDialer(t, fx.socks, nil)
	viaSocks := &http.Transport{Dial: socks.Dial}
	localHost, localPort := localEcho(t)

	get := func(tr *http.Transport, url string) string {
		t.Helper()
		status, body, err := httpGet(tr, url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		return fmt.Sprintf("%d %s", status, strings.TrimSpace(body))
	}

	t.Run("hostname rule", func(t *testing.T) {
		want := "200 T1 " + testpeer.HTTPHost + " /a"
		if got := get(viaSocks, "http://"+testpeer.HTTPHost+"/a"); got != want {
			t.Errorf("socks: got %q, want %q", got, want)
		}
		if got := get(proxyTransport(fx.web), "http://"+testpeer.HTTPHost+"/a"); got != want {
			t.Errorf("http: got %q, want %q", got, want)
		}
	})

	t.Run("address rule", func(t *testing.T) {
		want := "200 T2 10.99.0.1 /b"
		if got := get(viaSocks, "http://10.99.0.1/b"); got != want {
			t.Errorf("socks: got %q, want %q", got, want)
		}
		if got := get(proxyTransport(fx.web), "http://10.99.0.1/b"); got != want {
			t.Errorf("http: got %q, want %q", got, want)
		}
	})

	t.Run("rule excluded from a listener falls to that listener's default", func(t *testing.T) {
		want := "200 T2 " + testpeer.HTTPHost + " /c"
		if got := get(proxyTransport(fx.office), "http://"+testpeer.HTTPHost+"/c"); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("global default is direct", func(t *testing.T) {
		if err := echoVia(socks, localHost, localPort); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("failover skips the dead tunnel", func(t *testing.T) {
		if err := echoVia(socks, testpeer.EchoHost, testpeer.EchoPort); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "earlier connections to end", 5*time.Second, func() bool {
			return len(fx.s.tracker.Snapshot()) == 0
		})
		status, c, err := connectVia(fx.web, fmt.Sprintf("%s:%d", testpeer.EchoHost, testpeer.EchoPort))
		if err != nil || !strings.Contains(status, " 200 ") {
			t.Fatalf("CONNECT: %q %v", status, err)
		}
		defer c.Close()
		io.WriteString(c, "ping")
		got := make([]byte, 4)
		if _, err := io.ReadFull(c, got); err != nil || string(got) != "ping" {
			t.Fatalf("echo through CONNECT: %q %v", got, err)
		}
		snap := fx.s.tracker.Snapshot()
		if len(snap) != 1 {
			t.Fatalf("tracker has %d connections, want 1", len(snap))
		}
		last := snap[len(snap)-1]
		if last.Rule != "failover" || last.Egress != "T1" || last.Listener != "web" {
			t.Errorf("tracked as %+v", last)
		}
	})

	t.Run("fails closed when the only egress is down", func(t *testing.T) {
		if err := echoVia(socks, "dead.test", localPort); err == nil {
			t.Error("socks: connection was made")
		}
		if got := get(proxyTransport(fx.web), "http://dead.test/"); !strings.HasPrefix(got, "503 ") {
			t.Errorf("http: got %q, want 503", got)
		}
		status, c, err := connectVia(fx.web, "dead.test:443")
		if err != nil || !strings.Contains(status, " 503 ") {
			t.Errorf("CONNECT: %q %v", status, err)
		}
		if c != nil {
			c.Close()
		}
	})

	t.Run("block", func(t *testing.T) {
		if err := echoVia(socks, "x.ads.test", localPort); err == nil {
			t.Error("socks: connection was made")
		}
		if got := get(proxyTransport(fx.web), "http://x.ads.test/"); !strings.HasPrefix(got, "403 ") {
			t.Errorf("http: got %q, want 403", got)
		}
	})

	t.Run("unreachable destination is a 502", func(t *testing.T) {
		url := fmt.Sprintf("http://127.0.0.1:%d/", freePort(t))
		if got := get(proxyTransport(fx.web), url); !strings.HasPrefix(got, "502 ") {
			t.Errorf("got %q, want 502", got)
		}
	})

	t.Run("https through CONNECT", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "secure hello")
		}))
		defer srv.Close()
		if got := get(proxyTransport(fx.web), srv.URL); got != "200 secure hello" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("post body and headers are forwarded", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, "%s|%s|%s|%s", r.Method, body, r.Header.Get("X-Test"), r.Header.Get("Proxy-Authorization"))
		}))
		defer srv.Close()
		req, _ := http.NewRequest("POST", srv.URL, strings.NewReader("payload"))
		req.Header.Set("X-Test", "kept")
		tr := proxyTransport(fx.web)
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "POST|payload|kept|" {
			t.Errorf("got %q", body)
		}
	})

	t.Run("a plain request to the proxy port is refused", func(t *testing.T) {
		status, _, err := httpGet(&http.Transport{}, fmt.Sprintf("http://127.0.0.1:%d/", fx.web))
		if err != nil || status != 400 {
			t.Errorf("got %d %v, want 400", status, err)
		}
	})
}
