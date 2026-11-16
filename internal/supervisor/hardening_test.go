package supervisor

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"tr-proxy/internal/admin"
	"tr-proxy/internal/config"
	"tr-proxy/internal/testpeer"
	"tr-proxy/internal/wgkey"
)

func intPtr(n int) *int { return &n }

// roundTrip sends msg on an open echo connection and expects it back.
func roundTrip(c net.Conn, msg string) error {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	defer c.SetDeadline(time.Time{})
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

// closedSoon reports whether the peer closes c within the given time.
func closedSoon(c net.Conn, within time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(within))
	defer c.SetReadDeadline(time.Time{})
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		return false
	}
	nerr, isNet := err.(net.Error)
	return !(isNet && nerr.Timeout())
}

func TestConnectionLimit(t *testing.T) {
	cfg := config.New()
	port := freePort(t)
	cfg.Listeners = []config.Listener{{Name: "socks", Type: "socks5", Port: port}}
	cfg.Limits = &config.Limits{MaxConnections: intPtr(2), AllowLocalDirect: true, DrainTimeout: intPtr(0)}
	s := startServer(t, cfg)
	host, echoPort := localEcho(t)
	d := socksDialer(t, port, nil)
	dial := func() (net.Conn, error) { return d.Dial("tcp", fmt.Sprintf("%s:%d", host, echoPort)) }

	a, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// The listener is full: the next client is turned away at once.
	if c, err := dial(); err == nil {
		c.Close()
		t.Fatal("a third connection was served although the limit is two")
	}
	if got := s.tracker.Refused("socks"); got != 1 {
		t.Errorf("refused = %d, want 1", got)
	}
	st := s.status()
	if st.Listeners[0].Refused != 1 || st.Listeners[0].Connections != 2 {
		t.Errorf("status: %+v", st.Listeners[0])
	}
	var noted bool
	for _, e := range s.events.Snapshot() {
		noted = noted || strings.Contains(e.Message, "at its limit of 2 connections")
	}
	if !noted {
		t.Error("the event log does not mention the limit")
	}
	// The connections that were let in are unaffected.
	if err := roundTrip(a, "still here"); err != nil {
		t.Errorf("an admitted connection broke: %v", err)
	}

	// A slot that is given back can be used again.
	b.Close()
	waitFor(t, "the slot to be free", 5*time.Second, func() bool {
		c, err := dial()
		if err == nil {
			c.Close()
		}
		return err == nil
	})

	// Raising the limit takes effect without reopening the listener.
	c := newAPIClient(t, s)
	c.login("")
	var edit config.Config
	c.want(200, "GET", "/api/config", nil, &edit)
	edit.Limits.MaxConnections = intPtr(10)
	c.want(200, "PUT", "/api/config", edit, nil)
	var held []net.Conn
	for i := 0; i < 5; i++ {
		conn, err := dial()
		if err != nil {
			t.Fatalf("connection %d after raising the limit: %v", i, err)
		}
		held = append(held, conn)
	}
	for _, conn := range held {
		conn.Close()
	}
	if err := roundTrip(a, "survived the change"); err != nil {
		t.Errorf("the config change interrupted an open connection: %v", err)
	}
}

func TestIdleTimeout(t *testing.T) {
	cfg := config.New()
	socksPort, webPort := freePort(t), freePort(t)
	cfg.Listeners = []config.Listener{
		{Name: "socks", Type: "socks5", Port: socksPort},
		{Name: "web", Type: "http", Port: webPort},
	}
	cfg.Limits = &config.Limits{IdleTimeout: intPtr(1), AllowLocalDirect: true, DrainTimeout: intPtr(0)}
	s := startServer(t, cfg)
	host, echoPort := localEcho(t)
	target := fmt.Sprintf("%s:%d", host, echoPort)

	quiet, err := socksDialer(t, socksPort, nil).Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer quiet.Close()
	_, quietConnect, err := connectVia(webPort, target)
	if err != nil {
		t.Fatal(err)
	}
	defer quietConnect.Close()
	busy, err := socksDialer(t, socksPort, nil).Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	// The busy connection is used for three seconds, three times the idle
	// timeout, and must stay up.
	for i := 0; i < 10; i++ {
		if err := roundTrip(busy, "tick"); err != nil {
			t.Fatalf("busy connection broke after %d round trips: %v", i, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	// By now both quiet ones have been closed.
	if !closedSoon(quiet, time.Second) {
		t.Error("the idle SOCKS5 connection is still open")
	}
	if !closedSoon(quietConnect, time.Second) {
		t.Error("the idle CONNECT tunnel is still open")
	}
	waitFor(t, "only the busy connection to remain", 5*time.Second, func() bool {
		return len(s.tracker.Snapshot()) == 1
	})
}

func TestDirectDoesNotReachLocalAddresses(t *testing.T) {
	// An upstream proxy on loopback, in its own server, to show that the
	// restriction is on destinations of the direct route only.
	upCfg := config.New()
	upPort := freePort(t)
	upCfg.Listeners = []config.Listener{{Name: "up", Type: "http", Port: upPort}}
	startServer(t, upCfg)

	cfg := config.New()
	socksPort, webPort := freePort(t), freePort(t)
	cfg.Listeners = []config.Listener{
		{Name: "socks", Type: "socks5", Port: socksPort},
		{Name: "web", Type: "http", Port: webPort},
	}
	cfg.Upstreams = []config.Upstream{{Name: "H-Proxy", Type: "http", URL: fmt.Sprintf("http://127.0.0.1:%d/", upPort)}}
	cfg.Rules = []config.Rule{{Name: "via-upstream", Match: []string{"localhost"}, Via: config.Via{"H-Proxy"}}}
	cfg.Limits = &config.Limits{DrainTimeout: intPtr(0)} // allowLocalDirect is off, the default
	s := startServer(t, cfg)

	host, echoPort := localEcho(t)
	d := socksDialer(t, socksPort, nil)

	if err := echoVia(d, host, echoPort); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("SOCKS5 to loopback: %v, want a refusal", err)
	}
	// The admin port of the proxy itself is the case that matters most.
	if err := echoVia(d, "127.0.0.1", s.env.AdminPort); err == nil {
		t.Error("the admin port was reachable through the proxy")
	}
	for _, dest := range []string{"127.0.0.1", "169.254.169.254", "[::1]", "0.0.0.0"} {
		status, _, err := httpGet(proxyTransport(webPort), fmt.Sprintf("http://%s:%d/", dest, echoPort))
		if err != nil || status != 403 {
			t.Errorf("HTTP to %s: %d %v, want 403", dest, status, err)
		}
	}
	status, c, err := connectVia(webPort, fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil || !strings.Contains(status, " 403 ") {
		t.Errorf("CONNECT to loopback: %q %v, want 403", status, err)
	}
	if c != nil {
		c.Close()
	}
	if n := len(s.tracker.Snapshot()); n != 0 {
		t.Errorf("%d refused connections are tracked as open", n)
	}

	// The upstream on loopback is still used, and what it reaches is its
	// own business.
	if err := echoVia(d, "localhost", echoPort); err != nil {
		t.Errorf("through the upstream proxy on loopback: %v", err)
	}
}

func TestShutdownDrainsOpenConnections(t *testing.T) {
	fx := newTunnelFixture(t, "T1")
	cfg := config.New()
	cfg.Keys = []config.Key{fx.key}
	cfg.WireGuard = []config.WireGuard{fx.conn}
	port := freePort(t)
	cfg.Listeners = []config.Listener{{Name: "socks", Type: "socks5", Port: port}}
	cfg.Rules = []config.Rule{{Name: "tunnel", Match: []string{testpeer.EchoHost}, Via: config.Via{"T1"}}}
	cfg.Limits = &config.Limits{DrainTimeout: intPtr(20), AllowLocalDirect: true}
	s := startServer(t, cfg)
	s.waitUp(t, "T1")
	workerPID := workerStatus(s.workers, "T1").PID

	host, echoPort := localEcho(t)
	d := socksDialer(t, port, nil)
	direct, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, echoPort))
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	tunnelled, err := d.Dial("tcp", fmt.Sprintf("%s:%d", testpeer.EchoHost, testpeer.EchoPort))
	if err != nil {
		t.Fatal(err)
	}
	defer tunnelled.Close()

	done := make(chan struct{})
	started := time.Now()
	go func() {
		s.Shutdown()
		close(done)
	}()

	// New clients are turned away at once...
	waitFor(t, "the listener to close", 5*time.Second, func() bool { return !portOpen(port) })
	// ...while the open connections keep working, the tunnelled one
	// included: its worker must outlive the drain.
	for i := 0; i < 5; i++ {
		if err := roundTrip(direct, "direct during drain"); err != nil {
			t.Fatalf("direct connection during the drain: %v", err)
		}
		if err := roundTrip(tunnelled, "tunnel during drain"); err != nil {
			t.Fatalf("tunnelled connection during the drain: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("shutdown finished while connections were still open")
	default:
	}

	// Once they are done, shutdown does not sit out the rest of the timeout.
	direct.Close()
	tunnelled.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not finish after the connections closed")
	}
	if took := time.Since(started); took > 12*time.Second {
		t.Errorf("shutdown took %v with a 20 s drain timeout and connections that closed early", took)
	}
	if syscall.Kill(workerPID, 0) == nil {
		t.Errorf("the worker process (pid %d) is still running after shutdown", workerPID)
	}
}

func TestShutdownClosesConnectionsThatOutstayTheDrain(t *testing.T) {
	cfg := config.New()
	port := freePort(t)
	cfg.Listeners = []config.Listener{{Name: "socks", Type: "socks5", Port: port}}
	cfg.Limits = &config.Limits{DrainTimeout: intPtr(1), AllowLocalDirect: true}
	s := startServer(t, cfg)

	host, echoPort := localEcho(t)
	held, err := socksDialer(t, port, nil).Dial("tcp", fmt.Sprintf("%s:%d", host, echoPort))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	started := time.Now()
	s.Shutdown()
	took := time.Since(started)
	if took < 900*time.Millisecond || took > 5*time.Second {
		t.Errorf("shutdown took %v, want about the 1 s drain timeout", took)
	}
	if !closedSoon(held, 2*time.Second) {
		t.Error("the connection is still open after shutdown")
	}
}

// lockedBuffer is a bytes.Buffer that several goroutines may write to.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestSecretsStayOutOfLogsAndStatus runs a server with recognisable secrets
// through the situations that produce log lines and events, and checks that
// none of the secrets appears anywhere an operator or the UI can read.
func TestSecretsStayOutOfLogsAndStatus(t *testing.T) {
	fx := newTunnelFixture(t, "T1")
	_, presharedKey, _ := wgkey.Generate() // any valid key
	const (
		adminPassword    = "admin-password-Zq7"
		upstreamPassword = "upstream-password-Xk2"
		upstreamToken    = "upstream-token-Lm9"
		userPassword     = "listener-password-Vb4"
	)
	totpSecret := []byte("totp-secret-Hw5!")

	// A second connection to a peer that does not exist, with a preshared
	// key, so that a failing tunnel is part of the picture.
	dead := fx.conn
	dead.Name = "Dead"
	dead.Peer.Endpoint = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	dead.Peer.PresharedKey = presharedKey
	dead.Probe = fastProbe(config.ProbeDNS, "")

	cfg := config.New()
	cfg.Keys = []config.Key{fx.key}
	cfg.WireGuard = []config.WireGuard{fx.conn, dead}
	deadUpstream := fmt.Sprintf("http://127.0.0.1:%d/", freePort(t))
	cfg.Upstreams = []config.Upstream{
		{Name: "Basic", Type: "http", URL: deadUpstream, Auth: &config.UpstreamAuth{Type: "basic", Username: "u", Password: upstreamPassword}},
		{Name: "Bearer", Type: "http", URL: deadUpstream, Auth: &config.UpstreamAuth{Type: "bearer", Token: upstreamToken}},
	}
	socksPort, webPort := freePort(t), freePort(t)
	users := &config.ListenerAuth{Users: []config.User{{Username: "alice", Password: userPassword}}}
	cfg.Listeners = []config.Listener{
		{Name: "socks", Type: "socks5", Port: socksPort, Auth: users},
		{Name: "web", Type: "http", Port: webPort, Auth: users},
	}
	cfg.Rules = []config.Rule{
		{Name: "basic", Match: []string{"basic.test"}, Via: config.Via{"Basic"}},
		{Name: "bearer", Match: []string{"bearer.test"}, Via: config.Via{"Bearer"}},
		{Name: "dead", Match: []string{"dead.test"}, Via: config.Via{"Dead"}},
		{Name: "tunnel", Match: []string{testpeer.EchoHost}, Via: config.Via{"T1"}},
	}
	cfg.Limits = &config.Limits{AllowLocalDirect: true, DrainTimeout: intPtr(0)}

	env := newTestEnv(t)
	env.AdminPassword = adminPassword
	env.AdminTOTPSecret = totpSecret
	if err := config.Validate(cfg, env.ProxyPorts); err != nil {
		t.Fatal(err)
	}
	if err := config.Save(env.ConfigPath, cfg); err != nil {
		t.Fatal(err)
	}

	// Everything the supervisor and its workers log, at the most verbose
	// level.
	var logs, workerLogs lockedBuffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s, err := New(env, log)
	if err != nil {
		t.Fatal(err)
	}
	s.workers.stderr = &workerLogs
	s.workers.args = []string{"worker", "verbose"}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		s.Shutdown()
	})
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	s.waitUp(t, "T1")

	// Proxy traffic: good and bad logins, a working tunnel, upstreams that
	// are down, a tunnel that is down.
	good := socksDialer(t, socksPort, proxyAuthFor{"alice", userPassword}.auth())
	if err := echoVia(good, testpeer.EchoHost, testpeer.EchoPort); err != nil {
		t.Fatalf("through the tunnel: %v", err)
	}
	for _, host := range []string{"basic.test", "bearer.test", "dead.test"} {
		echoVia(good, host, 80)
	}
	echoVia(socksDialer(t, socksPort, proxyAuthFor{"alice", "a wrong password"}.auth()), "x.test", 80)
	httpGet(proxyTransport(webPort), "http://basic.test/")

	// Admin API: bad and good logins, reads, an invalid write, a valid one.
	c := newAPIClient(t, s)
	c.base = fmt.Sprintf("http://127.0.0.1:%d", env.AdminPort)
	c.do("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong", "totp": "000000"})
	status, _ := c.do("POST", "/api/login", map[string]string{
		"username": "admin", "password": adminPassword, "totp": totpCode(totpSecret)})
	if status != 200 {
		t.Fatalf("login: %d", status)
	}
	var readable bytes.Buffer // what the API hands out
	var edit config.Config
	readable.Write(c.want(200, "GET", "/api/config", nil, &edit))
	for _, path := range []string{"/api/keys", "/api/wireguard", "/api/upstreams", "/api/listeners", "/api/rules"} {
		readable.Write(c.want(200, "GET", path, nil, nil))
	}
	bad := edit
	bad.Default = "nope"
	_, body := c.do("PUT", "/api/config", bad)
	readable.Write(body)
	readable.Write(c.want(200, "PUT", "/api/config", edit, nil))
	c.want(204, "POST", "/api/wireguard/T1/restart", nil, nil)

	// Let the dead tunnel be declared down and restarted at least once.
	waitFor(t, "the dead tunnel to be restarted", 20*time.Second, func() bool {
		return workerStatus(s.workers, "Dead").Restarts > 0
	})
	readable.Write(c.want(200, "GET", "/api/status", nil, nil))
	events, _ := json.Marshal(s.events.Snapshot())
	readable.Write(events)

	clientPublic, _ := wgkey.Public(fx.key.SecretKey)
	keyHex, _ := wgkey.Hex(fx.key.SecretKey)
	pskHex, _ := wgkey.Hex(presharedKey)
	secrets := map[string]string{
		"the WireGuard secret key":          fx.key.SecretKey,
		"the WireGuard secret key (hex)":    keyHex,
		"the preshared key":                 presharedKey,
		"the preshared key (hex)":           pskHex,
		"the upstream password":             upstreamPassword,
		"the upstream token":                upstreamToken,
		"the listener password":             userPassword,
		"the admin password":                adminPassword,
		"the TOTP secret":                   string(totpSecret),
		"the TOTP secret (base32)":          base32.StdEncoding.EncodeToString(totpSecret),
		"the upstream basic-auth header":    base64.StdEncoding.EncodeToString([]byte("u:" + upstreamPassword)),
		"the wrong password a client tried": "a wrong password",
	}
	outputs := map[string]string{
		"the supervisor's log": logs.String(),
		"the workers' log":     workerLogs.String(),
		"the API's answers":    readable.String(),
	}
	for what, secret := range secrets {
		for where, text := range outputs {
			if strings.Contains(text, secret) {
				t.Errorf("%s appears in %s", what, where)
			}
		}
	}

	// The check is only worth something if these outputs are not empty and
	// the public parts are where they should be.
	if !strings.Contains(logs.String(), "proxy login rejected") || !strings.Contains(logs.String(), "worker exited") {
		t.Errorf("the supervisor's log is missing the lines this test provokes:\n%s", logs.String())
	}
	// In JSON the placeholder's angle brackets are escaped.
	if !strings.Contains(readable.String(), clientPublic) || !strings.Contains(readable.String(), `\u003credacted\u003e`) {
		t.Error("the API's answers lack the public key or the redaction placeholder")
	}
	if !strings.Contains(workerLogs.String(), "tunnel up") {
		t.Errorf("the workers' log is missing its start-up lines:\n%s", workerLogs.String())
	}
}

// proxyAuthFor builds SOCKS5 credentials.
type proxyAuthFor struct{ user, password string }

func (p proxyAuthFor) auth() *proxy.Auth { return &proxy.Auth{User: p.user, Password: p.password} }

func totpCode(secret []byte) string { return admin.TOTPCode(secret, time.Now()) }
