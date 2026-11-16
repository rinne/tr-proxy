package supervisor

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"tr-proxy/internal/config"
	"tr-proxy/internal/ipc"
	"tr-proxy/internal/testpeer"
)

// fastProbe is a probe of the given type that reacts within a few seconds.
func fastProbe(typ, target string) *config.Probe {
	return &config.Probe{Type: typ, Target: target, Interval: 1, Timeout: 1, Failures: 2}
}

func TestProbeTypes(t *testing.T) {
	dns, tcp, icmp, hs, quiet := newTunnelFixture(t, "Dns"), newTunnelFixture(t, "Tcp"),
		newTunnelFixture(t, "Icmp"), newTunnelFixture(t, "Handshake"), newTunnelFixture(t, "Quiet")
	tcp.conn.Probe = fastProbe(config.ProbeTCP, fmt.Sprintf("%s:%d", testpeer.EchoHost, testpeer.EchoPort))
	icmp.conn.Probe = fastProbe(config.ProbeICMP, icmp.peer.Addr.String())
	hs.conn.Probe = fastProbe(config.ProbeHandshake, "")
	// No DNS, no keepalive: nothing to probe, usable at once.
	quiet.conn.DNS = nil
	zero := 0
	quiet.conn.Peer.Keepalive = &zero

	cfg := config.New()
	for _, fx := range []tunnelFixture{dns, tcp, icmp, hs, quiet} {
		cfg.Keys = append(cfg.Keys, fx.key)
		cfg.WireGuard = append(cfg.WireGuard, fx.conn)
	}
	s := startServer(t, cfg)
	s.waitUp(t, "Dns", "Tcp", "Icmp", "Handshake", "Quiet")

	for name, want := range map[string]string{
		"Dns": config.ProbeDNS, "Tcp": config.ProbeTCP, "Icmp": config.ProbeICMP,
		"Handshake": config.ProbeHandshake, "Quiet": config.ProbeHandshake,
	} {
		st := workerStatus(s.workers, name)
		if st.Probe.Type != want || !st.Probe.Checked || !st.Probe.OK || st.Probe.Failures != 0 {
			t.Errorf("%s: probe = %+v, want an ok %s probe", name, st.Probe, want)
		}
	}
	if st := workerStatus(s.workers, "Quiet"); !st.LastHandshake.IsZero() {
		t.Errorf("Quiet: handshake happened although nothing should have sent traffic")
	}
}

func TestTunnelFailureAndRecovery(t *testing.T) {
	t1, t2 := newTunnelFixture(t, "T1"), newTunnelFixture(t, "T2")
	t1.conn.Probe = fastProbe(config.ProbeDNS, "")

	cfg := config.New()
	cfg.Keys = []config.Key{t1.key, t2.key}
	cfg.WireGuard = []config.WireGuard{t1.conn, t2.conn}
	webPort := freePort(t)
	cfg.Listeners = []config.Listener{{Name: "web", Type: "http", Port: webPort}}
	cfg.Rules = []config.Rule{
		{Name: "failover", Match: []string{"10.99.0.1"}, Via: config.Via{"T1", "T2"}},
		{Name: "t1-only", Match: []string{testpeer.HTTPHost}, Via: config.Via{"T1"}},
	}
	s := startServer(t, cfg)
	s.waitUp(t, "T1", "T2")

	get := func(url string) string {
		t.Helper()
		status, body, err := httpGet(proxyTransport(webPort), url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		return fmt.Sprintf("%d %s", status, strings.TrimSpace(body))
	}
	const failoverURL, onlyURL = "http://10.99.0.1/", "http://" + testpeer.HTTPHost + "/"

	if got := get(failoverURL); got != "200 T1 10.99.0.1 /" {
		t.Fatalf("before the failure: %q", got)
	}
	if got := get(onlyURL); !strings.HasPrefix(got, "200 T1 ") {
		t.Fatalf("before the failure: %q", got)
	}

	// The peer of T1 goes away.
	if err := t1.peer.Pause(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "T1 to be declared down and restarted", 20*time.Second, func() bool {
		return workerStatus(s.workers, "T1").Restarts > 0
	})
	if st := workerStatus(s.workers, "T1"); !strings.Contains(st.LastError, "tunnel is down") && st.State == ipc.StateUp {
		t.Errorf("T1 after the failure: %+v", st)
	}
	if got := get(failoverURL); got != "200 T2 10.99.0.1 /" {
		t.Errorf("during the failure, failover rule: %q, want it served by T2", got)
	}
	if got := get(onlyURL); !strings.HasPrefix(got, "503 ") {
		t.Errorf("during the failure, T1-only rule: %q, want 503", got)
	}
	// The restarted worker cannot come up either and keeps being restarted.
	restarts := workerStatus(s.workers, "T1").Restarts
	waitFor(t, "a second restart", 20*time.Second, func() bool {
		return workerStatus(s.workers, "T1").Restarts > restarts
	})

	// The peer comes back.
	if err := t1.peer.Resume(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "T1 to recover", 30*time.Second, func() bool {
		return workerStatus(s.workers, "T1").State == ipc.StateUp
	})
	if got := get(failoverURL); got != "200 T1 10.99.0.1 /" {
		t.Errorf("after recovery, failover rule: %q, want it back on T1", got)
	}
	if got := get(onlyURL); !strings.HasPrefix(got, "200 T1 ") {
		t.Errorf("after recovery, T1-only rule: %q", got)
	}
}

func TestUpstreamHealth(t *testing.T) {
	old := upstreamCheckInterval
	upstreamCheckInterval = 200 * time.Millisecond
	t.Cleanup(func() { upstreamCheckInterval = old })

	// The upstream's address exists but nothing listens there yet.
	upPort := freePort(t)
	cfg := config.New()
	cfg.Upstreams = []config.Upstream{{Name: "H-Proxy", Type: "http", URL: fmt.Sprintf("http://127.0.0.1:%d/", upPort)}}
	socksPort := freePort(t)
	cfg.Listeners = []config.Listener{{Name: "socks", Type: "socks5", Port: socksPort}}
	cfg.Rules = []config.Rule{{Name: "only", Match: []string{"localhost"}, Via: config.Via{"H-Proxy"}}}
	cfg.Default = "direct"
	cfg.Rules = append(cfg.Rules, config.Rule{Name: "failover", Match: []string{"127.0.0.1"}, Via: config.Via{"H-Proxy", "direct"}})
	s := startServer(t, cfg)

	waitFor(t, "the upstream to be found unreachable", 5*time.Second, func() bool {
		st := s.upstreams.Status("H-Proxy")
		return !st.Checked.IsZero() && !st.Reachable && st.LastError != ""
	})
	host, port := localEcho(t)
	d := socksDialer(t, socksPort, nil)
	if err := echoVia(d, host, port); err != nil {
		t.Fatalf("failover to direct: %v", err)
	}
	waitFor(t, "the connection to end", 5*time.Second, func() bool { return len(s.tracker.Snapshot()) == 0 })
	if err := echoVia(d, "localhost", port); err == nil {
		t.Fatal("connected although the only egress is unreachable")
	}

	// The upstream appears.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", upPort))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not really a proxy", http.StatusTeapot)
	}))
	waitFor(t, "the upstream to be found reachable", 5*time.Second, func() bool {
		return s.upstreams.Status("H-Proxy").Reachable
	})
}
