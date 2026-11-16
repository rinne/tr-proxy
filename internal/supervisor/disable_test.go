package supervisor

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"tr-proxy/internal/config"
)

var proxyAuth = proxy.Auth{User: "u", Password: "pw"}

func portOpen(port int) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err == nil {
		c.Close()
	}
	return err == nil
}

func TestDisableListener(t *testing.T) {
	cfg := config.New()
	onPort, offPort := freePort(t), freePort(t)
	cfg.Listeners = []config.Listener{
		{Name: "on", Type: "socks5", Port: onPort,
			Auth: &config.ListenerAuth{Users: []config.User{{Username: "u", Password: "pw"}}}},
		{Name: "off", Type: "http", Port: offPort, Disabled: true},
	}
	s := startServer(t, cfg)
	c := newAPIClient(t, s)
	c.login("")

	listener := func(name string) ListenerStatus {
		t.Helper()
		var st Status
		c.want(200, "GET", "/api/status", nil, &st)
		for _, l := range st.Listeners {
			if l.Name == name {
				return l
			}
		}
		t.Fatalf("no listener %q in the status", name)
		return ListenerStatus{}
	}

	// A listener that is disabled in the config is not opened at start-up.
	if portOpen(offPort) || !portOpen(onPort) {
		t.Fatalf("at start: on open = %v, off open = %v", portOpen(onPort), portOpen(offPort))
	}
	if st := listener("off"); !st.Disabled || st.Error != "" {
		t.Errorf("status of the disabled listener: %+v", st)
	}

	// Hold a connection through the listener that is about to be disabled.
	host, port := localEcho(t)
	d := socksDialer(t, onPort, &proxyAuth)
	held, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	var got config.Listener
	c.want(200, "POST", "/api/listeners/on/disable", nil, &got)
	if !got.Disabled || got.Auth.Users[0].Password != config.Redacted {
		t.Errorf("answer to disable: %+v", got)
	}
	waitFor(t, "the port to close", 5*time.Second, func() bool { return !portOpen(onPort) })
	if !listener("on").Disabled {
		t.Error("status does not show the listener as disabled")
	}

	// It stays in the config, password included.
	onDisk, err := config.Load(s.env.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if l := onDisk.Listeners[0]; l.Name != "on" || !l.Disabled || l.Auth.Users[0].Password != "pw" {
		t.Errorf("listener on disk: %+v", l)
	}

	// The connection opened before keeps working.
	held.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(held, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(held, buf); err != nil || string(buf) != "ping" {
		t.Errorf("held connection after disabling: %q %v", buf, err)
	}

	// Enabling brings both back, with the same credentials.
	var enabled config.Listener
	c.want(200, "POST", "/api/listeners/on/enable", nil, &enabled)
	c.want(200, "POST", "/api/listeners/off/enable", nil, nil)
	if enabled.Name != "on" || enabled.Disabled {
		t.Errorf("answer to enable: %+v", enabled)
	}
	waitFor(t, "the ports to open", 5*time.Second, func() bool { return portOpen(onPort) && portOpen(offPort) })
	if err := echoVia(socksDialer(t, onPort, &proxyAuth), host, port); err != nil {
		t.Errorf("after enabling: %v", err)
	}
	if onDisk, _ := config.Load(s.env.ConfigPath); onDisk.Listeners[0].Disabled || onDisk.Listeners[1].Disabled {
		t.Errorf("listeners on disk after enabling: %+v", onDisk.Listeners)
	}

	c.want(404, "POST", "/api/listeners/nope/disable", nil, nil)

	// A disabled listener still holds its port in the config.
	c.want(200, "POST", "/api/listeners/off/disable", nil, nil)
	c.want(400, "POST", "/api/listeners", config.Listener{Name: "clash", Type: "http", Port: offPort}, nil)
}
