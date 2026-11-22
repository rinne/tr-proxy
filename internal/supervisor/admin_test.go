package supervisor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"

	"tr-proxy/internal/admin"
	"tr-proxy/internal/config"
	"tr-proxy/internal/ipc"
	"tr-proxy/internal/testpeer"
	"tr-proxy/internal/wgkey"
)

// apiClient talks to a server's admin API and keeps its session cookie.
type apiClient struct {
	t    *testing.T
	base string
	http *http.Client
}

func newAPIClient(t *testing.T, s *Server) *apiClient {
	jar, _ := cookiejar.New(nil)
	return &apiClient{
		t:    t,
		base: fmt.Sprintf("http://127.0.0.1:%d", s.env.AdminPort),
		http: &http.Client{Jar: jar, Timeout: 30 * time.Second},
	}
}

// do sends a request with an optional JSON body and returns status and body.
// headers are key, value pairs.
func (c *apiClient) do(method, path string, body any, headers ...string) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// want sends a request, requires the status and decodes the answer into out
// (if not nil).
func (c *apiClient) want(status int, method, path string, body, out any) []byte {
	c.t.Helper()
	got, data := c.do(method, path, body)
	if got != status {
		c.t.Fatalf("%s %s: status %d, want %d; body: %s", method, path, got, status, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			c.t.Fatalf("%s %s: %v; body: %s", method, path, err, data)
		}
	}
	return data
}

func (c *apiClient) login(totp string) int {
	status, _ := c.do("POST", "/api/login", map[string]string{"username": "admin", "password": "test-password", "totp": totp})
	return status
}

func TestAdminLogin(t *testing.T) {
	s := startServer(t, config.New())
	c := newAPIClient(t, s)

	if status, _ := c.do("GET", "/healthz", nil); status != 200 {
		t.Errorf("healthz: %d", status)
	}
	for _, path := range []string{"/api/config", "/api/status", "/api/keys", "/api/rules/x"} {
		if status, _ := c.do("GET", path, nil); status != 401 {
			t.Errorf("GET %s without a session: %d, want 401", path, status)
		}
	}
	if status, _ := c.do("PUT", "/api/config", config.New()); status != 401 {
		t.Errorf("PUT /api/config without a session: %d, want 401", status)
	}

	var sess struct{ Authenticated, TOTP bool }
	c.want(200, "GET", "/api/session", nil, &sess)
	if sess.Authenticated || sess.TOTP {
		t.Errorf("session before login: %+v", sess)
	}

	if status, _ := c.do("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"}); status != 401 {
		t.Errorf("wrong password: %d, want 401", status)
	}
	if status, _ := c.do("POST", "/api/login",
		map[string]string{"username": "admin", "password": "test-password"},
		"Origin", "http://evil.example"); status != 403 {
		t.Errorf("cross-origin login: %d, want 403", status)
	}
	if status := c.login(""); status != 200 {
		t.Fatalf("login: %d", status)
	}
	c.want(200, "GET", "/api/session", nil, &sess)
	if !sess.Authenticated {
		t.Error("not authenticated after login")
	}
	c.want(200, "GET", "/api/config", nil, nil)

	// A logged-in browser on another site cannot change anything.
	if status, _ := c.do("PUT", "/api/config", config.New(), "Origin", "http://evil.example"); status != 403 {
		t.Errorf("cross-origin PUT: %d, want 403", status)
	}
	if status, _ := c.do("PUT", "/api/config", config.New(), "Sec-Fetch-Site", "cross-site"); status != 403 {
		t.Errorf("cross-site PUT: %d, want 403", status)
	}
	if status, _ := c.do("PUT", "/api/config", config.New(), "Origin", c.base); status != 200 {
		t.Errorf("same-origin PUT: %d, want 200", status)
	}

	c.want(200, "POST", "/api/logout", nil, nil)
	if status, _ := c.do("GET", "/api/config", nil); status != 401 {
		t.Errorf("after logout: %d, want 401", status)
	}

	// The login attempts are in the event log.
	var kinds []string
	for _, e := range s.events.Snapshot() {
		kinds = append(kinds, e.Kind+": "+e.Message)
	}
	all := strings.Join(kinds, "\n")
	if !strings.Contains(all, "admin login rejected") || !strings.Contains(all, "admin logged in") {
		t.Errorf("events:\n%s", all)
	}
}

func TestAdminTOTP(t *testing.T) {
	env := newTestEnv(t)
	env.AdminTOTPSecret = []byte("totp test secret")
	s := runServer(t, env)
	c := newAPIClient(t, s)

	var sess struct{ Authenticated, TOTP bool }
	c.want(200, "GET", "/api/session", nil, &sess)
	if !sess.TOTP {
		t.Error("session does not announce TOTP")
	}
	if status := c.login(""); status != 401 {
		t.Errorf("login without a code: %d, want 401", status)
	}
	code := admin.TOTPCode(env.AdminTOTPSecret, time.Now())
	if status := c.login(code); status != 200 {
		t.Fatalf("login with a code: %d", status)
	}
	if status := newAPIClient(t, s).login(code); status != 401 {
		t.Errorf("second login with the same code: %d, want 401", status)
	}
}

func TestAdminRateLimit(t *testing.T) {
	s := startServer(t, config.New())
	c := newAPIClient(t, s)
	for i := 0; i < 10; i++ {
		c.do("POST", "/api/login", map[string]string{"username": "admin", "password": "guess"})
	}
	if status := c.login(""); status != 429 {
		t.Errorf("login after ten failures: %d, want 429", status)
	}
}

func TestAdminConfigAndReload(t *testing.T) {
	fx := newTunnelFixture(t, "T1")
	cfg := config.New()
	cfg.Keys = []config.Key{fx.key}
	cfg.WireGuard = []config.WireGuard{fx.conn}
	socksPort, webPort := freePort(t), freePort(t)
	cfg.Listeners = []config.Listener{{Name: "socks", Type: "socks5", Port: socksPort}}
	cfg.Default = "T1"
	s := startServer(t, cfg)
	s.waitUp(t, "T1")
	c := newAPIClient(t, s)
	c.login("")

	stored := func() *config.Config {
		t.Helper()
		onDisk, err := config.Load(s.env.ConfigPath)
		if err != nil {
			t.Fatal(err)
		}
		return onDisk
	}
	pid := func() int { return workerStatus(s.workers, "T1").PID }
	firstPID := pid()

	t.Run("secrets are redacted on read", func(t *testing.T) {
		var got config.Config
		raw := c.want(200, "GET", "/api/config", nil, &got)
		if strings.Contains(string(raw), fx.key.SecretKey) {
			t.Fatal("the secret key is in the response")
		}
		public, _ := wgkey.Public(fx.key.SecretKey)
		if got.Keys[0].SecretKey != config.Redacted || got.Keys[0].PublicKey != public {
			t.Errorf("key in response: %+v", got.Keys[0])
		}
	})

	t.Run("whole-config write keeps secrets and restarts nothing unaffected", func(t *testing.T) {
		var edit config.Config
		c.want(200, "GET", "/api/config", nil, &edit)
		edit.Listeners = append(edit.Listeners, config.Listener{Name: "web", Type: "http", Port: webPort})
		edit.Rules = []config.Rule{{Name: "r1", Match: []string{"*.ads.test"}, Via: config.Via{"block"}}}
		c.want(200, "PUT", "/api/config", edit, nil)

		onDisk := stored()
		if onDisk.Keys[0].SecretKey != fx.key.SecretKey || onDisk.Keys[0].PublicKey != "" {
			t.Errorf("key on disk: %+v", onDisk.Keys[0])
		}
		if len(onDisk.Listeners) != 2 || len(onDisk.Rules) != 1 {
			t.Errorf("config on disk: %+v", onDisk)
		}
		if st := workerStatus(s.workers, "T1"); st.PID != firstPID || st.Restarts != 0 {
			t.Errorf("T1 was restarted by an unrelated change: %+v", st)
		}
		// The new listener and rule work at once.
		status, body, err := httpGet(proxyTransport(webPort), "http://"+testpeer.HTTPHost+"/")
		if err != nil || status != 200 || !strings.HasPrefix(body, "T1 ") {
			t.Errorf("new listener: %d %q %v", status, body, err)
		}
		status, _, _ = httpGet(proxyTransport(webPort), "http://x.ads.test/")
		if status != 403 {
			t.Errorf("new rule: %d, want 403", status)
		}
	})

	t.Run("invalid config is rejected whole", func(t *testing.T) {
		var edit config.Config
		c.want(200, "GET", "/api/config", nil, &edit)
		edit.Default = "nope"
		edit.Rules = nil
		var resp struct {
			Error    string
			Problems []string
		}
		c.want(400, "PUT", "/api/config", edit, &resp)
		if len(resp.Problems) != 1 || !strings.Contains(resp.Problems[0], "unknown connection") {
			t.Errorf("problems: %+v", resp)
		}
		if onDisk := stored(); onDisk.Default != "T1" || len(onDisk.Rules) != 1 {
			t.Errorf("a rejected config changed the file: %+v", onDisk)
		}
		if status, _ := c.do("PUT", "/api/config", map[string]any{"version": 1, "defualt": "direct"}); status != 400 {
			t.Errorf("unknown field: %d, want 400", status)
		}
	})

	t.Run("changing a connection restarts its worker", func(t *testing.T) {
		var conn config.WireGuard
		c.want(200, "GET", "/api/wireguard/T1", nil, &conn)
		conn.Probe = fastProbe(config.ProbeDNS, "")
		c.want(200, "PUT", "/api/wireguard/T1", conn, nil)
		waitFor(t, "a new worker", 15*time.Second, func() bool {
			st := workerStatus(s.workers, "T1")
			return st.PID != 0 && st.PID != firstPID && st.State == ipc.StateUp
		})
		if err := echoVia(socksDialer(t, socksPort, nil), testpeer.EchoHost, testpeer.EchoPort); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("restart on request", func(t *testing.T) {
		before := pid()
		c.want(204, "POST", "/api/wireguard/T1/restart", nil, nil)
		waitFor(t, "a new worker", 15*time.Second, func() bool {
			st := workerStatus(s.workers, "T1")
			return st.PID != 0 && st.PID != before && st.State == ipc.StateUp
		})
		c.want(404, "POST", "/api/wireguard/nope/restart", nil, nil)
	})

	t.Run("removing a listener closes its port", func(t *testing.T) {
		c.want(204, "DELETE", "/api/listeners/web", nil, nil)
		waitFor(t, "the port to close", 5*time.Second, func() bool {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", webPort), time.Second)
			if err == nil {
				conn.Close()
			}
			return err != nil
		})
		c.want(404, "GET", "/api/listeners/web", nil, nil)
	})

	t.Run("a referenced key cannot be deleted", func(t *testing.T) {
		c.want(400, "DELETE", "/api/keys/T1-key", nil, nil)
		c.want(200, "GET", "/api/keys/T1-key", nil, nil)
	})

	t.Run("rule collection", func(t *testing.T) {
		r2 := config.Rule{Name: "r2", Match: []string{"x.test"}, Via: config.Via{"direct"}}
		c.want(201, "POST", "/api/rules", r2, nil)
		c.want(409, "POST", "/api/rules", r2, nil)
		c.want(400, "POST", "/api/rules", config.Rule{Name: "r3", Match: []string{"x.test"}, Via: config.Via{"nope"}}, nil)

		r2.Via = config.Via{"T1", "direct"}
		var got config.Rule
		c.want(200, "PUT", "/api/rules/r2", r2, &got)
		if len(got.Via) != 2 {
			t.Errorf("updated rule: %+v", got)
		}
		c.want(404, "PUT", "/api/rules/nope", r2, nil)

		var rules []config.Rule
		c.want(200, "POST", "/api/rules/order", []string{"r2", "r1"}, &rules)
		c.want(200, "GET", "/api/rules", nil, &rules)
		if len(rules) != 2 || rules[0].Name != "r2" || rules[1].Name != "r1" {
			t.Errorf("order: %+v", rules)
		}
		c.want(400, "POST", "/api/rules/order", []string{"r2"}, nil)
		c.want(400, "POST", "/api/rules/order", []string{"r2", "r2"}, nil)

		c.want(204, "DELETE", "/api/rules/r1", nil, nil)
		c.want(404, "DELETE", "/api/rules/r1", nil, nil)
	})

	t.Run("test-route", func(t *testing.T) {
		var route admin.RouteTest
		c.want(200, "POST", "/api/test-route", map[string]string{"listener": "socks", "host": "X.Test."}, &route)
		if route.Rule != "r2" || route.Egress != "T1" || len(route.Via) != 2 || route.Error != "" {
			t.Errorf("route: %+v", route)
		}
		c.want(200, "POST", "/api/test-route", map[string]string{"listener": "socks", "host": "other.test"}, &route)
		if route.Rule != "" || route.Egress != "T1" {
			t.Errorf("default route: %+v", route)
		}
		c.want(400, "POST", "/api/test-route", map[string]string{"listener": "nope", "host": "x.test"}, nil)
	})

	t.Run("generate a key", func(t *testing.T) {
		var key config.Key
		raw := c.want(201, "POST", "/api/keys/generate", map[string]string{"name": "gen"}, &key)
		onDisk, _ := stored().KeyByName("gen")
		public, err := wgkey.Public(onDisk.SecretKey)
		if err != nil || key.PublicKey != public || key.SecretKey != config.Redacted {
			t.Errorf("generated key: %+v (on disk public %q, %v)", key, public, err)
		}
		if strings.Contains(string(raw), onDisk.SecretKey) {
			t.Error("the generated secret is in the response")
		}
		c.want(409, "POST", "/api/keys/generate", map[string]string{"name": "gen"}, nil)
		c.want(204, "DELETE", "/api/keys/gen", nil, nil)
	})

	t.Run("listener passwords are kept on update", func(t *testing.T) {
		port1, port2 := freePort(t), freePort(t)
		l := config.Listener{Name: "authed", Type: "http", Port: port1,
			Auth: &config.ListenerAuth{Users: []config.User{{Username: "u", Password: "pw"}}}}
		var got config.Listener
		c.want(201, "POST", "/api/listeners", l, &got)
		if got.Auth.Users[0].Password != config.Redacted {
			t.Errorf("password in response: %+v", got.Auth.Users[0])
		}
		// Send the redacted form back with another port.
		got.Port = port2
		c.want(200, "PUT", "/api/listeners/authed", got, nil)
		for _, saved := range stored().Listeners {
			if saved.Name == "authed" && (saved.Port != port2 || saved.Auth.Users[0].Password != "pw") {
				t.Errorf("stored listener: %+v", saved)
			}
		}
		// A placeholder for a user that has no stored password is refused.
		got.Auth.Users = append(got.Auth.Users, config.User{Username: "new", Password: config.Redacted})
		c.want(400, "PUT", "/api/listeners/authed", got, nil)
		c.want(204, "DELETE", "/api/listeners/authed", nil, nil)
	})

	t.Run("status", func(t *testing.T) {
		// Hold a connection open so that it shows.
		d := socksDialer(t, socksPort, nil)
		conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", testpeer.EchoHost, testpeer.EchoPort))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		var st Status
		raw := c.want(200, "GET", "/api/status", nil, &st)
		if len(st.Tunnels) != 1 || st.Tunnels[0].Name != "T1" || st.Tunnels[0].State != ipc.StateUp ||
			st.Tunnels[0].Endpoint != fx.peer.Endpoint || !st.Tunnels[0].Probe.OK {
			t.Errorf("tunnels: %+v", st.Tunnels)
		}
		if len(st.Listeners) != 1 || st.Listeners[0].Name != "socks" || st.Listeners[0].Connections != 1 {
			t.Errorf("listeners: %+v", st.Listeners)
		}
		if len(st.Connections) != 1 || st.Connections[0].Egress != "T1" || st.Connections[0].Rule != "" {
			t.Errorf("connections: %+v", st.Connections)
		}
		if len(st.Events) == 0 || st.ConfigError != "" {
			t.Errorf("events %d, configError %q", len(st.Events), st.ConfigError)
		}
		if strings.Contains(string(raw), fx.key.SecretKey) {
			t.Error("the secret key is in the status")
		}
	})
}

func TestStartWithUnusableConfig(t *testing.T) {
	for name, content := range map[string]string{
		"not json": "{ this is not json",
		"invalid":  `{"version":1,"keys":[],"wireguard":[],"upstreams":[],"listeners":[],"rules":[],"default":"nope"}`,
	} {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t)
			if err := os.WriteFile(env.ConfigPath, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			s := runServer(t, env)
			c := newAPIClient(t, s)
			c.login("")

			var st Status
			c.want(200, "GET", "/api/status", nil, &st)
			if st.ConfigError == "" {
				t.Fatal("status does not report the config problem")
			}
			if onDisk, _ := os.ReadFile(env.ConfigPath); string(onDisk) != content {
				t.Fatal("the unusable file was modified")
			}

			// Saving a good config through the API replaces it.
			c.want(200, "PUT", "/api/config", config.New(), nil)
			var after Status
			c.want(200, "GET", "/api/status", nil, &after)
			if after.ConfigError != "" {
				t.Errorf("configError still set: %q", after.ConfigError)
			}
			if _, err := config.Load(env.ConfigPath); err != nil {
				t.Errorf("file after the save: %v", err)
			}
		})
	}
}

func TestStartRemovesLoginFromUpstreamURL(t *testing.T) {
	env := newTestEnv(t)
	content := `{"version":1,"keys":[],"wireguard":[],"upstreams":[{"name":"U","type":"http","url":"https://user:secret@127.0.0.1:9/"}],"listeners":[],"rules":[],"default":"direct"}`
	if err := os.WriteFile(env.ConfigPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	s := runServer(t, env)
	c := newAPIClient(t, s)
	c.login("")

	var st Status
	c.want(200, "GET", "/api/status", nil, &st)
	if st.ConfigError != "" {
		t.Fatalf("config not used: %s", st.ConfigError)
	}
	found := false
	for _, e := range st.Events {
		found = found || strings.Contains(e.Message, "upstream U: the login in its url was removed")
	}
	if !found {
		t.Errorf("no event about the removed login: %+v", st.Events)
	}
	raw := c.want(200, "GET", "/api/config", nil, nil)
	if strings.Contains(string(raw), "secret") || !strings.Contains(string(raw), `"https://127.0.0.1:9/"`) {
		t.Errorf("config: %s", raw)
	}
}
