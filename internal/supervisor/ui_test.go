package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"tr-proxy/internal/config"
)

func TestUIIsServed(t *testing.T) {
	s := startServer(t, config.New())
	c := newAPIClient(t, s)

	for path, want := range map[string]string{
		"/":                 "<title>TR Proxy</title>",
		"/ui/app.js":        "function app()",
		"/ui/style.css":     "--accent",
		"/ui/alpine.min.js": "Alpine",
	} {
		status, body := c.do("GET", path, nil)
		if status != 200 || !strings.Contains(string(body), want) {
			t.Errorf("GET %s: %d, body does not contain %q", path, status, want)
		}
	}
	for _, path := range []string{"/nope", "/ui/nope.js", "/ui/VENDOR.md", "/api/nope"} {
		if status, _ := c.do("GET", path, nil); status != 404 {
			t.Errorf("GET %s: %d, want 404", path, status)
		}
	}

	resp, err := http.Get(c.base + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for header, want := range map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
	} {
		if got := resp.Header.Get(header); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to contain %q", header, got, want)
		}
	}
}

// wsMessages collects what the server sends on a WebSocket.
type wsMessage struct {
	Type   string
	Status *Status
	Events []Event
}

func TestWebSocket(t *testing.T) {
	cfg := config.New()
	cfg.Listeners = []config.Listener{{Name: "socks", Type: "socks5", Port: freePort(t)}}
	s := startServer(t, cfg)
	c := newAPIClient(t, s)
	wsURL := fmt.Sprintf("ws://127.0.0.1:%d/api/ws", s.env.AdminPort)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Without a session, and from another origin, the upgrade is refused.
	_, resp, err := websocket.Dial(ctx, wsURL, nil)
	if err == nil || resp == nil || resp.StatusCode != 401 {
		t.Fatalf("no session: err %v, response %v; want 401", err, resp)
	}
	c.login("")
	_, resp, err = websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: c.http,
		HTTPHeader: http.Header{"Origin": {"http://evil.example"}},
	})
	if err == nil || resp == nil || resp.StatusCode != 403 {
		t.Fatalf("cross-origin: err %v, response %v; want 403", err, resp)
	}

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: c.http})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)

	// next reads messages until one of the wanted type arrives.
	next := func(typ string) wsMessage {
		t.Helper()
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				t.Fatalf("waiting for a %q message: %v", typ, err)
			}
			var m wsMessage
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("bad message %s: %v", data, err)
			}
			if m.Type == typ {
				return m
			}
		}
	}

	st := next("status")
	if st.Status == nil || len(st.Status.Listeners) != 1 || st.Status.Listeners[0].Name != "socks" || len(st.Status.Events) != 0 {
		t.Fatalf("first status: %+v", st.Status)
	}
	// The login is in the backlog of events.
	ev := next("events")
	if len(ev.Events) == 0 || !strings.Contains(ev.Events[len(ev.Events)-1].Message, "admin logged in") {
		t.Fatalf("event backlog: %+v", ev.Events)
	}

	// A config change produces an event, a nudge, and shows in the status.
	c.want(201, "POST", "/api/rules", config.Rule{Name: "r", Match: []string{"x.test"}, Via: config.Via{"block"}}, nil)
	ev = next("events")
	if len(ev.Events) != 1 || ev.Events[0].Kind != "config" {
		t.Errorf("events after a change: %+v", ev.Events)
	}
	next("config-changed")
	if again := next("status"); again.Status == nil {
		t.Error("no status after the change")
	}

	// Logging out ends the stream.
	c.want(200, "POST", "/api/logout", nil, nil)
	for {
		if _, _, err := conn.Read(ctx); err != nil {
			if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
				t.Errorf("stream ended with %v, want a policy-violation close", err)
			}
			break
		}
	}
}
