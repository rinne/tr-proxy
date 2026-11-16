package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// How often an open WebSocket gets a status snapshot. A variable so that
// tests can shorten it.
var wsInterval = time.Second

// wsMessage is one server-to-client message. Type is "status" (a full
// status snapshot without the event log), "events" (event log entries the
// client has not seen yet) or "config-changed" (refetch the config).
type wsMessage struct {
	Type   string `json:"type"`
	Status any    `json:"status,omitempty"`
	Events any    `json:"events,omitempty"`
}

// ws streams status to a logged-in browser. The client sends nothing.
func (a *api) ws(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	token := a.token(r)
	if !a.auth.Valid(token) {
		writeError(w, http.StatusUnauthorized, "not logged in")
		return
	}
	// Accept checks the Origin header against the Host once more.
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	// The client sends nothing; this keeps control frames answered and
	// cancels ctx when the client goes away.
	ctx := c.CloseRead(r.Context())

	send := func(m wsMessage) error {
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return wsjson.Write(wctx, c, m)
	}

	var lastEvent uint64
	generation := a.b.ConfigGeneration()
	tick := time.NewTicker(wsInterval)
	defer tick.Stop()
	for {
		if !a.auth.Valid(token) {
			c.Close(websocket.StatusPolicyViolation, "session ended")
			return
		}
		if err := send(wsMessage{Type: "status", Status: a.b.LiveStatus()}); err != nil {
			return
		}
		if events, n, last := a.b.EventsAfter(lastEvent); n > 0 {
			lastEvent = last
			if err := send(wsMessage{Type: "events", Events: events}); err != nil {
				return
			}
		}
		if g := a.b.ConfigGeneration(); g != generation {
			generation = g
			if err := send(wsMessage{Type: "config-changed"}); err != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
