package proxy

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ConnInfo describes one proxied connection for the status view.
type ConnInfo struct {
	ID          uint64    `json:"id"`
	Listener    string    `json:"listener"`
	Client      string    `json:"client"`
	Destination string    `json:"destination"`
	Rule        string    `json:"rule,omitempty"` // empty: the default route
	Egress      string    `json:"egress"`
	Started     time.Time `json:"started"`
	BytesUp     uint64    `json:"bytesUp"`   // client to destination
	BytesDown   uint64    `json:"bytesDown"` // destination to client
}

// Tracker keeps the set of active proxied connections.
type Tracker struct {
	mu    sync.Mutex
	next  uint64
	conns map[uint64]*Tracked
}

func NewTracker() *Tracker {
	return &Tracker{conns: map[uint64]*Tracked{}}
}

// Tracked is one active connection in a Tracker.
type Tracked struct {
	tracker  *Tracker
	info     ConnInfo
	up, down atomic.Uint64
}

// Add registers a connection; call Done when it ends.
func (t *Tracker) Add(info ConnInfo) *Tracked {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	info.ID = t.next
	info.Started = time.Now()
	c := &Tracked{tracker: t, info: info}
	t.conns[info.ID] = c
	return c
}

func (c *Tracked) Done() {
	c.tracker.mu.Lock()
	defer c.tracker.mu.Unlock()
	delete(c.tracker.conns, c.info.ID)
}

// Snapshot returns the active connections, oldest first.
func (t *Tracker) Snapshot() []ConnInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]ConnInfo, 0, len(t.conns))
	for _, c := range t.conns {
		info := c.info
		info.BytesUp, info.BytesDown = c.up.Load(), c.down.Load()
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Count returns the number of active connections on a listener.
func (t *Tracker) Count(listener string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, c := range t.conns {
		if c.info.Listener == listener {
			n++
		}
	}
	return n
}

// counted wraps the destination side of a connection: writes are bytes going
// up, reads are bytes coming down.
type counted struct {
	net.Conn
	c *Tracked
}

func (c counted) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.c.down.Add(uint64(n))
	return n, err
}

func (c counted) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.c.up.Add(uint64(n))
	return n, err
}

func (c counted) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
