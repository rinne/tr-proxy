package proxy

import (
	"io"
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
	// authFailures counts rejected credentials per listener.
	authFailures map[string]uint64
	// refused counts connections turned away at the limit, per listener.
	refused map[string]uint64
}

func NewTracker() *Tracker {
	return &Tracker{conns: map[uint64]*Tracked{}, authFailures: map[string]uint64{}, refused: map[string]uint64{}}
}

// Refuse records one connection turned away because the listener was at its
// connection limit, and returns the new count.
func (t *Tracker) Refuse(listener string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.refused[listener]++
	return t.refused[listener]
}

// Refused returns the number of connections turned away on a listener.
func (t *Tracker) Refused(listener string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.refused[listener]
}

// Len returns the number of active connections.
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// CloseAll closes every active connection's destination side, which ends
// its relay.
func (t *Tracker) CloseAll() {
	t.mu.Lock()
	var closers []io.Closer
	for _, c := range t.conns {
		if c.closer != nil {
			closers = append(closers, c.closer)
		}
	}
	t.mu.Unlock()
	for _, c := range closers {
		c.Close()
	}
}

// AuthFailure records one rejected login on a listener.
func (t *Tracker) AuthFailure(listener string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.authFailures[listener]++
}

// AuthFailures returns the number of rejected logins on a listener.
func (t *Tracker) AuthFailures(listener string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.authFailures[listener]
}

// Tracked is one active connection in a Tracker.
type Tracked struct {
	tracker  *Tracker
	info     ConnInfo
	closer   io.Closer
	up, down atomic.Uint64
}

// Add registers a connection; call Done when it ends. closer, if not nil,
// is what CloseAll closes to end the connection.
func (t *Tracker) Add(info ConnInfo, closer io.Closer) *Tracked {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	info.ID = t.next
	info.Started = time.Now()
	c := &Tracked{tracker: t, info: info, closer: closer}
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
