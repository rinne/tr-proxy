package proxy

import (
	"net"
	"sync"
	"sync/atomic"
)

// LimitListener wraps a listener so that at most max() connections are open
// at a time. A connection beyond that is closed as soon as it is accepted
// and onRefuse is called. max is asked on every accept, so the limit can
// change while the listener runs. open counts the open connections; give
// a listener that replaces another one the same counter, so that the
// connections the old one accepted still count.
func LimitListener(ln net.Listener, open *atomic.Int64, max func() int, onRefuse func()) net.Listener {
	return &limitListener{Listener: ln, open: open, max: max, onRefuse: onRefuse}
}

type limitListener struct {
	net.Listener
	open     *atomic.Int64
	max      func() int
	onRefuse func()
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.open.Add(1) > int64(l.max()) {
			l.open.Add(-1)
			// Count first, then close: by the time the client sees the
			// connection go away, the refusal is on record.
			l.onRefuse()
			c.Close()
			continue
		}
		return &limitConn{Conn: c, l: l}, nil
	}
}

// limitConn gives its slot back when it is closed.
type limitConn struct {
	net.Conn
	l    *limitListener
	once sync.Once
}

func (c *limitConn) Close() error {
	c.once.Do(func() { c.l.open.Add(-1) })
	return c.Conn.Close()
}

func (c *limitConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}
