// Package netutil holds small networking helpers shared by the supervisor
// and the workers.
package netutil

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

// Relay copies bytes both ways between a and b until both directions are
// done, then closes both. A clean end of one direction is passed on as a
// half-close where the connection supports it; an error tears both down.
//
// With idle > 0 the relay ends when no byte has moved in either direction
// for that long, or when a write has been stuck for that long. With idle = 0
// it never times out. It returns the byte counts a→b and b→a.
func Relay(a, b net.Conn, idle time.Duration) (aToB, bToA int64) {
	var wg sync.WaitGroup
	var last atomic.Int64 // time of the last byte in either direction
	last.Store(time.Now().UnixNano())

	pipe := func(dst, src net.Conn, n *int64) {
		defer wg.Done()
		err := copyIdle(dst, src, n, idle, &last)
		if cw, ok := dst.(closeWriter); ok && err == nil {
			cw.CloseWrite()
			return
		}
		a.Close()
		b.Close()
	}
	wg.Add(2)
	go pipe(b, a, &aToB)
	go pipe(a, b, &bToA)
	wg.Wait()
	a.Close()
	b.Close()
	return aToB, bToA
}

// copyIdle copies src to dst until src ends. A direction that is quiet does
// not time out on its own: only when both directions have been quiet for
// idle does the copy fail.
func copyIdle(dst, src net.Conn, n *int64, idle time.Duration, last *atomic.Int64) error {
	if idle <= 0 {
		var err error
		*n, err = io.Copy(dst, src)
		return err
	}
	buf := make([]byte, 32<<10)
	for {
		src.SetReadDeadline(time.Now().Add(idle))
		nr, rerr := src.Read(buf)
		if nr > 0 {
			last.Store(time.Now().UnixNano())
			dst.SetWriteDeadline(time.Now().Add(idle))
			nw, werr := dst.Write(buf[:nr])
			*n += int64(nw)
			if werr != nil {
				return werr
			}
		}
		if rerr == nil {
			continue
		}
		if rerr == io.EOF {
			return nil
		}
		if errors.Is(rerr, os.ErrDeadlineExceeded) && time.Since(time.Unix(0, last.Load())) < idle {
			continue // the other direction is busy
		}
		return rerr
	}
}

// IdleConn wraps a connection so that a read or write that makes no
// progress for the given time fails. Use it where the bytes are moved by
// code that cannot be told about idleness, such as net/http.
type IdleConn struct {
	net.Conn
	Idle time.Duration
}

func (c *IdleConn) Read(p []byte) (int, error) {
	if c.Idle > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.Idle))
	}
	return c.Conn.Read(p)
}

func (c *IdleConn) Write(p []byte) (int, error) {
	if c.Idle > 0 {
		c.Conn.SetWriteDeadline(time.Now().Add(c.Idle))
	}
	return c.Conn.Write(p)
}
