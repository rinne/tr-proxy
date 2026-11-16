// Package netutil holds small networking helpers shared by the supervisor
// and the workers.
package netutil

import (
	"io"
	"net"
	"sync"
)

type closeWriter interface {
	CloseWrite() error
}

// Relay copies bytes both ways between a and b until both directions are
// done, then closes both. A clean end of one direction is passed on as a
// half-close where the connection supports it; an error tears both down. It
// returns the byte counts a→b and b→a.
func Relay(a, b net.Conn) (aToB, bToA int64) {
	var wg sync.WaitGroup
	pipe := func(dst, src net.Conn, n *int64) {
		defer wg.Done()
		var err error
		*n, err = io.Copy(dst, src)
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
