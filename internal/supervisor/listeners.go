package supervisor

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"tr-proxy/internal/config"
	"tr-proxy/internal/proxy"
)

// listeners is the set of running proxy listeners.
type listeners struct {
	mu     sync.Mutex
	active map[string]*activeListener
	// open counts each listener's open connections. It outlives the
	// socket, so that a listener that is reopened after a config change
	// still counts the connections it accepted before.
	open map[string]*atomic.Int64
}

func (ls *listeners) counter(name string) *atomic.Int64 {
	if ls.open == nil {
		ls.open = map[string]*atomic.Int64{}
	}
	c, ok := ls.open[name]
	if !ok {
		c = new(atomic.Int64)
		ls.open[name] = c
	}
	return c
}

type activeListener struct {
	cfg config.Listener
	ln  net.Listener // nil if the port could not be opened
	err string
}

// socketConfig is the part of a listener's config that needs a new socket or
// server when it changes. The default route is read from the state on every
// connection, so it is left out.
func socketConfig(l config.Listener) config.Listener {
	l.Default = ""
	return l
}

// syncListeners makes the running listeners match want: listeners that are
// gone, disabled or changed are closed, missing ones (and ones that failed
// to open before) are started, the rest keep running. Connections already
// accepted are not interrupted.
func (s *Server) syncListeners(ctx context.Context, want []config.Listener) {
	ls := &s.listeners
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.active == nil {
		ls.active = map[string]*activeListener{}
	}

	// A disabled listener is treated like one that is not there: it is
	// closed if it runs and not started if it does not.
	wanted := map[string]config.Listener{}
	for _, l := range want {
		if !l.Disabled {
			wanted[l.Name] = l
		}
	}
	for name, a := range ls.active {
		l, ok := wanted[name]
		if ok && a.ln != nil && reflect.DeepEqual(socketConfig(l), socketConfig(a.cfg)) {
			a.cfg = l
			continue
		}
		if a.ln != nil {
			a.ln.Close()
			s.log.Info("listener stopped", "listener", name)
		}
		delete(ls.active, name)
	}

	for _, l := range want {
		if _, ok := ls.active[l.Name]; ok || l.Disabled {
			continue
		}
		a := &activeListener{cfg: l}
		ls.active[l.Name] = a

		ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(l.Port)))
		if err != nil {
			a.err = err.Error()
			s.log.Error("listener failed to start", "listener", l.Name, "err", err)
			s.events.Add("listener", fmt.Sprintf("%s: failed to start: %v", l.Name, err))
			continue
		}
		name := l.Name
		// The limit and the idle timeout are read from the current config
		// each time, so changing them needs no new listener.
		ln = proxy.LimitListener(ln, ls.counter(name),
			func() int { return s.state.Load().limits.MaxConnections },
			func() { s.refused(name) })
		a.ln = ln

		srv := &proxy.Server{
			Name:    name,
			Router:  proxyRouter{s},
			Tracker: s.tracker,
			Log:     s.log,
			Auth:    listenerAuth(l),
			OnAuthFailure: func(client, username string) {
				s.events.Add("auth", fmt.Sprintf("%s: login rejected for %q from %s", name, username, client))
			},
			IdleTimeout: func() time.Duration { return s.state.Load().limits.IdleTimeout },
		}
		serve := srv.ServeSOCKS5
		if l.Type == "http" {
			serve = srv.ServeHTTP
		}
		go serve(ctx, ln)
		s.log.Info("listener started", "listener", l.Name, "type", l.Type, "port", l.Port)
	}
}

// refused counts a connection turned away at the limit. The event log gets
// the first one and then every thousandth, so that a flood cannot push
// everything else out of it.
func (s *Server) refused(listener string) {
	n := s.tracker.Refuse(listener)
	if n == 1 || n%1000 == 0 {
		limit := s.state.Load().limits.MaxConnections
		s.log.Warn("connection limit reached", "listener", listener, "limit", limit, "refused", n)
		s.events.Add("listener", fmt.Sprintf("%s: at its limit of %d connections; %d refused so far", listener, limit, n))
	}
}

func (s *Server) closeListeners() {
	s.listeners.mu.Lock()
	defer s.listeners.mu.Unlock()
	for _, a := range s.listeners.active {
		if a.ln != nil {
			a.ln.Close()
		}
	}
	s.listeners.active = nil
}

// listenerErrors returns the start-up error of each listener that has one.
func (s *Server) listenerErrors() map[string]string {
	s.listeners.mu.Lock()
	defer s.listeners.mu.Unlock()
	out := map[string]string{}
	for name, a := range s.listeners.active {
		if a.err != "" {
			out[name] = a.err
		}
	}
	return out
}
