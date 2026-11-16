package supervisor

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"

	"tr-proxy/internal/config"
	"tr-proxy/internal/proxy"
)

// listeners is the set of running proxy listeners.
type listeners struct {
	mu     sync.Mutex
	active map[string]*activeListener
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
// gone or changed are closed, missing ones (and ones that failed to open
// before) are started, the rest keep running. Connections already accepted
// are not interrupted.
func (s *Server) syncListeners(ctx context.Context, want []config.Listener) {
	ls := &s.listeners
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.active == nil {
		ls.active = map[string]*activeListener{}
	}

	wanted := map[string]config.Listener{}
	for _, l := range want {
		wanted[l.Name] = l
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
		if _, ok := ls.active[l.Name]; ok {
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
		a.ln = ln

		name := l.Name
		srv := &proxy.Server{
			Name:    name,
			Router:  proxyRouter{s},
			Tracker: s.tracker,
			Log:     s.log,
			Auth:    listenerAuth(l),
			OnAuthFailure: func(client, username string) {
				s.events.Add("auth", fmt.Sprintf("%s: login rejected for %q from %s", name, username, client))
			},
		}
		serve := srv.ServeSOCKS5
		if l.Type == "http" {
			serve = srv.ServeHTTP
		}
		go serve(ctx, ln)
		s.log.Info("listener started", "listener", l.Name, "type", l.Type, "port", l.Port)
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
