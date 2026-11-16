// Package proxy implements the client-facing proxy listeners. A listener
// takes a destination from a client, asks the Router where it should go, and
// relays bytes.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"tr-proxy/internal/egress"
)

// How long a client gets to say where it wants to go.
const handshakeTimeout = 30 * time.Second

var (
	// ErrBlocked: the matching rule says block.
	ErrBlocked = errors.New("blocked by rule")
	// ErrUnavailable: the rule's egress, or every entry of its failover
	// list, is down. The connection fails closed.
	ErrUnavailable = errors.New("no healthy egress for this destination")
)

// Route is the Router's decision for one destination.
type Route struct {
	Rule   string // name of the matching rule; empty for the default route
	Egress string // name of the chosen egress
	Dialer egress.Dialer
}

// Router decides how a destination requested on a listener leaves. host is a
// lower-case hostname or an IP address, as the client sent it.
type Router interface {
	Route(listener, host string) (Route, error)
}

// Server serves one listener.
type Server struct {
	Name    string // listener name
	Router  Router
	Tracker *Tracker
	Log     *slog.Logger
	// Auth checks a client's credentials; nil means the listener is open.
	Auth func(username, password string) bool
	// OnAuthFailure, if set, is told about every rejected login.
	OnAuthFailure func(client, username string)
	// IdleTimeout, if set, returns how long a connection may sit without a
	// byte moving before it is closed; 0 means never. It is asked for every
	// new connection.
	IdleTimeout func() time.Duration
}

func (s *Server) idle() time.Duration {
	if s.IdleTimeout == nil {
		return 0
	}
	return s.IdleTimeout()
}

// authenticate checks credentials and counts a failure.
func (s *Server) authenticate(client, username, password string) bool {
	if s.Auth(username, password) {
		return true
	}
	s.Tracker.AuthFailure(s.Name)
	s.Log.Warn("proxy login rejected", "listener", s.Name, "client", client, "username", username)
	if s.OnAuthFailure != nil {
		s.OnAuthFailure(client, username)
	}
	return false
}

// connect routes and dials the destination. On success the returned
// connection counts bytes into the tracked entry, which the caller must
// finish with Done.
func (s *Server) connect(ctx context.Context, client, host string, port int) (net.Conn, *Tracked, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	dest := net.JoinHostPort(host, strconv.Itoa(port))

	route, err := s.Router.Route(s.Name, host)
	if err != nil {
		s.Log.Info("refused", "listener", s.Name, "client", client, "destination", dest, "reason", err.Error())
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, egress.DialTimeout)
	defer cancel()
	up, err := route.Dialer.Dial(ctx, host, port)
	if err != nil {
		s.Log.Info("dial failed", "listener", s.Name, "client", client, "destination", dest,
			"rule", route.Rule, "egress", route.Egress, "err", err.Error())
		if errors.Is(err, egress.ErrLocalDestination) {
			return nil, nil, fmt.Errorf("%w: %w", ErrBlocked, err)
		}
		return nil, nil, fmt.Errorf("via %s: %w", route.Egress, err)
	}

	tracked := s.Tracker.Add(ConnInfo{
		Listener:    s.Name,
		Client:      client,
		Destination: dest,
		Rule:        route.Rule,
		Egress:      route.Egress,
	}, up)
	return counted{Conn: up, c: tracked}, tracked, nil
}
