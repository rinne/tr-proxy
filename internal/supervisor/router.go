package supervisor

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"

	"tr-proxy/internal/config"
	"tr-proxy/internal/egress"
	"tr-proxy/internal/ipc"
	"tr-proxy/internal/proxy"
	"tr-proxy/internal/router"
)

// state is everything derived from one config. It is replaced as a whole
// when the config changes.
type state struct {
	cfg     *config.Config
	table   *router.Table
	dialers map[string]egress.Dialer // by egress name; block is absent
	tunnels map[string]bool          // egress names that are WireGuard connections
}

func (s *Server) newState(cfg *config.Config) (*state, error) {
	table, err := router.Compile(cfg)
	if err != nil {
		return nil, err
	}
	st := &state{
		cfg:     cfg,
		table:   table,
		dialers: map[string]egress.Dialer{config.EgressDirect: egress.Direct{}},
		tunnels: map[string]bool{},
	}
	for _, w := range cfg.WireGuard {
		st.dialers[w.Name] = egress.Worker{Socket: s.workers.SocketPath(w.Name)}
		st.tunnels[w.Name] = true
	}
	for _, u := range cfg.Upstreams {
		d, err := egress.NewHTTPProxy(u)
		if err != nil {
			return nil, err
		}
		st.dialers[u.Name] = d
	}
	return st, nil
}

// listenerAuth returns the credential check for a listener, or nil if the
// listener is open. Every configured user is compared, in constant time, so
// that the answer's timing does not depend on which user matched.
func listenerAuth(l config.Listener) func(username, password string) bool {
	if l.Auth == nil {
		return nil
	}
	type cred struct{ user, pass [sha256.Size]byte }
	creds := make([]cred, len(l.Auth.Users))
	for i, u := range l.Auth.Users {
		creds[i] = cred{sha256.Sum256([]byte(u.Username)), sha256.Sum256([]byte(u.Password))}
	}
	return func(username, password string) bool {
		user, pass := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(password))
		ok := 0
		for _, c := range creds {
			ok |= subtle.ConstantTimeCompare(user[:], c.user[:]) & subtle.ConstantTimeCompare(pass[:], c.pass[:])
		}
		return ok == 1
	}
}

// routeResult is a routing decision with the reason, for the proxy and for
// the route test in the admin API.
type routeResult struct {
	Rule   string   // matching rule; empty for a default
	Via    []string // the rule's egress list
	Egress string   // the chosen egress; empty when none is usable
	Err    error    // proxy.ErrBlocked, proxy.ErrUnavailable or nil
}

// decide applies the rules and picks the first healthy egress of the
// matching rule's list. If none is healthy the result fails closed.
func (s *Server) decide(listener, host string) (routeResult, egress.Dialer) {
	st := s.state.Load()
	d := st.table.Select(listener, host)
	res := routeResult{Rule: d.Rule, Via: d.Via}

	for _, name := range d.Via {
		if name == config.EgressBlock {
			res.Egress, res.Err = name, proxy.ErrBlocked
			return res, nil
		}
		dialer, ok := st.dialers[name]
		if !ok || !s.healthy(st, name) {
			continue
		}
		res.Egress = name
		return res, dialer
	}
	res.Err = fmt.Errorf("%w (%s)", proxy.ErrUnavailable, strings.Join(d.Via, ", "))
	return res, nil
}

// healthy reports whether an egress can take new connections.
func (s *Server) healthy(st *state, name string) bool {
	if st.tunnels[name] {
		return s.workers.State(name) == ipc.StateUp
	}
	return true
}

// router adapts the server to proxy.Router.
type proxyRouter struct {
	s *Server
}

func (r proxyRouter) Route(listener, host string) (proxy.Route, error) {
	res, dialer := r.s.decide(listener, host)
	return proxy.Route{Rule: res.Rule, Egress: res.Egress, Dialer: dialer}, res.Err
}
