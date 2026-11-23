package supervisor

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/netip"
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
	cfg       *config.Config
	limits    config.EffectiveLimits
	table     *router.Table
	dialers   map[string]egress.Dialer // by egress name; block is absent
	tunnels   map[string]bool          // egress names that are WireGuard connections
	upstreams map[string]egress.Upstream
}

func (s *Server) newState(cfg *config.Config) (*state, error) {
	table, err := router.Compile(cfg)
	if err != nil {
		return nil, err
	}
	st := &state{
		cfg:       cfg,
		table:     table,
		limits:    cfg.EffectiveLimits(),
		dialers:   map[string]egress.Dialer{},
		tunnels:   map[string]bool{},
		upstreams: map[string]egress.Upstream{},
	}
	st.dialers[config.EgressDirect] = egress.Direct{AllowLocal: st.limits.AllowLocalDirect}
	for _, w := range cfg.WireGuard {
		st.dialers[w.Name] = egress.Worker{Socket: s.workers.SocketPath(w.Name)}
		st.tunnels[w.Name] = true
	}
	for _, u := range cfg.Upstreams {
		d, err := egress.NewUpstream(u)
		if err != nil {
			return nil, err
		}
		st.dialers[u.Name] = d
		st.upstreams[u.Name] = d
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

// decide applies the rules and picks an egress from the matching rule's
// list: the first healthy one, or failing that the first degraded one. If
// there is neither, the result fails closed.
func (s *Server) decide(listener, host string) (routeResult, egress.Dialer) {
	st := s.state.Load()
	d := st.table.Select(listener, host)
	res := routeResult{Rule: d.Rule, Via: d.Via}

	var degraded string
	for _, name := range d.Via {
		if name == config.EgressBlock {
			res.Egress, res.Err = name, proxy.ErrBlocked
			return res, nil
		}
		switch s.health(st, name) {
		case healthUp:
			res.Egress = name
			return res, s.dialer(st, listener, host, res)
		case healthDegraded:
			if degraded == "" {
				degraded = name
			}
		}
	}
	if degraded != "" {
		res.Egress = degraded
		return res, s.dialer(st, listener, host, res)
	}
	res.Err = fmt.Errorf("%w (%s)", proxy.ErrUnavailable, strings.Join(d.Via, ", "))
	return res, nil
}

// dialer returns the dialer for the chosen egress. A hostname that no
// hostname rule matched and that goes out directly by default is also
// checked against the address rules once it is resolved: if the address
// would be blocked or sent elsewhere, the connection is refused, so that a
// name cannot be used to get around a rule for its address. Names are not
// resolved beforehand, which would ask the container's resolver about
// names meant for a tunnel's DNS.
func (s *Server) dialer(st *state, listener, host string, res routeResult) egress.Dialer {
	d := st.dialers[res.Egress]
	if res.Rule != "" || res.Egress != config.EgressDirect {
		return d
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return d
	}
	return egress.Direct{
		AllowLocal: st.limits.AllowLocalDirect,
		Check: func(ip netip.Addr) error {
			r, _ := s.decide(listener, ip.String())
			if r.Rule == "" || r.Egress == config.EgressDirect {
				return nil
			}
			return fmt.Errorf("%w (%s, rule %q)", egress.ErrRuledAddress, ip, r.Rule)
		},
	}
}

type health int

const (
	healthDown     health = iota // must not be used
	healthDegraded               // usable when nothing better is available
	healthUp
)

// health reports whether an egress can take new connections.
func (s *Server) health(st *state, name string) health {
	switch {
	case st.dialers[name] == nil:
		return healthDown
	case st.tunnels[name]:
		switch s.workers.State(name) {
		case ipc.StateUp:
			return healthUp
		case ipc.StateDegraded:
			return healthDegraded
		}
		return healthDown
	case st.upstreams[name] != nil:
		if !s.upstreams.reachable(name) {
			return healthDown
		}
	}
	return healthUp
}

// router adapts the server to proxy.Router.
type proxyRouter struct {
	s *Server
}

func (r proxyRouter) Route(listener, host string) (proxy.Route, error) {
	res, dialer := r.s.decide(listener, host)
	return proxy.Route{Rule: res.Rule, Egress: res.Egress, Dialer: dialer}, res.Err
}
