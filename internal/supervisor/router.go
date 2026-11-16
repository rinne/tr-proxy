package supervisor

import (
	"fmt"

	"tr-proxy/internal/config"
	"tr-proxy/internal/egress"
	"tr-proxy/internal/proxy"
)

// router sends everything to the config's default egress. Rules come next.
type router struct {
	s *Server
}

func (r router) Route(listener, host string) (proxy.Route, error) {
	return r.s.egressRoute("", r.s.cfg.Default)
}

// egressRoute turns an egress name into a route.
func (s *Server) egressRoute(rule, name string) (proxy.Route, error) {
	route := proxy.Route{Rule: rule, Egress: name}
	switch name {
	case config.EgressBlock:
		return route, proxy.ErrBlocked
	case config.EgressDirect:
		route.Dialer = egress.Direct{}
		return route, nil
	}
	for _, w := range s.cfg.WireGuard {
		if w.Name == name {
			route.Dialer = egress.Worker{Socket: s.workers.SocketPath(name)}
			return route, nil
		}
	}
	return route, fmt.Errorf("egress %q is not implemented yet", name)
}
