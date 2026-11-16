package supervisor

import (
	"time"

	"tr-proxy/internal/proxy"
)

// Status is the live status served by GET /api/status.
type Status struct {
	Time time.Time `json:"time"`
	// Version is the version of the running build.
	Version string `json:"version,omitempty"`
	// ConfigError is set while the server runs on an empty config because
	// the config file could not be used at start-up.
	ConfigError string           `json:"configError,omitempty"`
	Tunnels     []TunnelStatus   `json:"tunnels"`
	Upstreams   []UpstreamStatus `json:"upstreams"`
	Listeners   []ListenerStatus `json:"listeners"`
	Connections []proxy.ConnInfo `json:"connections"`
	// Events is left out of the WebSocket's snapshots, which send events
	// separately.
	Events []Event `json:"events,omitempty"`
}

type TunnelStatus struct {
	WorkerStatus
	Endpoint string `json:"endpoint"`
}

type ListenerStatus struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Port         int    `json:"port"`
	Auth         bool   `json:"auth"`
	Disabled     bool   `json:"disabled"`
	Connections  int    `json:"connections"`
	AuthFailures uint64 `json:"authFailures"`
	// Refused counts connections closed because the listener was at its
	// connection limit.
	Refused uint64 `json:"refused"`
	// Error is set when the listener could not be started.
	Error string `json:"error,omitempty"`
}

// Status returns the live status with the event log.
func (s *Server) Status() any {
	st := s.status()
	st.Events = s.events.Snapshot()
	return st
}

// LiveStatus returns the live status without the event log.
func (s *Server) LiveStatus() any { return s.status() }

func (s *Server) EventsAfter(seq uint64) (any, int, uint64) {
	list, last := s.events.After(seq)
	return list, len(list), last
}

func (s *Server) ConfigGeneration() uint64 { return s.generation.Load() }

func (s *Server) status() Status {
	cfg := s.state.Load().cfg
	out := Status{
		Time:        time.Now(),
		Version:     s.version,
		Tunnels:     []TunnelStatus{},
		Upstreams:   []UpstreamStatus{},
		Listeners:   []ListenerStatus{},
		Connections: s.tracker.Snapshot(),
	}
	if msg := s.configError.Load(); msg != nil {
		out.ConfigError = *msg
	}

	endpoints := map[string]string{}
	for _, w := range cfg.WireGuard {
		endpoints[w.Name] = w.Peer.Endpoint
	}
	for _, ws := range s.workers.Status() {
		out.Tunnels = append(out.Tunnels, TunnelStatus{WorkerStatus: ws, Endpoint: endpoints[ws.Name]})
	}
	for _, u := range cfg.Upstreams {
		out.Upstreams = append(out.Upstreams, s.upstreams.Status(u.Name))
	}
	errs := s.listenerErrors()
	for _, l := range cfg.Listeners {
		out.Listeners = append(out.Listeners, ListenerStatus{
			Name:         l.Name,
			Type:         l.Type,
			Port:         l.Port,
			Auth:         l.Auth != nil,
			Disabled:     l.Disabled,
			Connections:  s.tracker.Count(l.Name),
			AuthFailures: s.tracker.AuthFailures(l.Name),
			Refused:      s.tracker.Refused(l.Name),
			Error:        errs[l.Name],
		})
	}
	return out
}
