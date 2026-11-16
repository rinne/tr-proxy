// Package ipc defines what the supervisor and a worker say to each other.
//
// The supervisor writes one Spec as a JSON line to the worker's stdin and then
// keeps stdin open; the worker exits when stdin closes, so workers never
// outlive the supervisor. The worker writes Status JSON lines to stdout; each
// line also counts as a heartbeat. Secrets travel over stdin only, never in
// argv or the environment.
//
// Connections through the tunnel are requested over the worker's unix
// socket; see dial.go.
package ipc

import (
	"time"

	"tr-proxy/internal/config"
)

const (
	// HeartbeatInterval is how often a worker reports.
	HeartbeatInterval = 2 * time.Second
	// HeartbeatTimeout is how long the supervisor waits for a report before
	// it kills the worker.
	HeartbeatTimeout = 10 * time.Second
)

// Spec is everything a worker needs to run one WireGuard connection.
type Spec struct {
	Connection config.WireGuard `json:"connection"`
	SecretKey  string           `json:"secretKey"`
	// Socket is the unix socket path the worker serves dial requests on.
	Socket string `json:"socket"`
}

// Worker states.
const (
	StateStarting   = "starting"   // no handshake yet
	StateUp         = "up"         // handshake is fresh
	StateDegraded   = "degraded"   // handshake is stale or probes are failing
	StateDown       = "down"       // not running, or declared dead
	StateRestarting = "restarting" // waiting to be started again
)

// Status is one report from a worker.
type Status struct {
	State string `json:"state"`
	// LastHandshake is unix seconds; 0 means there has been none.
	LastHandshake int64  `json:"lastHandshake,omitempty"`
	Rx            uint64 `json:"rx"`
	Tx            uint64 `json:"tx"`
	LastError     string `json:"lastError,omitempty"`
}
