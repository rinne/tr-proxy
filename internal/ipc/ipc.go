// Package ipc defines what the supervisor and a worker say to each other.
//
// The supervisor writes one Spec as a JSON line to the worker's stdin and then
// keeps stdin open; the worker exits when stdin closes, so workers never
// outlive the supervisor. The worker writes Status JSON lines to stdout; each
// line also counts as a heartbeat. Secrets travel over stdin only, never in
// argv or the environment.
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
}

// Worker states.
const (
	StateStarting = "starting"
	StateUp       = "up"
	StateDegraded = "degraded"
	StateDown     = "down"
)

// Status is one report from a worker.
type Status struct {
	State     string `json:"state"`
	LastError string `json:"lastError,omitempty"`
}
