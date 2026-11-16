// Package worker is the per-tunnel process. For now it is a stub that speaks
// the supervisor protocol (spec in, heartbeats out) without bringing up a
// tunnel; the WireGuard device and the dialer socket come next.
package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"tr-proxy/internal/ipc"
)

// Run reads the spec from stdin, then reports status on stdout until the
// context is cancelled or stdin closes.
func Run(ctx context.Context, log *slog.Logger) error {
	stdin := bufio.NewReader(os.Stdin)
	line, err := stdin.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read spec: %w", err)
	}
	var spec ipc.Spec
	if err := json.Unmarshal(line, &spec); err != nil {
		return fmt.Errorf("parse spec: %w", err)
	}
	log = log.With("connection", spec.Connection.Name)
	log.Info("worker started (stub: no tunnel yet)", "endpoint", spec.Connection.Peer.Endpoint)

	// The supervisor holds stdin open for as long as it lives.
	parentGone := make(chan struct{})
	go func() {
		io.Copy(io.Discard, stdin)
		close(parentGone)
	}()

	out := json.NewEncoder(os.Stdout)
	report := func() error {
		return out.Encode(ipc.Status{State: ipc.StateStarting})
	}
	if err := report(); err != nil {
		return err
	}

	tick := time.NewTicker(ipc.HeartbeatInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("worker stopping")
			return nil
		case <-parentGone:
			return fmt.Errorf("supervisor went away")
		case <-tick.C:
			if err := report(); err != nil {
				return err
			}
		}
	}
}
