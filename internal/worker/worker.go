// Package worker is the per-tunnel process: one WireGuard tunnel, a unix
// socket on which the supervisor asks for connections through it, and status
// reports on stdout.
package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"tr-proxy/internal/ipc"
	"tr-proxy/internal/netutil"
	"tr-proxy/internal/tunnel"
)

var errSupervisorGone = errors.New("supervisor went away")

// Run reads the spec from stdin, brings the tunnel up and serves until the
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

	// The supervisor holds stdin open for as long as it lives.
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go func() {
		io.Copy(io.Discard, stdin)
		cancel(errSupervisorGone)
	}()

	tun, err := tunnel.Up(ctx, spec.Connection, spec.SecretKey, log)
	if err != nil {
		return err
	}
	defer tun.Close()

	os.Remove(spec.Socket)
	ln, err := net.Listen("unix", spec.Socket)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", spec.Socket, err)
	}
	defer ln.Close()
	if err := os.Chmod(spec.Socket, 0o600); err != nil {
		return err
	}
	go serve(ctx, ln, tun, log)
	log.Info("tunnel up", "endpoint", spec.Connection.Peer.Endpoint)

	probe := newProber(tun, spec.Connection)
	go probe.run(ctx)

	out := json.NewEncoder(os.Stdout)
	report := func() error { return out.Encode(status(tun, probe)) }
	if err := report(); err != nil {
		return err
	}
	tick := time.NewTicker(ipc.HeartbeatInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			if errors.Is(context.Cause(ctx), errSupervisorGone) {
				return errSupervisorGone
			}
			log.Info("worker stopping")
			return nil
		case <-tick.C:
			if err := report(); err != nil {
				return err
			}
		}
	}
}

func status(tun *tunnel.Tunnel, probe *prober) ipc.Status {
	var st ipc.Status
	st.State, st.Probe = probe.snapshot()
	st.LastError = st.Probe.Error
	if stats, err := tun.Stats(); err == nil {
		st.Rx, st.Tx = stats.Rx, stats.Tx
		if !stats.LastHandshake.IsZero() {
			st.LastHandshake = stats.LastHandshake.Unix()
		}
	}
	return st
}

func serve(ctx context.Context, ln net.Listener, tun *tunnel.Tunnel, log *slog.Logger) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				log.Error("dial socket closed", "err", err)
			}
			return
		}
		go handle(ctx, c, tun)
	}
}

func handle(ctx context.Context, c net.Conn, tun *tunnel.Tunnel) {
	defer c.Close()

	c.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := ipc.ReadRequest(c)
	if err != nil {
		return
	}
	c.SetDeadline(time.Time{})

	dctx, cancel := context.WithTimeout(ctx, ipc.DialTimeout)
	up, err := tun.Dial(dctx, req.Host, req.Port)
	cancel()
	if err != nil {
		ipc.WriteResponse(c, err)
		return
	}
	defer up.Close()
	if err := ipc.WriteResponse(c, nil); err != nil {
		return
	}
	netutil.Relay(c, up)
}
