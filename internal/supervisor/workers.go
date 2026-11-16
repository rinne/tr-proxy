package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"tr-proxy/internal/config"
	"tr-proxy/internal/ipc"
)

const (
	backoffMin = time.Second
	backoffMax = time.Minute
	// A worker that ran this long is considered to have been healthy, so the
	// next restart starts from backoffMin again.
	backoffReset = time.Minute
	// How long a worker gets to exit after SIGTERM before it is killed.
	stopGrace = 5 * time.Second
)

// WorkerStatus is the supervisor's view of one worker.
type WorkerStatus struct {
	Name          string    `json:"name"`
	State         string    `json:"state"`
	PID           int       `json:"pid,omitempty"`
	Restarts      int       `json:"restarts"`
	LastError     string    `json:"lastError,omitempty"`
	LastHeartbeat time.Time `json:"lastHeartbeat,omitzero"`
	LastHandshake time.Time `json:"lastHandshake,omitzero"`
	Rx            uint64    `json:"rx"`
	Tx            uint64    `json:"tx"`
}

// Workers runs one worker process per WireGuard connection and restarts any
// that exit or stop sending heartbeats.
type Workers struct {
	exe    string
	runDir string
	log    *slog.Logger
	wg     sync.WaitGroup

	mu     sync.Mutex
	status map[string]*WorkerStatus
}

// NewWorkers prepares a worker set whose dial sockets live in runDir.
func NewWorkers(log *slog.Logger, runDir string) (*Workers, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &Workers{exe: exe, runDir: runDir, log: log, status: map[string]*WorkerStatus{}}, nil
}

// SocketPath is where the named connection's worker serves dial requests.
func (w *Workers) SocketPath(name string) string {
	return filepath.Join(w.runDir, name+".sock")
}

// Start launches a supervised worker for every connection in the config. The
// workers stop when ctx is cancelled; Wait blocks until they have.
func (w *Workers) Start(ctx context.Context, c *config.Config) {
	for _, conn := range c.WireGuard {
		key, _ := c.KeyByName(conn.LocalKey) // presence is checked by Validate
		spec := ipc.Spec{Connection: conn, SecretKey: key.SecretKey, Socket: w.SocketPath(conn.Name)}

		w.mu.Lock()
		w.status[conn.Name] = &WorkerStatus{Name: conn.Name, State: ipc.StateStarting}
		w.mu.Unlock()

		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			w.supervise(ctx, spec)
		}()
	}
}

func (w *Workers) Wait() { w.wg.Wait() }

// Status returns a snapshot of all workers.
func (w *Workers) Status() []WorkerStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]WorkerStatus, 0, len(w.status))
	for _, s := range w.status {
		out = append(out, *s)
	}
	return out
}

// State returns the named worker's state, or StateDown if there is none.
func (w *Workers) State(name string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := w.status[name]; ok {
		return s.State
	}
	return ipc.StateDown
}

func (w *Workers) update(name string, f func(s *WorkerStatus)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f(w.status[name])
}

// supervise keeps one worker running until ctx is cancelled.
func (w *Workers) supervise(ctx context.Context, spec ipc.Spec) {
	name := spec.Connection.Name
	log := w.log.With("connection", name)
	backoff := backoffMin

	for {
		started := time.Now()
		err := w.runOnce(ctx, spec, log)
		if ctx.Err() != nil {
			return
		}

		if time.Since(started) >= backoffReset {
			backoff = backoffMin
		}
		w.update(name, func(s *WorkerStatus) {
			s.State = ipc.StateRestarting
			s.PID = 0
			s.Restarts++
			s.LastError = fmt.Sprint(err)
		})
		log.Warn("worker exited; restarting", "err", err, "in", backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, backoffMax)
	}
}

// runOnce runs one worker process to completion. It returns when the process
// has exited: on its own, because ctx was cancelled, or because it was killed
// for missing heartbeats.
func (w *Workers) runOnce(ctx context.Context, spec ipc.Spec, log *slog.Logger) error {
	name := spec.Connection.Name

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	cmd := exec.CommandContext(ctx, w.exe, "worker")
	cmd.Env = []string{} // workers get no environment; the spec is all they need
	cmd.Stderr = os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopGrace

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	w.update(name, func(s *WorkerStatus) {
		s.State = ipc.StateStarting
		s.PID = cmd.Process.Pid
	})
	log.Info("worker started", "pid", cmd.Process.Pid)

	// The spec goes first; stdin then stays open until the process is gone,
	// which is how the worker knows the supervisor is alive.
	if err := json.NewEncoder(stdin).Encode(spec); err != nil {
		cancel(fmt.Errorf("send spec: %w", err))
	}

	watchdog := time.AfterFunc(ipc.HeartbeatTimeout, func() {
		cancel(fmt.Errorf("no heartbeat for %s", ipc.HeartbeatTimeout))
	})
	defer watchdog.Stop()

	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		var st ipc.Status
		if err := json.Unmarshal(lines.Bytes(), &st); err != nil {
			log.Warn("worker sent a malformed status line", "err", err)
			continue
		}
		watchdog.Reset(ipc.HeartbeatTimeout)
		w.update(name, func(s *WorkerStatus) {
			s.State = st.State
			s.LastError = st.LastError
			s.LastHeartbeat = time.Now()
			s.LastHandshake = time.Time{}
			if st.LastHandshake > 0 {
				s.LastHandshake = time.Unix(st.LastHandshake, 0)
			}
			s.Rx, s.Tx = st.Rx, st.Tx
		})
	}

	waitErr := cmd.Wait()
	stdin.Close()
	if cause := context.Cause(ctx); cause != nil && cause != context.Canceled {
		return cause
	}
	if waitErr == nil {
		return fmt.Errorf("worker exited without an error")
	}
	return waitErr
}
