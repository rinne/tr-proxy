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
	"reflect"
	"sort"
	"sync"
	"syscall"
	"time"

	"tr-proxy/internal/config"
	"tr-proxy/internal/ipc"
)

const (
	backoffMin = time.Second
	backoffMax = time.Minute
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
	Probe         ipc.Probe `json:"probe"`
}

// Workers runs one worker process per WireGuard connection and restarts any
// that exit, stop sending heartbeats or report their tunnel down.
type Workers struct {
	exe     string
	runDir  string
	log     *slog.Logger
	onEvent func(kind, message string)
	wg      sync.WaitGroup

	// syncMu serializes Sync and Restart.
	syncMu sync.Mutex

	mu      sync.Mutex
	ctx     context.Context
	running map[string]*workerProc
}

// workerProc is one supervised connection.
type workerProc struct {
	spec   ipc.Spec
	cancel context.CancelFunc
	done   chan struct{}
	status WorkerStatus // guarded by Workers.mu
}

// NewWorkers prepares a worker set whose dial sockets live in runDir.
func NewWorkers(log *slog.Logger, runDir string, onEvent func(kind, message string)) (*Workers, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if onEvent == nil {
		onEvent = func(string, string) {}
	}
	return &Workers{exe: exe, runDir: runDir, log: log, onEvent: onEvent, running: map[string]*workerProc{}}, nil
}

// SocketPath is where the named connection's worker serves dial requests.
func (w *Workers) SocketPath(name string) string {
	return filepath.Join(w.runDir, name+".sock")
}

// Specs returns the worker specs for a validated config.
func (w *Workers) Specs(c *config.Config) []ipc.Spec {
	specs := make([]ipc.Spec, 0, len(c.WireGuard))
	for _, conn := range c.WireGuard {
		key, _ := c.KeyByName(conn.LocalKey)
		specs = append(specs, ipc.Spec{Connection: conn, SecretKey: key.SecretKey, Socket: w.SocketPath(conn.Name)})
	}
	return specs
}

// Start sets the context all workers live under. Workers stop when it is
// cancelled; Wait blocks until they have.
func (w *Workers) Start(ctx context.Context) {
	w.mu.Lock()
	w.ctx = ctx
	w.mu.Unlock()
}

// Sync makes the running workers match specs: workers whose connection is
// gone or changed are stopped, missing ones are started, and the rest are
// left alone.
func (w *Workers) Sync(specs []ipc.Spec) {
	w.syncMu.Lock()
	defer w.syncMu.Unlock()

	want := map[string]ipc.Spec{}
	for _, s := range specs {
		want[s.Connection.Name] = s
	}

	var stopping []*workerProc
	w.mu.Lock()
	for name, wk := range w.running {
		if s, ok := want[name]; !ok || !reflect.DeepEqual(s, wk.spec) {
			stopping = append(stopping, wk)
			delete(w.running, name)
		}
	}
	w.mu.Unlock()
	// The old process must be gone before a new one takes over its socket.
	for _, wk := range stopping {
		wk.cancel()
	}
	for _, wk := range stopping {
		<-wk.done
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range specs {
		if _, ok := w.running[s.Connection.Name]; !ok {
			w.startLocked(s, 0)
		}
	}
}

// Restart stops and starts the named worker. It reports whether there is
// such a worker.
func (w *Workers) Restart(name string) bool {
	w.syncMu.Lock()
	defer w.syncMu.Unlock()

	w.mu.Lock()
	wk, ok := w.running[name]
	if ok {
		delete(w.running, name)
	}
	w.mu.Unlock()
	if !ok {
		return false
	}
	wk.cancel()
	<-wk.done

	w.mu.Lock()
	defer w.mu.Unlock()
	w.startLocked(wk.spec, wk.status.Restarts+1)
	w.onEvent("tunnel", fmt.Sprintf("%s: restarted on request", name))
	return true
}

func (w *Workers) startLocked(spec ipc.Spec, restarts int) {
	if w.ctx == nil || w.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(w.ctx)
	wk := &workerProc{
		spec:   spec,
		cancel: cancel,
		done:   make(chan struct{}),
		status: WorkerStatus{
			Name:     spec.Connection.Name,
			State:    ipc.StateStarting,
			Restarts: restarts,
			Probe:    ipc.Probe{Type: spec.Connection.EffectiveProbe().Type},
		},
	}
	w.running[spec.Connection.Name] = wk
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer close(wk.done)
		defer cancel()
		w.supervise(ctx, wk)
	}()
}

func (w *Workers) Wait() { w.wg.Wait() }

// Status returns a snapshot of all workers, sorted by name.
func (w *Workers) Status() []WorkerStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]WorkerStatus, 0, len(w.running))
	for _, wk := range w.running {
		out = append(out, wk.status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// State returns the named worker's state, or StateDown if there is none.
func (w *Workers) State(name string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if wk, ok := w.running[name]; ok {
		return wk.status.State
	}
	return ipc.StateDown
}

func (w *Workers) update(wk *workerProc, f func(s *WorkerStatus)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f(&wk.status)
}

// supervise keeps one worker running until ctx is cancelled.
func (w *Workers) supervise(ctx context.Context, wk *workerProc) {
	name := wk.spec.Connection.Name
	log := w.log.With("connection", name)
	backoff := backoffMin

	for {
		wasUp, err := w.runOnce(ctx, wk, log)
		if ctx.Err() != nil {
			return
		}

		// A worker whose tunnel worked starts over with the shortest delay.
		if wasUp {
			backoff = backoffMin
		}
		w.update(wk, func(s *WorkerStatus) {
			s.State = ipc.StateRestarting
			s.PID = 0
			s.Restarts++
			s.LastError = fmt.Sprint(err)
			s.Probe = ipc.Probe{Type: s.Probe.Type}
		})
		log.Warn("worker exited; restarting", "err", err, "in", backoff)
		w.onEvent("tunnel", fmt.Sprintf("%s: %v; restarting in %s", name, err, backoff))

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, backoffMax)
	}
}

// runOnce runs one worker process to completion. It returns when the process
// has exited: on its own, because ctx was cancelled, because it was killed
// for missing heartbeats, or because it reported its tunnel down.
func (w *Workers) runOnce(ctx context.Context, wk *workerProc, log *slog.Logger) (wasUp bool, err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	cmd := exec.CommandContext(ctx, w.exe, "worker")
	cmd.Env = []string{} // workers get no environment; the spec is all they need
	cmd.Stderr = os.Stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopGrace

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err := cmd.Start(); err != nil {
		return false, err
	}
	w.update(wk, func(s *WorkerStatus) {
		s.State = ipc.StateStarting
		s.PID = cmd.Process.Pid
	})
	log.Info("worker started", "pid", cmd.Process.Pid)

	// The spec goes first; stdin then stays open until the process is gone,
	// which is how the worker knows the supervisor is alive.
	if err := json.NewEncoder(stdin).Encode(wk.spec); err != nil {
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
		var previous string
		w.update(wk, func(s *WorkerStatus) {
			previous = s.State
			s.State = st.State
			s.LastError = st.LastError
			s.LastHeartbeat = time.Now()
			s.LastHandshake = time.Time{}
			if st.LastHandshake > 0 {
				s.LastHandshake = time.Unix(st.LastHandshake, 0)
			}
			s.Rx, s.Tx = st.Rx, st.Tx
			s.Probe = st.Probe
		})
		if st.State != previous {
			w.onEvent("tunnel", fmt.Sprintf("%s: %s", wk.spec.Connection.Name, st.State))
		}
		switch st.State {
		case ipc.StateUp:
			wasUp = true
		case ipc.StateDown:
			cancel(fmt.Errorf("tunnel is down: %s", st.LastError))
		}
	}

	waitErr := cmd.Wait()
	stdin.Close()
	if cause := context.Cause(ctx); cause != nil && cause != context.Canceled {
		return wasUp, cause
	}
	if waitErr == nil {
		return wasUp, fmt.Errorf("worker exited without an error")
	}
	return wasUp, waitErr
}
