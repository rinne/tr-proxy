package supervisor

import (
	"context"
	"sync"
	"time"

	"tr-proxy/internal/egress"
)

// How often upstream proxies are checked, and how long one check may take.
// Variables so that tests can shorten them; a monitor reads them when it is
// created.
var (
	upstreamCheckInterval = 15 * time.Second
	upstreamCheckTimeout  = 5 * time.Second
)

// UpstreamStatus is the supervisor's view of one upstream proxy.
type UpstreamStatus struct {
	Name      string    `json:"name"`
	Reachable bool      `json:"reachable"`
	LastError string    `json:"lastError,omitempty"`
	Checked   time.Time `json:"checked,omitzero"` // zero: not checked yet
}

// upstreamMonitor periodically checks that upstream proxies accept
// connections.
type upstreamMonitor struct {
	interval, timeout time.Duration
	done              chan struct{} // closed when run returns

	mu     sync.Mutex
	status map[string]UpstreamStatus
}

func newUpstreamMonitor() *upstreamMonitor {
	return &upstreamMonitor{
		interval: upstreamCheckInterval,
		timeout:  upstreamCheckTimeout,
		done:     make(chan struct{}),
		status:   map[string]UpstreamStatus{},
	}
}

// wait blocks until run has returned; it must have been started.
func (m *upstreamMonitor) wait() { <-m.done }

// reachable reports false only for an upstream whose last check failed; one
// that has not been checked yet gets the benefit of the doubt.
func (m *upstreamMonitor) reachable(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.status[name]
	return !ok || st.Reachable
}

// Status returns the status of the named upstream.
func (m *upstreamMonitor) Status(name string) UpstreamStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.status[name]; ok {
		return st
	}
	return UpstreamStatus{Name: name}
}

// run checks the upstreams returned by current, which is asked anew every
// round so that config changes are picked up, until ctx is cancelled.
func (m *upstreamMonitor) run(ctx context.Context, current func() map[string]egress.Upstream) {
	defer close(m.done)
	for {
		upstreams := current()
		var wg sync.WaitGroup
		results := make(map[string]UpstreamStatus, len(upstreams))
		var resMu sync.Mutex
		for name, up := range upstreams {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cctx, cancel := context.WithTimeout(ctx, m.timeout)
				defer cancel()
				st := UpstreamStatus{Name: name, Reachable: true, Checked: time.Now()}
				if err := up.Check(cctx); err != nil {
					st.Reachable, st.LastError = false, err.Error()
				}
				resMu.Lock()
				results[name] = st
				resMu.Unlock()
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			return
		}
		// Replace the whole map: upstreams that no longer exist drop out.
		m.mu.Lock()
		m.status = results
		m.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-time.After(m.interval):
		}
	}
}
