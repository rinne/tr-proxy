// Package supervisor is the container's main process: it owns the config,
// runs the proxy listeners and the admin HTTP server, and keeps one worker
// per WireGuard connection alive.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"tr-proxy/internal/admin"
	"tr-proxy/internal/config"
	"tr-proxy/internal/egress"
	"tr-proxy/internal/proxy"
)

// Server is the supervisor's state.
type Server struct {
	env *Env
	log *slog.Logger
	// version is the build's version, shown in the status.
	version string

	// state is everything derived from the running config; applyMu
	// serializes its replacement.
	state   atomic.Pointer[state]
	applyMu sync.Mutex
	// configError is set when the config file could not be used at start-up
	// and the server runs on an empty config instead.
	configError atomic.Pointer[string]
	// generation counts applied configs; the UI refetches when it changes.
	generation atomic.Uint64

	// ctx is what workers, listeners and monitors run under. It is not the
	// context given to Start: Shutdown cancels it only after draining.
	ctx       context.Context
	cancel    context.CancelFunc
	workers   *Workers
	upstreams *upstreamMonitor
	tracker   *proxy.Tracker
	listeners listeners
	events    events
	admin     *http.Server
	adminErr  chan error
}

// Run is the supervisor's main loop. It returns when ctx is cancelled and
// everything has shut down, or on a fatal start-up error.
func Run(ctx context.Context, log *slog.Logger, version string) error {
	env, err := LoadEnv()
	if err != nil {
		return err
	}
	log.Info("tr-proxy starting", "version", version)
	s, err := New(env, log)
	if err != nil {
		return err
	}
	s.version = version
	if err := s.Start(ctx); err != nil {
		s.Shutdown()
		return err
	}
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err = <-s.adminErr:
		err = fmt.Errorf("admin server: %w", err)
	}
	s.Shutdown()
	return err
}

// New loads the config and prepares a server; nothing runs until Start.
func New(env *Env, log *slog.Logger) (*Server, error) {
	s := &Server{
		env:       env,
		log:       log,
		upstreams: newUpstreamMonitor(),
		tracker:   proxy.NewTracker(),
		adminErr:  make(chan error, 1),
	}

	if err := os.MkdirAll(env.RunDir, 0o700); err != nil {
		return nil, fmt.Errorf("run directory: %w", err)
	}
	// Workers create their sockets here. Finding out now gives one clear
	// error instead of every worker failing in a restart loop.
	probe, err := os.CreateTemp(env.RunDir, ".writable-*")
	if err != nil {
		return nil, fmt.Errorf("run directory %s is not writable for uid %d (a tmpfs mounted there needs uid, gid and mode options): %w",
			env.RunDir, os.Getuid(), err)
	}
	probe.Close()
	os.Remove(probe.Name())
	workers, err := NewWorkers(log, env.RunDir, s.events.Add)
	if err != nil {
		return nil, err
	}
	s.workers = workers

	cfg, err := s.loadOrCreateConfig()
	if err != nil {
		return nil, err
	}
	log.Info("config loaded",
		"path", env.ConfigPath,
		"wireguard", len(cfg.WireGuard),
		"upstreams", len(cfg.Upstreams),
		"listeners", len(cfg.Listeners),
		"rules", len(cfg.Rules))
	st, err := s.newState(cfg)
	if err != nil {
		return nil, err
	}
	s.state.Store(st)
	return s, nil
}

// loadOrCreateConfig loads and validates the config file, writing an empty
// one on first start. A file that exists but cannot be used does not stop
// the server: it starts on an empty config, leaves the file alone and
// reports the problem in the status, so that it can be fixed through the
// admin API.
func (s *Server) loadOrCreateConfig() (*config.Config, error) {
	path := s.env.ConfigPath
	cfg, err := config.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg = config.New()
		if err := config.Save(path, cfg); err != nil {
			return nil, fmt.Errorf("create %s: %w", path, err)
		}
		s.log.Info("no config found; wrote an empty one", "path", path)
		return cfg, nil
	}
	if err == nil {
		for _, name := range config.StripURLLogins(cfg) {
			msg := fmt.Sprintf("upstream %s: the login in its url was removed; it was never used, give it under auth", name)
			s.log.Warn("login removed from an upstream url", "upstream", name)
			s.events.Add("config", msg)
		}
		err = config.Validate(cfg, s.env.ProxyPorts)
	}
	if err != nil {
		msg := fmt.Sprintf("%s was not used: %v", path, err)
		s.configError.Store(&msg)
		s.log.Error("config file is not usable; running on an empty config until it is replaced", "path", path, "err", err)
		s.events.Add("config", msg)
		return config.New(), nil
	}
	return cfg, nil
}

// Start launches the workers, the proxy listeners and the admin server. They
// run until Shutdown; cancelling ctx alone stops nothing, so that open
// connections can be drained first.
func (s *Server) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(context.WithoutCancel(ctx))
	ctx = s.ctx
	cfg := s.state.Load().cfg

	s.workers.Start(ctx)
	s.workers.Sync(s.workers.Specs(cfg))
	go s.upstreams.run(ctx, func() map[string]egress.Upstream { return s.state.Load().upstreams })
	s.syncListeners(ctx, cfg.Listeners)

	ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(s.env.AdminPort)))
	if err != nil {
		return fmt.Errorf("admin server: %w", err)
	}
	creds := admin.Credentials{
		Username:   s.env.AdminUsername,
		Password:   s.env.AdminPassword,
		TOTPSecret: s.env.AdminTOTPSecret,
	}
	s.admin = &http.Server{
		Handler:           admin.NewHandler(s, creds, s.log),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	go func() {
		if err := s.admin.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			s.adminErr <- err
		}
	}()
	s.log.Info("admin server listening", "port", s.env.AdminPort)
	return nil
}

// Shutdown stops accepting, gives open connections the drain timeout to
// finish, closes what is left, and stops the workers.
func (s *Server) Shutdown() {
	s.closeListeners()
	if s.admin != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.admin.Shutdown(ctx)
		cancel()
	}
	s.drain(s.state.Load().limits.DrainTimeout)
	s.tracker.CloseAll()
	if s.cancel != nil {
		s.cancel()
		s.upstreams.wait()
	}
	s.workers.Wait()
}

// drain waits until no proxied connection is open, or for timeout.
func (s *Server) drain(timeout time.Duration) {
	open := s.tracker.Len()
	if open == 0 || timeout <= 0 {
		return
	}
	s.log.Info("waiting for open connections to finish", "connections", open, "timeout", timeout)
	deadline := time.Now().Add(timeout)
	for s.tracker.Len() > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if left := s.tracker.Len(); left > 0 {
		s.log.Info("closing connections that did not finish in time", "connections", left)
	}
}

// --- admin.Backend ---

// Config returns a copy of the running config.
func (s *Server) Config() *config.Config {
	return s.state.Load().cfg.Clone()
}

// Apply validates cfg, saves it and switches to it. Only what changed is
// touched: workers whose connection (or key) changed are restarted,
// listeners whose port, type or users changed are reopened, and rules,
// defaults and upstreams take effect for new connections at once. Existing
// proxied connections are left alone unless their tunnel is restarted.
func (s *Server) Apply(cfg *config.Config) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	if err := config.Validate(cfg, s.env.ProxyPorts); err != nil {
		return &admin.InvalidError{Err: err}
	}
	st, err := s.newState(cfg)
	if err != nil {
		return &admin.InvalidError{Err: err}
	}
	if err := config.Save(s.env.ConfigPath, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	s.state.Store(st)
	s.configError.Store(nil)
	s.generation.Add(1)

	s.workers.Sync(s.workers.Specs(cfg))
	s.syncListeners(s.ctx, cfg.Listeners)
	s.events.Add("config", "configuration changed")
	s.log.Info("config applied")
	return nil
}

func (s *Server) TestRoute(listener, host string) admin.RouteTest {
	res, _ := s.decide(listener, host)
	out := admin.RouteTest{Rule: res.Rule, Via: res.Via, Egress: res.Egress}
	if res.Err != nil {
		out.Error = res.Err.Error()
	}
	return out
}

func (s *Server) RestartTunnel(name string) bool { return s.workers.Restart(name) }

func (s *Server) Event(kind, message string) { s.events.Add(kind, message) }

// Healthcheck is the container health check: it asks the supervisor's
// /healthz on localhost and fails unless the answer is 200.
func Healthcheck(ctx context.Context) error {
	port, err := adminPort()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %s", resp.Status)
	}
	return nil
}
