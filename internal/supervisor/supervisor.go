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
	"sync/atomic"
	"time"

	"tr-proxy/internal/config"
	"tr-proxy/internal/proxy"
)

// Server is the supervisor's state.
type Server struct {
	env   *Env
	log   *slog.Logger
	state atomic.Pointer[state]

	workers   *Workers
	tracker   *proxy.Tracker
	listeners []net.Listener
	admin     *http.Server
	adminErr  chan error
}

// Run is the supervisor's main loop. It returns when ctx is cancelled and
// everything has shut down, or on a fatal start-up error.
func Run(ctx context.Context, log *slog.Logger) error {
	env, err := LoadEnv()
	if err != nil {
		return err
	}
	s, err := New(env, log)
	if err != nil {
		return err
	}
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
	cfg, err := loadOrCreateConfig(env, log)
	if err != nil {
		return nil, err
	}
	log.Info("config loaded",
		"path", env.ConfigPath,
		"wireguard", len(cfg.WireGuard),
		"upstreams", len(cfg.Upstreams),
		"listeners", len(cfg.Listeners),
		"rules", len(cfg.Rules))

	if err := os.MkdirAll(env.RunDir, 0o700); err != nil {
		return nil, fmt.Errorf("run directory: %w", err)
	}
	workers, err := NewWorkers(log, env.RunDir)
	if err != nil {
		return nil, err
	}
	s := &Server{
		env:      env,
		log:      log,
		workers:  workers,
		tracker:  proxy.NewTracker(),
		adminErr: make(chan error, 1),
	}
	st, err := s.newState(cfg)
	if err != nil {
		return nil, err
	}
	s.state.Store(st)
	return s, nil
}

// Start launches the workers, the proxy listeners and the admin server. They
// run until ctx is cancelled; call Shutdown afterwards to wait for them.
func (s *Server) Start(ctx context.Context) error {
	cfg := s.state.Load().cfg
	s.workers.Start(ctx, cfg)

	for _, l := range cfg.Listeners {
		if err := s.startListener(ctx, l); err != nil {
			return err
		}
	}

	ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(s.env.AdminPort)))
	if err != nil {
		return fmt.Errorf("admin server: %w", err)
	}
	s.admin = &http.Server{Handler: adminHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := s.admin.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			s.adminErr <- err
		}
	}()
	s.log.Info("admin server listening", "port", s.env.AdminPort)
	return nil
}

func (s *Server) startListener(ctx context.Context, l config.Listener) error {
	srv := &proxy.Server{Name: l.Name, Router: proxyRouter{s}, Tracker: s.tracker, Log: s.log, Auth: listenerAuth(l)}
	serve := srv.ServeSOCKS5
	if l.Type == "http" {
		serve = srv.ServeHTTP
	}

	ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(l.Port)))
	if err != nil {
		return fmt.Errorf("listener %s: %w", l.Name, err)
	}
	s.listeners = append(s.listeners, ln)
	go serve(ctx, ln)
	s.log.Info("listener started", "listener", l.Name, "type", l.Type, "port", l.Port)
	return nil
}

// Shutdown stops accepting, closes the admin server and waits for the
// workers, which stop when the context given to Start is cancelled.
func (s *Server) Shutdown() {
	for _, ln := range s.listeners {
		ln.Close()
	}
	if s.admin != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.admin.Shutdown(ctx)
	}
	s.workers.Wait()
}

// loadOrCreateConfig loads and validates the config file, writing an empty
// one on first start.
func loadOrCreateConfig(env *Env, log *slog.Logger) (*config.Config, error) {
	cfg, err := config.Load(env.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		cfg = config.New()
		if err := config.Save(env.ConfigPath, cfg); err != nil {
			return nil, fmt.Errorf("create %s: %w", env.ConfigPath, err)
		}
		log.Info("no config found; wrote an empty one", "path", env.ConfigPath)
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", env.ConfigPath, err)
	}
	if err := config.Validate(cfg, env.ProxyPorts); err != nil {
		return nil, fmt.Errorf("invalid config %s:\n%w", env.ConfigPath, err)
	}
	return cfg, nil
}

func adminHandler() http.Handler {
	mux := http.NewServeMux()
	// Unauthenticated; process health only.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	return mux
}

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
