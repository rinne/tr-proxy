// Package supervisor is the container's main process: it owns the config,
// runs the admin HTTP server and keeps one worker per WireGuard connection
// alive.
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
	"time"

	"tr-proxy/internal/config"
)

// Run is the supervisor's main loop. It returns when ctx is cancelled and
// everything has shut down, or on a fatal start-up error.
func Run(ctx context.Context, log *slog.Logger) error {
	env, err := LoadEnv()
	if err != nil {
		return err
	}

	cfg, err := loadOrCreateConfig(env, log)
	if err != nil {
		return err
	}
	log.Info("config loaded",
		"path", env.ConfigPath,
		"wireguard", len(cfg.WireGuard),
		"upstreams", len(cfg.Upstreams),
		"listeners", len(cfg.Listeners),
		"rules", len(cfg.Rules))

	if err := os.MkdirAll(env.RunDir, 0o700); err != nil {
		return fmt.Errorf("run directory: %w", err)
	}
	workers, err := NewWorkers(log, env.RunDir)
	if err != nil {
		return err
	}
	workers.Start(ctx, cfg)

	srv := &http.Server{
		Addr:              net.JoinHostPort("", strconv.Itoa(env.AdminPort)),
		Handler:           adminHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.ListenAndServe() }()
	log.Info("admin server listening", "port", env.AdminPort)

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-srvErr:
		return fmt.Errorf("admin server: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
	workers.Wait()
	return nil
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
