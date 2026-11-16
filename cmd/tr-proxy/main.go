// Command tr-proxy is the single binary behind the TR Proxy container. It
// runs as the supervisor (default), as a per-tunnel worker spawned by the
// supervisor, or as the container health check.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"tr-proxy/internal/supervisor"
	"tr-proxy/internal/worker"
)

func main() {
	role := "supervisor"
	if len(os.Args) > 1 {
		role = os.Args[1]
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil)).With("role", role)

	var err error
	switch role {
	case "supervisor":
		err = supervisor.Run(ctx, log)
	case "worker":
		err = worker.Run(ctx, log)
	case "healthcheck":
		err = supervisor.Healthcheck(ctx)
	default:
		fmt.Fprintf(os.Stderr, "usage: %s [supervisor|worker|healthcheck]\n", os.Args[0])
		os.Exit(2)
	}
	if err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}
