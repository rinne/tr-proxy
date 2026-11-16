// Command tr-proxy is the single binary behind the TR Proxy container. It
// runs as the supervisor (default), as a per-tunnel worker spawned by the
// supervisor, or as the container health check; "version" prints the
// version.
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

// version is set at build time (-ldflags "-X main.version=..."); "dev" is a
// build that was not made by the release script.
var version = "dev"

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
	case "version":
		fmt.Println(version)
		return
	case "supervisor":
		err = supervisor.Run(ctx, log, version)
	case "worker":
		err = worker.Run(ctx, log)
	case "healthcheck":
		err = supervisor.Healthcheck(ctx)
	default:
		fmt.Fprintf(os.Stderr, "usage: %s [supervisor|worker|healthcheck|version]\n", os.Args[0])
		os.Exit(2)
	}
	if err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}
