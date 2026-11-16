package supervisor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"tr-proxy/internal/config"
	"tr-proxy/internal/ipc"
	"tr-proxy/internal/testpeer"
	"tr-proxy/internal/wgkey"
	"tr-proxy/internal/worker"
)

// The supervisor starts workers by running its own executable with the
// argument "worker". In tests that executable is the test binary, so the
// test binary takes on the worker role when asked to.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})).With("role", "worker")
		if err := worker.Run(ctx, log); err != nil {
			log.Error("exiting", "err", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var clientAddr = netip.MustParseAddr("10.99.0.2")

func testLog(t *testing.T) *slog.Logger {
	if testing.Verbose() {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// tunnelFixture is a test peer plus the config entries of a connection to it.
type tunnelFixture struct {
	peer *testpeer.Peer
	key  config.Key
	conn config.WireGuard
}

func newTunnelFixture(t *testing.T, name string) tunnelFixture {
	t.Helper()
	secret, public, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := testpeer.Start(name, public, clientAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)
	return tunnelFixture{
		peer: peer,
		key:  config.Key{Name: name + "-key", SecretKey: secret},
		conn: config.WireGuard{
			Name:      name,
			LocalKey:  name + "-key",
			Addresses: []string{clientAddr.String() + "/32"},
			Peer:      config.Peer{PublicKey: peer.PublicKey, Endpoint: peer.Endpoint},
			DNS:       []string{peer.Addr.String()},
		},
	}
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func workerStatus(w *Workers, name string) WorkerStatus {
	for _, s := range w.Status() {
		if s.Name == name {
			return s
		}
	}
	return WorkerStatus{}
}

func echoThrough(ctx context.Context, socket, host string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := ipc.Dial(ctx, socket, host, testpeer.EchoPort)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	msg := "hello through the tunnel"
	if _, err := io.WriteString(c, msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if string(got) != msg {
		return fmt.Errorf("echo returned %q", got)
	}
	return nil
}

func TestWorkerTunnel(t *testing.T) {
	fx := newTunnelFixture(t, "T1")
	cfg := config.New()
	cfg.Keys = []config.Key{fx.key}
	cfg.WireGuard = []config.WireGuard{fx.conn}
	if err := config.Validate(cfg, config.PortRange{Lo: 1080, Hi: 1099}); err != nil {
		t.Fatal(err)
	}

	workers, err := NewWorkers(testLog(t), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	workers.Start(ctx, cfg)
	defer func() {
		cancel()
		workers.Wait()
	}()
	socket := workers.SocketPath("T1")

	waitFor(t, "handshake", 15*time.Second, func() bool {
		return workerStatus(workers, "T1").State == ipc.StateUp
	})

	t.Run("dial by address", func(t *testing.T) {
		if err := echoThrough(ctx, socket, fx.peer.Addr.String()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("dial by hostname via tunnel dns", func(t *testing.T) {
		if err := echoThrough(ctx, socket, testpeer.EchoHost); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unknown hostname fails", func(t *testing.T) {
		if err := echoThrough(ctx, socket, "nope.test"); err == nil {
			t.Fatal("dial to an unknown host succeeded")
		}
	})
	t.Run("counters move", func(t *testing.T) {
		waitFor(t, "byte counters", 5*time.Second, func() bool {
			s := workerStatus(workers, "T1")
			return s.Rx > 0 && s.Tx > 0 && !s.LastHandshake.IsZero()
		})
	})
	t.Run("killed worker is restarted", func(t *testing.T) {
		before := workerStatus(workers, "T1")
		if err := syscall.Kill(before.PID, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "restart", 20*time.Second, func() bool {
			s := workerStatus(workers, "T1")
			return s.Restarts == before.Restarts+1 && s.PID != before.PID && s.State == ipc.StateUp
		})
		if err := echoThrough(ctx, socket, fx.peer.Addr.String()); err != nil {
			t.Fatal(err)
		}
	})
}
