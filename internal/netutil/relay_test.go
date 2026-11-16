package netutil

import (
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair returns the two ends of a TCP connection over loopback.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

// relayed sets up client <-> relay <-> server and returns the outer ends
// and a channel that reports when the relay has ended.
func relayed(t *testing.T, idle time.Duration) (client, server net.Conn, done chan [2]int64) {
	client, relayA := tcpPair(t)
	relayB, server := tcpPair(t)
	done = make(chan [2]int64, 1)
	go func() {
		up, down := Relay(relayA, relayB, idle)
		done <- [2]int64{up, down}
	}()
	return client, server, done
}

func TestRelayCopiesAndHalfCloses(t *testing.T) {
	for _, idle := range []time.Duration{0, time.Minute} {
		client, server, done := relayed(t, idle)

		io.WriteString(client, "request")
		client.(*net.TCPConn).CloseWrite()
		got, err := io.ReadAll(server)
		if err != nil || string(got) != "request" {
			t.Fatalf("idle %v: server read %q, %v", idle, got, err)
		}
		// The other direction still works after the half-close.
		io.WriteString(server, "response")
		server.Close()
		got, err = io.ReadAll(client)
		if err != nil || string(got) != "response" {
			t.Fatalf("idle %v: client read %q, %v", idle, got, err)
		}
		select {
		case n := <-done:
			if n != [2]int64{7, 8} {
				t.Errorf("idle %v: byte counts %v, want [7 8]", idle, n)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("idle %v: relay did not end", idle)
		}
	}
}

func TestRelayIdleTimeout(t *testing.T) {
	const idle = 300 * time.Millisecond
	client, server, done := relayed(t, idle)

	// One busy direction keeps a quiet one alive well past the timeout.
	go io.Copy(io.Discard, server)
	for i := 0; i < 10; i++ {
		if _, err := io.WriteString(client, "tick"); err != nil {
			t.Fatalf("write %d failed although the relay should be alive: %v", i, err)
		}
		time.Sleep(idle / 3)
	}
	select {
	case <-done:
		t.Fatal("relay ended while one direction was busy")
	default:
	}

	// Silence in both directions ends it.
	start := time.Now()
	select {
	case <-done:
		if waited := time.Since(start); waited > 4*idle {
			t.Errorf("relay ended after %v of silence, want about %v", waited, idle)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("idle relay did not end")
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("client side is still open after the idle timeout")
	}
}

func TestRelayWithoutIdleTimeoutStaysOpen(t *testing.T) {
	_, _, done := relayed(t, 0)
	select {
	case <-done:
		t.Fatal("relay without a timeout ended on its own")
	case <-time.After(500 * time.Millisecond):
	}
}
