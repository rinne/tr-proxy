package egress

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDirectRefusesLocalDestinations(t *testing.T) {
	host, port := echoServer(t)

	if err := echo(Direct{AllowLocal: true}, host, port); err != nil {
		t.Fatalf("with AllowLocal: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, dest := range []string{
		host,              // 127.0.0.1
		"localhost",       // by name: checked after resolution
		"127.8.9.10",      // all of 127/8
		"::1",             //
		"0.0.0.0",         // unspecified reaches loopback on Linux
		"169.254.169.254", // cloud metadata service
		"::ffff:127.0.0.1",
	} {
		c, err := Direct{}.Dial(ctx, dest, port)
		if err == nil {
			c.Close()
			t.Errorf("%s: connected", dest)
			continue
		}
		if !errors.Is(err, ErrLocalDestination) {
			t.Errorf("%s: error %v, want ErrLocalDestination", dest, err)
		}
	}
}
