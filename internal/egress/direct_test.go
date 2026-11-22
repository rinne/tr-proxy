package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
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

// A service listening on every interface, as the admin API does, must not
// be reachable through the container's own non-loopback addresses either.
func TestDirectRefusesOwnAddresses(t *testing.T) {
	var own netip.Addr
	addrs, err := interfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			own = a
			break
		}
	}
	if !own.IsValid() {
		t.Skip("no non-loopback interface address")
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Direct{}.Dial(ctx, own.String(), port)
	if err == nil {
		c.Close()
		t.Fatalf("%s: connected to an address of this host", own)
	}
	if !errors.Is(err, ErrLocalDestination) {
		t.Fatalf("%s: error %v, want ErrLocalDestination", own, err)
	}
	c, err = Direct{AllowLocal: true}.Dial(ctx, own.String(), port)
	if err != nil {
		t.Fatalf("with AllowLocal: %v", err)
	}
	c.Close()
}

func TestAddrCacheRereadsAndKeepsLastOnError(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	list, fail := []netip.Addr{a}, false
	c := &addrCache{ttl: time.Hour, read: func() ([]netip.Addr, error) {
		if fail {
			return nil, errors.New("no")
		}
		return list, nil
	}}
	if !c.has(a) || c.has(b) {
		t.Fatal("first read")
	}
	list = []netip.Addr{b}
	if !c.has(a) {
		t.Fatal("re-read before the ttl")
	}
	c.at = time.Time{}
	if c.has(a) || !c.has(b) {
		t.Fatal("not re-read after the ttl")
	}
	fail = true
	c.at = time.Time{}
	if !c.has(b) {
		t.Fatal("lost the addresses on a read error")
	}
}
