package worker

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"tr-proxy/internal/config"
	"tr-proxy/internal/ipc"
	"tr-proxy/internal/tunnel"
)

// A handshake older than this means the peer has gone quiet: WireGuard
// renews it every two minutes while there is traffic or keepalive.
const handshakeStale = 3 * time.Minute

// While a tunnel has never passed a probe it is probed this often, so that
// it comes up quickly.
const startingInterval = time.Second

// prober runs a connection's health probe and derives the tunnel state.
type prober struct {
	tun       *tunnel.Tunnel
	conn      config.WireGuard
	probe     config.Probe
	started   time.Time
	keepalive bool

	mu       sync.Mutex
	state    string
	everOK   bool
	failures int
	result   ipc.Probe
}

func newProber(tun *tunnel.Tunnel, conn config.WireGuard) *prober {
	p := conn.EffectiveProbe()
	return &prober{
		tun:       tun,
		conn:      conn,
		probe:     p,
		started:   time.Now(),
		keepalive: conn.Peer.KeepaliveSeconds() > 0,
		state:     ipc.StateStarting,
		result:    ipc.Probe{Type: p.Type},
	}
}

func (p *prober) snapshot() (state string, result ipc.Probe) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state, p.result
}

// run probes until ctx is cancelled.
func (p *prober) run(ctx context.Context) {
	interval := time.Duration(p.probe.Interval) * time.Second
	timeout := time.Duration(p.probe.Timeout) * time.Second
	// A tunnel that has never worked is given this long before it is
	// declared down.
	grace := interval * time.Duration(p.probe.Failures)

	for {
		pctx, cancel := context.WithTimeout(ctx, timeout)
		began := time.Now()
		err := p.check(pctx)
		latency := time.Since(began)
		cancel()
		if ctx.Err() != nil {
			return
		}

		p.mu.Lock()
		p.result.Checked = true
		p.result.OK = err == nil
		if err == nil {
			p.everOK = true
			p.failures = 0
			p.state = ipc.StateUp
			p.result.LatencyMs = float64(latency.Microseconds()) / 1000
			p.result.Error = ""
		} else {
			p.result.Error = err.Error()
			switch {
			case !p.everOK && time.Since(p.started) < grace:
				p.state = ipc.StateStarting
			case !p.everOK:
				p.state = ipc.StateDown
			default:
				p.failures++
				p.state = ipc.StateDegraded
				if p.failures >= p.probe.Failures {
					p.state = ipc.StateDown
				}
			}
		}
		p.result.Failures = p.failures
		wait := interval
		if !p.everOK {
			wait = min(interval, startingInterval)
		}
		p.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (p *prober) check(ctx context.Context) error {
	switch p.probe.Type {
	case config.ProbeDNS:
		return p.checkDNS(ctx)
	case config.ProbeTCP:
		return p.checkTCP(ctx)
	case config.ProbeICMP:
		return p.checkICMP(ctx)
	default:
		return p.checkHandshake()
	}
}

// checkHandshake is the passive probe: it looks at the age of the last
// handshake. Without keepalive WireGuard handshakes only on traffic, so
// there is nothing to judge and the tunnel counts as usable.
func (p *prober) checkHandshake() error {
	if !p.keepalive {
		return nil
	}
	stats, err := p.tun.Stats()
	if err != nil {
		return err
	}
	if stats.LastHandshake.IsZero() {
		return errors.New("no handshake yet")
	}
	if age := time.Since(stats.LastHandshake); age > handshakeStale {
		return fmt.Errorf("last handshake was %s ago", age.Round(time.Second))
	}
	return nil
}

// checkDNS sends a query to the tunnel's first DNS server. Any answer, even
// a refusal, shows that packets make the round trip.
func (p *prober) checkDNS(ctx context.Context) error {
	server, err := netip.ParseAddr(p.conn.DNS[0])
	if err != nil {
		return err
	}
	id := uint16(rand.Uint32())
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("."),
		Type:  dnsmessage.TypeNS,
		Class: dnsmessage.ClassINET,
	})
	query, err := b.Finish()
	if err != nil {
		return err
	}

	c, err := p.tun.Net().DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(server, 53))
	if err != nil {
		return err
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	if _, err := c.Write(query); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return fmt.Errorf("no answer from dns server %s", server)
		}
		var parser dnsmessage.Parser
		if hdr, err := parser.Start(buf[:n]); err == nil && hdr.ID == id && hdr.Response {
			return nil
		}
	}
}

func (p *prober) checkTCP(ctx context.Context) error {
	host, portStr, err := net.SplitHostPort(p.probe.Target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	c, err := p.tun.Dial(ctx, host, port)
	if err != nil {
		return err
	}
	c.Close()
	return nil
}

func (p *prober) checkICMP(ctx context.Context) error {
	target, err := netip.ParseAddr(p.probe.Target)
	if err != nil {
		addrs, err := p.tun.Net().LookupContextHost(ctx, p.probe.Target)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("cannot resolve %s", p.probe.Target)
		}
		if target, err = netip.ParseAddr(addrs[0]); err != nil {
			return err
		}
	}

	var echoType, replyType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	proto := 1
	if target.Is6() {
		echoType, replyType, proto = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, 58
	}
	seq := int(rand.Uint32() & 0xffff)
	msg, err := (&icmp.Message{Type: echoType, Body: &icmp.Echo{Seq: seq, Data: []byte("tr-proxy probe")}}).Marshal(nil)
	if err != nil {
		return err
	}

	c, err := p.tun.Net().DialPingAddr(netip.Addr{}, target)
	if err != nil {
		return err
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	if _, err := c.Write(msg); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return fmt.Errorf("no ping reply from %s", target)
		}
		reply, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || reply.Type != replyType {
			continue
		}
		if echo, ok := reply.Body.(*icmp.Echo); ok && echo.Seq == seq {
			return nil
		}
	}
}
