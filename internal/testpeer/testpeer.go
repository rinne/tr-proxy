// Package testpeer is a WireGuard peer for tests: a userspace WireGuard
// device listening on loopback, with an echo server, an HTTP server and a
// DNS server on its tunnel address. It stands in for a real VPN server.
package testpeer

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"tr-proxy/internal/wgkey"
)

const (
	EchoPort = 7
	HTTPPort = 80
	// EchoHost and HTTPHost resolve, on the peer's DNS server, to the peer.
	EchoHost = "echo.test"
	HTTPHost = "www.test"
)

type Peer struct {
	Name      string
	PublicKey string     // base64
	Endpoint  string     // 127.0.0.1:port, for the client's peer.endpoint
	Addr      netip.Addr // the peer's address inside the tunnel

	dev        *device.Device
	net        *netstack.Net
	clientUAPI string
	clientHex  string
}

// Start brings up a peer that accepts one client, identified by its public
// key and tunnel address. The HTTP server answers "name host path".
func Start(name, clientPublicKey string, clientAddr netip.Addr) (*Peer, error) {
	secret, public, err := wgkey.Generate()
	if err != nil {
		return nil, err
	}
	secretHex, _ := wgkey.Hex(secret)
	clientHex, err := wgkey.Hex(clientPublicKey)
	if err != nil {
		return nil, err
	}

	p := &Peer{
		Name:       name,
		PublicKey:  public,
		Addr:       netip.MustParseAddr("10.99.0.1"),
		clientHex:  clientHex,
		clientUAPI: fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", clientHex, clientAddr),
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{p.Addr}, nil, 1420)
	if err != nil {
		return nil, err
	}
	quiet := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	p.dev = device.NewDevice(tun, conn.NewDefaultBind(), quiet)
	p.net = tnet
	if err := p.dev.IpcSet("private_key=" + secretHex + "\nlisten_port=0\n" + p.clientUAPI); err != nil {
		p.dev.Close()
		return nil, err
	}
	if err := p.dev.Up(); err != nil {
		p.dev.Close()
		return nil, err
	}
	port, err := p.listenPort()
	if err != nil {
		p.dev.Close()
		return nil, err
	}
	p.Endpoint = fmt.Sprintf("127.0.0.1:%d", port)

	if err := p.serve(); err != nil {
		p.dev.Close()
		return nil, err
	}
	return p, nil
}

func (p *Peer) listenPort() (int, error) {
	raw, err := p.dev.IpcGet()
	if err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		var port int
		if _, err := fmt.Sscanf(sc.Text(), "listen_port=%d", &port); err == nil && port != 0 {
			return port, nil
		}
	}
	return 0, fmt.Errorf("peer has no listen port")
}

// Pause makes the peer forget its client: handshakes and traffic stop
// working, as if the server had gone away. Resume undoes it.
func (p *Peer) Pause() error {
	return p.dev.IpcSet("public_key=" + p.clientHex + "\nremove=true\n")
}

func (p *Peer) Resume() error { return p.dev.IpcSet(p.clientUAPI) }

func (p *Peer) Close() { p.dev.Close() }

func (p *Peer) serve() error {
	echo, err := p.net.ListenTCPAddrPort(netip.AddrPortFrom(p.Addr, EchoPort))
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	web, err := p.net.ListenTCPAddrPort(netip.AddrPortFrom(p.Addr, HTTPPort))
	if err != nil {
		return err
	}
	go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s %s", p.Name, r.Host, r.URL.Path)
	}))

	dns, err := p.net.ListenUDPAddrPort(netip.AddrPortFrom(p.Addr, 53))
	if err != nil {
		return err
	}
	go p.serveDNS(dns)
	return nil
}

// serveDNS answers A queries for EchoHost and HTTPHost with the peer's
// address and everything else with NXDOMAIN.
func (p *Peer) serveDNS(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var parser dnsmessage.Parser
		hdr, err := parser.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := parser.Question()
		if err != nil {
			continue
		}

		name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
		known := name == EchoHost || name == HTTPHost
		resp := dnsmessage.Header{ID: hdr.ID, Response: true, RecursionAvailable: true}
		if !known {
			resp.RCode = dnsmessage.RCodeNameError
		}
		b := dnsmessage.NewBuilder(nil, resp)
		b.StartQuestions()
		b.Question(q)
		if known && q.Type == dnsmessage.TypeA {
			b.StartAnswers()
			b.AResource(
				dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				dnsmessage.AResource{A: p.Addr.As4()},
			)
		}
		if msg, err := b.Finish(); err == nil {
			pc.WriteTo(msg, from)
		}
	}
}
