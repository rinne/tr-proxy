package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"tr-proxy/internal/netutil"
)

// SOCKS5 (RFC 1928), CONNECT only.
const (
	socksVersion = 5

	socksAuthNone         = 0x00
	socksAuthNoAcceptable = 0xff

	socksCmdConnect = 1

	socksAddrIPv4   = 1
	socksAddrDomain = 3
	socksAddrIPv6   = 4

	socksOK                  = 0
	socksGeneralFailure      = 1
	socksNotAllowed          = 2
	socksHostUnreachable     = 4
	socksCommandNotSupported = 7
	socksAddrNotSupported    = 8
)

// ServeSOCKS5 accepts SOCKS5 clients on ln until ln is closed.
func (s *Server) ServeSOCKS5(ctx context.Context, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleSOCKS5(ctx, c)
	}
}

func (s *Server) handleSOCKS5(ctx context.Context, c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTimeout))

	host, port, err := s.socksHandshake(c)
	if err != nil {
		return
	}

	up, tracked, err := s.connect(ctx, c.RemoteAddr().String(), host, port)
	if err != nil {
		code := byte(socksHostUnreachable)
		switch {
		case errors.Is(err, ErrBlocked):
			code = socksNotAllowed
		case errors.Is(err, ErrUnavailable):
			code = socksGeneralFailure
		}
		socksReply(c, code)
		return
	}
	defer tracked.Done()
	defer up.Close()

	if err := socksReply(c, socksOK); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	netutil.Relay(c, up)
}

// socksHandshake negotiates the method and reads the CONNECT request. All
// reads are unbuffered so that nothing of the client's payload is consumed.
func (s *Server) socksHandshake(c net.Conn) (host string, port int, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return "", 0, err
	}
	if hdr[0] != socksVersion {
		return "", 0, fmt.Errorf("not SOCKS5")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", 0, err
	}

	if !contains(methods, socksAuthNone) {
		c.Write([]byte{socksVersion, socksAuthNoAcceptable})
		return "", 0, fmt.Errorf("no acceptable auth method")
	}
	if _, err := c.Write([]byte{socksVersion, socksAuthNone}); err != nil {
		return "", 0, err
	}

	var req [4]byte // version, command, reserved, address type
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return "", 0, err
	}
	if req[0] != socksVersion {
		return "", 0, fmt.Errorf("not SOCKS5")
	}
	if req[1] != socksCmdConnect {
		socksReply(c, socksCommandNotSupported)
		return "", 0, fmt.Errorf("unsupported command %d", req[1])
	}

	switch req[3] {
	case socksAddrIPv4:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4(a).String()
	case socksAddrIPv6:
		var a [16]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16(a).Unmap().String()
	case socksAddrDomain:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return "", 0, err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	default:
		socksReply(c, socksAddrNotSupported)
		return "", 0, fmt.Errorf("unsupported address type %d", req[3])
	}

	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		return "", 0, err
	}
	port = int(binary.BigEndian.Uint16(p[:]))
	if host == "" || port == 0 {
		socksReply(c, socksGeneralFailure)
		return "", 0, fmt.Errorf("empty destination")
	}
	return host, port, nil
}

// socksReply sends a reply with an all-zero bound address; clients do not
// use it for CONNECT.
func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{socksVersion, code, 0, socksAddrIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func contains(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}
