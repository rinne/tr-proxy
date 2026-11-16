package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// Validate checks the whole config and returns every problem found, joined
// into one error. A config is accepted or rejected as a whole.
func Validate(c *Config, ports PortRange) error {
	v := &validator{c: c, ports: ports}
	v.run()
	return errors.Join(v.errs...)
}

type validator struct {
	c     *Config
	ports PortRange
	errs  []error

	keys      map[string]bool
	egress    map[string]bool // wireguard and upstream names
	listeners map[string]bool
}

func (v *validator) errf(format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf(format, args...))
}

func (v *validator) run() {
	c := v.c
	if c.Version != Version {
		v.errf("version: got %d, this build supports %d", c.Version, Version)
	}

	v.keys = map[string]bool{}
	for i, k := range c.Keys {
		at := fmt.Sprintf("keys[%d]", i)
		v.name(at, k.Name, v.keys)
		if !isWGKey(k.SecretKey) {
			v.errf("%s (%s): secretKey is not a base64 32-byte key", at, k.Name)
		}
	}

	v.egress = map[string]bool{}
	for i, w := range c.WireGuard {
		v.wireguard(fmt.Sprintf("wireguard[%d]", i), w)
	}
	for i, u := range c.Upstreams {
		v.upstream(fmt.Sprintf("upstreams[%d]", i), u)
	}

	// Listener names first, so rules and defaults can refer to them.
	v.listeners = map[string]bool{}
	usedPorts := map[int]string{}
	for i, l := range c.Listeners {
		at := fmt.Sprintf("listeners[%d]", i)
		v.name(at, l.Name, v.listeners)
		if l.Type != "socks5" && l.Type != "http" {
			v.errf("%s (%s): type must be socks5 or http", at, l.Name)
		}
		if !v.ports.Contains(l.Port) {
			v.errf("%s (%s): port %d is outside PROXY_PORT_RANGE %s", at, l.Name, l.Port, v.ports)
		} else if other, dup := usedPorts[l.Port]; dup {
			v.errf("%s (%s): port %d is already used by listener %s", at, l.Name, l.Port, other)
		} else {
			usedPorts[l.Port] = l.Name
		}
		if l.Auth != nil {
			if len(l.Auth.Users) == 0 {
				v.errf("%s (%s): auth has no users; use null for an open listener", at, l.Name)
			}
			seen := map[string]bool{}
			for _, u := range l.Auth.Users {
				if u.Username == "" || u.Password == "" {
					v.errf("%s (%s): users need a username and a password", at, l.Name)
				} else if seen[u.Username] {
					v.errf("%s (%s): duplicate user %q", at, l.Name, u.Username)
				}
				seen[u.Username] = true
			}
		}
		if l.Default != "" {
			v.egressRef(at+" ("+l.Name+"): default", l.Default)
		}
	}

	ruleNames := map[string]bool{}
	for i, r := range c.Rules {
		v.rule(fmt.Sprintf("rules[%d]", i), r, ruleNames)
	}

	if c.Default == "" {
		v.errf("default: required (direct, block or a connection name)")
	} else {
		v.egressRef("default", c.Default)
	}
}

// name checks a name's form and uniqueness within seen, and records it.
func (v *validator) name(at, name string, seen map[string]bool) {
	switch {
	case !nameRE.MatchString(name):
		v.errf("%s: name %q must be 1-63 characters of letters, digits, '.', '_' or '-'", at, name)
	case seen[name]:
		v.errf("%s: duplicate name %q", at, name)
	}
	seen[name] = true
}

// egressName is name() for wireguard connections and upstreams, which share
// one namespace with the reserved words.
func (v *validator) egressName(at, name string) {
	if name == EgressDirect || name == EgressBlock {
		v.errf("%s: name %q is reserved", at, name)
		return
	}
	v.name(at, name, v.egress)
}

func (v *validator) egressRef(at, name string) {
	if name != EgressDirect && name != EgressBlock && !v.egress[name] {
		v.errf("%s: unknown connection %q", at, name)
	}
}

func (v *validator) wireguard(at string, w WireGuard) {
	v.egressName(at, w.Name)
	at = at + " (" + w.Name + ")"

	if !v.keys[w.LocalKey] {
		v.errf("%s: unknown localKey %q", at, w.LocalKey)
	}
	if len(w.Addresses) == 0 {
		v.errf("%s: addresses is required", at)
	}
	for _, a := range w.Addresses {
		if _, err := netip.ParsePrefix(a); err != nil {
			if _, err := netip.ParseAddr(a); err != nil {
				v.errf("%s: address %q is not an IP address or CIDR", at, a)
			}
		}
	}
	if !isWGKey(w.Peer.PublicKey) {
		v.errf("%s: peer.publicKey is not a base64 32-byte key", at)
	}
	if w.Peer.PresharedKey != "" && !isWGKey(w.Peer.PresharedKey) {
		v.errf("%s: peer.presharedKey is not a base64 32-byte key", at)
	}
	if !isHostPort(w.Peer.Endpoint) {
		v.errf("%s: peer.endpoint %q must be host:port", at, w.Peer.Endpoint)
	}
	if k := w.Peer.Keepalive; k != nil && (*k < 0 || *k > 65535) {
		v.errf("%s: peer.keepalive must be 0-65535 seconds", at)
	}
	for _, d := range w.DNS {
		if _, err := netip.ParseAddr(d); err != nil {
			v.errf("%s: dns %q is not an IP address", at, d)
		}
	}
	if w.MTU != 0 && (w.MTU < 576 || w.MTU > 65535) {
		v.errf("%s: mtu must be 576-65535", at)
	}

	if p := w.Probe; p != nil {
		switch p.Type {
		case ProbeDNS:
			if len(w.DNS) == 0 {
				v.errf("%s: probe type dns needs a dns server", at)
			}
		case ProbeTCP:
			if !isHostPort(p.Target) {
				v.errf("%s: probe type tcp needs target host:port", at)
			}
		case ProbeICMP:
			if p.Target == "" {
				v.errf("%s: probe type icmp needs a target", at)
			}
		case ProbeHandshake:
		default:
			v.errf("%s: probe type must be dns, tcp, icmp or handshake", at)
		}
		if p.Interval < 0 || p.Timeout < 0 || p.Failures < 0 {
			v.errf("%s: probe interval, timeout and failures must not be negative", at)
		}
	}
}

func (v *validator) upstream(at string, u Upstream) {
	v.egressName(at, u.Name)
	at = at + " (" + u.Name + ")"

	if u.Type != "http" {
		v.errf("%s: type must be http", at)
	}
	pu, err := url.Parse(u.URL)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		v.errf("%s: url must be http://host[:port]/ or https://host[:port]/", at)
	}
	if a := u.Auth; a != nil {
		switch a.Type {
		case "basic":
			if a.Username == "" {
				v.errf("%s: basic auth needs a username", at)
			}
		case "bearer":
			if a.Token == "" {
				v.errf("%s: bearer auth needs a token", at)
			}
		default:
			v.errf("%s: auth type must be basic or bearer", at)
		}
	}
}

func (v *validator) rule(at string, r Rule, seen map[string]bool) {
	v.name(at, r.Name, seen)
	at = at + " (" + r.Name + ")"

	if len(r.Match) == 0 {
		v.errf("%s: match is required", at)
	}
	for _, m := range r.Match {
		if _, err := ParseMatcher(m); err != nil {
			v.errf("%s: %v", at, err)
		}
	}

	if len(r.Via) == 0 {
		v.errf("%s: via is required", at)
	}
	for _, name := range r.Via {
		v.egressRef(at+": via", name)
		if name == EgressBlock && len(r.Via) > 1 {
			v.errf("%s: block cannot be part of a failover list", at)
		}
	}

	if len(r.OnlyListeners) > 0 && len(r.ExceptListeners) > 0 {
		v.errf("%s: onlyListeners and exceptListeners are mutually exclusive", at)
	}
	for _, l := range append(append([]string{}, r.OnlyListeners...), r.ExceptListeners...) {
		if !v.listeners[l] {
			v.errf("%s: unknown listener %q", at, l)
		}
	}
}

func isWGKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func isHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}
