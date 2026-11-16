package config

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// PortRange is an inclusive range of TCP ports, written "1080-1099".
type PortRange struct {
	Lo, Hi int
}

func ParsePortRange(s string) (PortRange, error) {
	var r PortRange
	lo, hi, ok := strings.Cut(strings.TrimSpace(s), "-")
	if !ok {
		hi = lo
	}
	var errLo, errHi error
	r.Lo, errLo = strconv.Atoi(lo)
	r.Hi, errHi = strconv.Atoi(hi)
	if errLo != nil || errHi != nil {
		return r, fmt.Errorf("port range %q: want LO-HI", s)
	}
	if r.Lo < 1 || r.Hi > 65535 || r.Lo > r.Hi {
		return r, fmt.Errorf("port range %q: out of order or outside 1-65535", s)
	}
	return r, nil
}

func (r PortRange) Contains(port int) bool { return port >= r.Lo && port <= r.Hi }

func (r PortRange) String() string { return fmt.Sprintf("%d-%d", r.Lo, r.Hi) }

type matcherKind int

const (
	matchHost   matcherKind = iota // exact hostname
	matchSuffix                    // *.example.com
	matchPrefix                    // single address or CIDR
	matchRange                     // lo-hi
)

// Matcher is one parsed entry of a rule's match list.
type Matcher struct {
	kind   matcherKind
	host   string // exact host, or ".example.com" for a suffix
	prefix netip.Prefix
	lo, hi netip.Addr
}

// ParseMatcher parses an exact hostname, a "*.suffix" wildcard, an IP
// address, a CIDR network or an "a-b" address range.
func ParseMatcher(s string) (Matcher, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Matcher{}, fmt.Errorf("empty matcher")
	}

	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Matcher{}, fmt.Errorf("matcher %q: invalid network", s)
		}
		return Matcher{kind: matchPrefix, prefix: p.Masked()}, nil
	}

	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return Matcher{kind: matchPrefix, prefix: netip.PrefixFrom(a, a.BitLen())}, nil
	}

	// A range only when the left side is an address; hostnames may contain
	// dashes.
	if l, r, ok := strings.Cut(s, "-"); ok {
		if lo, err := netip.ParseAddr(strings.TrimSpace(l)); err == nil {
			hi, err := netip.ParseAddr(strings.TrimSpace(r))
			if err != nil {
				return Matcher{}, fmt.Errorf("matcher %q: invalid range end", s)
			}
			lo, hi = lo.Unmap(), hi.Unmap()
			if lo.BitLen() != hi.BitLen() || hi.Less(lo) {
				return Matcher{}, fmt.Errorf("matcher %q: range ends are mixed or out of order", s)
			}
			return Matcher{kind: matchRange, lo: lo, hi: hi}, nil
		}
	}

	if rest, ok := strings.CutPrefix(s, "*."); ok {
		h, err := normalizeHost(rest)
		if err != nil {
			return Matcher{}, fmt.Errorf("matcher %q: %w", s, err)
		}
		return Matcher{kind: matchSuffix, host: "." + h}, nil
	}

	h, err := normalizeHost(s)
	if err != nil {
		return Matcher{}, fmt.Errorf("matcher %q: %w", s, err)
	}
	return Matcher{kind: matchHost, host: h}, nil
}

// MatchHost reports whether a hostname matches. IP matchers never match
// hostnames.
func (m Matcher) MatchHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	switch m.kind {
	case matchHost:
		return host == m.host
	case matchSuffix:
		return strings.HasSuffix(host, m.host)
	}
	return false
}

// MatchIP reports whether an address matches. Hostname matchers never match
// addresses.
func (m Matcher) MatchIP(a netip.Addr) bool {
	a = a.Unmap()
	switch m.kind {
	case matchPrefix:
		return m.prefix.Contains(a)
	case matchRange:
		return a.BitLen() == m.lo.BitLen() && !a.Less(m.lo) && !m.hi.Less(a)
	}
	return false
}

func normalizeHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > 253 {
		return "", fmt.Errorf("invalid hostname")
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid hostname")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("invalid hostname")
			}
		}
	}
	return h, nil
}
