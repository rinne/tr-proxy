package netutil

import (
	"net/netip"
	"strings"
)

// ValidHost reports whether h can be used as a destination: an IP address
// without a zone, or a hostname made of labels of letters, digits, hyphens
// and underscores. A name whose last label is all digits is refused: no
// top-level domain is numeric, and some resolvers take such a name (127.1,
// 2130706433) for an IPv4 address, which would get it past IP rules.
//
// Destinations come from clients and end up in an upstream CONNECT line, a
// SOCKS5 request, a log line and the rule matcher, so anything else (spaces,
// CR, LF, NUL, '%', '@', '/') is refused before any of that.
func ValidHost(h string) bool {
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == ""
	}
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}
