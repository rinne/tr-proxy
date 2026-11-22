package netutil

import (
	"strings"
	"testing"
)

func TestValidHost(t *testing.T) {
	good := []string{
		"example.com", "a.b-c.example", "_sip._tcp.example.com", "localhost", "xn--bcher-kva.example",
		"1.2.3.4", "::1", "2001:db8::1", "1e100.net", strings.Repeat("a", 63) + ".com",
	}
	for _, h := range good {
		if !ValidHost(h) {
			t.Errorf("ValidHost(%q) = false, want true", h)
		}
	}
	bad := []string{
		"", "example.com\r\nX-Injected: 1", "a b.com", "evil.com:80", "user@host", "a/b", "a%2fb",
		"-a.com", "a-.com", "a..com", ".a.com", "a\x00.com", "fe80::1%eth0",
		"127.1", "2130706433", "0x7f.1", "10.0.0.1.2",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com",
	}
	for _, h := range bad {
		if ValidHost(h) {
			t.Errorf("ValidHost(%q) = true, want false", h)
		}
	}
}
