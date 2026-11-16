package config

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// 32 zero bytes, base64. Valid in form only.
const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

var testPorts = PortRange{Lo: 1080, Hi: 1099}

const sample = `{
  "version": 1,
  "keys": [{ "name": "home-key", "secretKey": "` + testKey + `" }],
  "wireguard": [
    {
      "name": "Office1", "localKey": "home-key", "addresses": ["10.8.0.5/32"],
      "peer": { "publicKey": "` + testKey + `", "endpoint": "vpn.example.com:51820", "presharedKey": null },
      "dns": ["10.8.0.1"],
      "probe": { "type": "dns" }
    },
    {
      "name": "Office2", "localKey": "home-key", "addresses": ["10.9.0.5"],
      "peer": { "publicKey": "` + testKey + `", "endpoint": "21.12.44.44:51820", "keepalive": 0 }
    }
  ],
  "upstreams": [
    { "name": "H-Proxy", "type": "http", "url": "https://hproxy.example.com/",
      "auth": { "type": "basic", "username": "u", "password": "p" } }
  ],
  "listeners": [
    { "name": "main-socks", "type": "socks5", "port": 1080,
      "auth": { "users": [{ "username": "alice", "password": "pw" }] } },
    { "name": "office-http", "type": "http", "port": 1081, "auth": null, "default": "Office1" }
  ],
  "rules": [
    { "name": "corp", "match": ["*.corp.example.com", "10.20.0.0/16"], "via": ["Office1", "Office2"] },
    { "name": "range", "match": ["1.2.3.4-1.2.3.7"], "via": "H-Proxy", "exceptListeners": ["office-http"] },
    { "name": "ads", "match": ["ads.example.net"], "via": "block" }
  ],
  "default": "direct"
}`

func mustParse(t *testing.T, s string) *Config {
	t.Helper()
	c, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSampleIsValid(t *testing.T) {
	c := mustParse(t, sample)
	if err := Validate(c, testPorts); err != nil {
		t.Fatalf("sample config rejected:\n%v", err)
	}
	if got := c.Rules[0].Via; !reflect.DeepEqual(got, Via{"Office1", "Office2"}) {
		t.Errorf("list via = %v", got)
	}
	if got := c.Rules[1].Via; !reflect.DeepEqual(got, Via{"H-Proxy"}) {
		t.Errorf("string via = %v", got)
	}
}

func TestNewIsValid(t *testing.T) {
	if err := Validate(New(), testPorts); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte(`{"version":1,"defualt":"direct"}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"version", func(c *Config) { c.Version = 2 }, "version"},
		{"bad secret key", func(c *Config) { c.Keys[0].SecretKey = "short" }, "secretKey"},
		{"duplicate key", func(c *Config) { c.Keys = append(c.Keys, c.Keys[0]) }, "duplicate name"},
		{"unknown local key", func(c *Config) { c.WireGuard[0].LocalKey = "nope" }, "unknown localKey"},
		{"no addresses", func(c *Config) { c.WireGuard[0].Addresses = nil }, "addresses is required"},
		{"bad endpoint", func(c *Config) { c.WireGuard[0].Peer.Endpoint = "1.2.3.4" }, "peer.endpoint"},
		{"reserved name", func(c *Config) { c.WireGuard[0].Name = "direct" }, "reserved"},
		{"shared namespace", func(c *Config) { c.Upstreams[0].Name = "Office1" }, "duplicate name"},
		{"dns probe without dns", func(c *Config) { c.WireGuard[0].DNS = nil }, "needs a dns server"},
		{"tcp probe without target", func(c *Config) { c.WireGuard[0].Probe = &Probe{Type: ProbeTCP} }, "target host:port"},
		{"upstream url", func(c *Config) { c.Upstreams[0].URL = "socks5://x" }, "url must be"},
		{"port out of range", func(c *Config) { c.Listeners[0].Port = 8080 }, "outside PROXY_PORT_RANGE"},
		{"port clash", func(c *Config) { c.Listeners[1].Port = 1080 }, "already used"},
		{"empty auth", func(c *Config) { c.Listeners[0].Auth.Users = nil }, "auth has no users"},
		{"listener default", func(c *Config) { c.Listeners[1].Default = "nope" }, "unknown connection"},
		{"rule via", func(c *Config) { c.Rules[0].Via = Via{"nope"} }, "unknown connection"},
		{"block in list", func(c *Config) { c.Rules[0].Via = Via{"Office1", "block"} }, "failover list"},
		{"rule matcher", func(c *Config) { c.Rules[0].Match = []string{"1.2.3.0/40"} }, "invalid network"},
		{"only and except", func(c *Config) { c.Rules[1].OnlyListeners = []string{"main-socks"} }, "mutually exclusive"},
		{"unknown listener", func(c *Config) { c.Rules[1].ExceptListeners = []string{"nope"} }, "unknown listener"},
		{"no default", func(c *Config) { c.Default = "" }, "default: required"},
		{"max connections", func(c *Config) { n := 0; c.Limits = &Limits{MaxConnections: &n} }, "maxConnections"},
		{"idle timeout", func(c *Config) { n := -1; c.Limits = &Limits{IdleTimeout: &n} }, "idleTimeout"},
		{"drain timeout", func(c *Config) { n := 4000; c.Limits = &Limits{DrainTimeout: &n} }, "drainTimeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := mustParse(t, sample)
			tc.mutate(c)
			err := Validate(c, testPorts)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := Load(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: got %v, want ErrNotExist", err)
	}

	want := mustParse(t, sample)
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the config:\n got %+v\nwant %+v", got, want)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode %o, want 600", perm)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestMatcher(t *testing.T) {
	cases := []struct {
		matcher string
		target  string // hostname or IP
		want    bool
	}{
		{"host.example.com", "host.example.com", true},
		{"host.example.com", "HOST.Example.com.", true},
		{"host.example.com", "x.host.example.com", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "badexample.com", false},
		{"my-host.example.com", "my-host.example.com", true},
		{"1.2.3.4", "1.2.3.4", true},
		{"1.2.3.4", "1.2.3.5", false},
		{"1.2.3.0/24", "1.2.3.200", true},
		{"1.2.3.0/24", "1.2.4.1", false},
		{"1.2.3.4-1.2.3.7", "1.2.3.4", true},
		{"1.2.3.4-1.2.3.7", "1.2.3.7", true},
		{"1.2.3.4-1.2.3.7", "1.2.3.8", false},
		{"1.2.3.4", "host.example.com", false},
		{"host.example.com", "1.2.3.4", false},
	}
	for _, tc := range cases {
		m, err := ParseMatcher(tc.matcher)
		if err != nil {
			t.Errorf("ParseMatcher(%q): %v", tc.matcher, err)
			continue
		}
		var got bool
		if a, err := netip.ParseAddr(tc.target); err == nil {
			got = m.MatchIP(a)
		} else {
			got = m.MatchHost(tc.target)
		}
		if got != tc.want {
			t.Errorf("%q vs %q = %v, want %v", tc.matcher, tc.target, got, tc.want)
		}
	}

	for _, bad := range []string{"", "1.2.3.7-1.2.3.4", "1.2.3.4-x", "1.2.3.0/40", "bad host", "*.", "-a.example.com"} {
		if _, err := ParseMatcher(bad); err == nil {
			t.Errorf("ParseMatcher(%q) accepted", bad)
		}
	}
}

func TestParsePortRange(t *testing.T) {
	r, err := ParsePortRange("1080-1099")
	if err != nil || r != (PortRange{1080, 1099}) {
		t.Fatalf("got %v, %v", r, err)
	}
	if !r.Contains(1080) || !r.Contains(1099) || r.Contains(1100) {
		t.Error("Contains is wrong at the edges")
	}
	for _, bad := range []string{"", "x", "1099-1080", "0-10", "1-70000"} {
		if _, err := ParsePortRange(bad); err == nil {
			t.Errorf("ParsePortRange(%q) accepted", bad)
		}
	}
}

func TestEffectiveLimits(t *testing.T) {
	c := New()
	got := c.EffectiveLimits()
	want := EffectiveLimits{MaxConnections: 1024, IdleTimeout: time.Hour, DrainTimeout: 5 * time.Second}
	if got != want {
		t.Errorf("defaults: %+v, want %+v", got, want)
	}

	c = mustParse(t, `{"version":1,"default":"direct","limits":{"maxConnections":10,"idleTimeout":0,"drainTimeout":30,"allowLocalDirect":true}}`)
	if err := Validate(c, testPorts); err != nil {
		t.Fatal(err)
	}
	got = c.EffectiveLimits()
	want = EffectiveLimits{MaxConnections: 10, IdleTimeout: 0, DrainTimeout: 30 * time.Second, AllowLocalDirect: true}
	if got != want {
		t.Errorf("explicit: %+v, want %+v", got, want)
	}

	// Only some fields given: the others keep their defaults.
	c = mustParse(t, `{"version":1,"default":"direct","limits":{"drainTimeout":0}}`)
	got = c.EffectiveLimits()
	want = EffectiveLimits{MaxConnections: 1024, IdleTimeout: time.Hour, DrainTimeout: 0}
	if got != want {
		t.Errorf("partial: %+v, want %+v", got, want)
	}
}
