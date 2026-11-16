// Package config defines the JSON configuration (SPEC.md section 5) and its
// loading, validation and atomic saving.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Version is the config schema version this build reads and writes.
const Version = 1

// Reserved egress names.
const (
	EgressDirect = "direct"
	EgressBlock  = "block"
)

// Defaults applied when a field is left out.
const (
	DefaultKeepalive = 25
	DefaultMTU       = 1420
)

type Config struct {
	Version   int         `json:"version"`
	Keys      []Key       `json:"keys"`
	WireGuard []WireGuard `json:"wireguard"`
	Upstreams []Upstream  `json:"upstreams"`
	Listeners []Listener  `json:"listeners"`
	Rules     []Rule      `json:"rules"`
	Default   string      `json:"default"`
}

type Key struct {
	Name      string `json:"name"`
	SecretKey string `json:"secretKey"`
}

type WireGuard struct {
	Name      string   `json:"name"`
	LocalKey  string   `json:"localKey"`
	Addresses []string `json:"addresses"`
	Peer      Peer     `json:"peer"`
	DNS       []string `json:"dns,omitempty"`
	MTU       int      `json:"mtu,omitempty"`
	Probe     *Probe   `json:"probe,omitempty"`
}

type Peer struct {
	PublicKey    string `json:"publicKey"`
	Endpoint     string `json:"endpoint"`
	PresharedKey string `json:"presharedKey,omitempty"`
	// Keepalive in seconds; nil means DefaultKeepalive, 0 disables it.
	Keepalive *int `json:"keepalive,omitempty"`
}

// Probe types.
const (
	ProbeDNS       = "dns"
	ProbeTCP       = "tcp"
	ProbeICMP      = "icmp"
	ProbeHandshake = "handshake"
)

type Probe struct {
	Type     string `json:"type"`
	Target   string `json:"target,omitempty"`
	Interval int    `json:"interval,omitempty"` // seconds
	Timeout  int    `json:"timeout,omitempty"`  // seconds
	Failures int    `json:"failures,omitempty"` // consecutive failures before down
}

// Probe defaults.
const (
	DefaultProbeInterval = 15
	DefaultProbeTimeout  = 5
	DefaultProbeFailures = 3
)

// EffectiveProbe returns the connection's probe with the defaults filled in:
// dns when the connection has a DNS server, handshake otherwise.
func (w WireGuard) EffectiveProbe() Probe {
	var p Probe
	if w.Probe != nil {
		p = *w.Probe
	}
	if p.Type == "" {
		p.Type = ProbeHandshake
		if len(w.DNS) > 0 {
			p.Type = ProbeDNS
		}
	}
	if p.Interval == 0 {
		p.Interval = DefaultProbeInterval
	}
	if p.Timeout == 0 {
		p.Timeout = DefaultProbeTimeout
	}
	if p.Failures == 0 {
		p.Failures = DefaultProbeFailures
	}
	return p
}

// KeepaliveSeconds returns the peer's keepalive with the default applied.
func (p Peer) KeepaliveSeconds() int {
	if p.Keepalive == nil {
		return DefaultKeepalive
	}
	return *p.Keepalive
}

type Upstream struct {
	Name string        `json:"name"`
	Type string        `json:"type"`
	URL  string        `json:"url"`
	Auth *UpstreamAuth `json:"auth,omitempty"`
}

type UpstreamAuth struct {
	Type     string `json:"type"` // "basic" or "bearer"
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
}

type Listener struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"` // "socks5" or "http"
	Port    int           `json:"port"`
	Auth    *ListenerAuth `json:"auth,omitempty"`
	Default string        `json:"default,omitempty"`
}

type ListenerAuth struct {
	Users []User `json:"users"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Rule struct {
	Name            string   `json:"name"`
	Match           []string `json:"match"`
	Via             Via      `json:"via"`
	OnlyListeners   []string `json:"onlyListeners,omitempty"`
	ExceptListeners []string `json:"exceptListeners,omitempty"`
}

// Via is one egress name or a failover list of them. In JSON it is either a
// string or an array of strings.
type Via []string

func (v *Via) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*v = Via{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("via must be a string or a list of strings")
	}
	*v = many
	return nil
}

func (v Via) MarshalJSON() ([]byte, error) {
	if len(v) == 1 {
		return json.Marshal(v[0])
	}
	return json.Marshal([]string(v))
}

// New returns an empty, valid config.
func New() *Config {
	return &Config{
		Version:   Version,
		Keys:      []Key{},
		WireGuard: []WireGuard{},
		Upstreams: []Upstream{},
		Listeners: []Listener{},
		Rules:     []Rule{},
		Default:   EgressDirect,
	}
}

// Parse decodes a config. Unknown fields are an error so that typos do not
// silently change behaviour. It does not validate; call Validate.
func Parse(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse config: trailing data after the JSON object")
	}
	return &c, nil
}

// Load reads and parses the config file. A missing file is reported with an
// error that satisfies errors.Is(err, os.ErrNotExist).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Save writes the config atomically: temp file in the same directory, fsync,
// rename, fsync of the directory. The file holds secrets and is created 0600.
func Save(path string, c *Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// KeyByName returns the named key.
func (c *Config) KeyByName(name string) (Key, bool) {
	for _, k := range c.Keys {
		if k.Name == name {
			return k, true
		}
	}
	return Key{}, false
}
