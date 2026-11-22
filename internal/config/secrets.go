package config

import (
	"encoding/json"
	"net/url"

	"tr-proxy/internal/wgkey"
)

// Redacted stands in for a secret in what the admin API returns. Sent back
// in a write, it means "keep the stored value".
const Redacted = "<redacted>"

// Clone returns a deep copy.
func (c *Config) Clone() *Config {
	data, err := json.Marshal(c)
	if err != nil {
		panic(err) // Config holds only plain data
	}
	var out Config
	if err := json.Unmarshal(data, &out); err != nil {
		panic(err)
	}
	return &out
}

// Redact returns a copy with every secret replaced by Redacted and each
// key's public key filled in.
func Redact(c *Config) *Config {
	out := c.Clone()
	for i := range out.Keys {
		out.Keys[i].PublicKey, _ = wgkey.Public(out.Keys[i].SecretKey)
		out.Keys[i].SecretKey = Redacted
	}
	for i := range out.WireGuard {
		if out.WireGuard[i].Peer.PresharedKey != "" {
			out.WireGuard[i].Peer.PresharedKey = Redacted
		}
	}
	for i := range out.Upstreams {
		if a := out.Upstreams[i].Auth; a != nil {
			if a.Password != "" {
				a.Password = Redacted
			}
			if a.Token != "" {
				a.Token = Redacted
			}
		}
	}
	for i := range out.Listeners {
		if a := out.Listeners[i].Auth; a != nil {
			for j := range a.Users {
				a.Users[j].Password = Redacted
			}
		}
	}
	return out
}

// MergeSecrets replaces every Redacted placeholder in c with the value
// stored under the same name: the key's name, the connection's name, the
// upstream's name, or the listener's name plus the username. A placeholder
// with no stored value stays, and Validate rejects it.
func MergeSecrets(c, stored *Config) {
	for i := range c.Keys {
		c.Keys[i].PublicKey = ""
		if c.Keys[i].SecretKey == Redacted {
			if k, ok := stored.KeyByName(c.Keys[i].Name); ok {
				c.Keys[i].SecretKey = k.SecretKey
			}
		}
	}
	for i := range c.WireGuard {
		if c.WireGuard[i].Peer.PresharedKey != Redacted {
			continue
		}
		for _, w := range stored.WireGuard {
			if w.Name == c.WireGuard[i].Name && w.Peer.PresharedKey != "" {
				c.WireGuard[i].Peer.PresharedKey = w.Peer.PresharedKey
			}
		}
	}
	for i := range c.Upstreams {
		a := c.Upstreams[i].Auth
		if a == nil {
			continue
		}
		for _, u := range stored.Upstreams {
			if u.Name != c.Upstreams[i].Name || u.Auth == nil {
				continue
			}
			if a.Password == Redacted && u.Auth.Password != "" {
				a.Password = u.Auth.Password
			}
			if a.Token == Redacted && u.Auth.Token != "" {
				a.Token = u.Auth.Token
			}
		}
	}
	for i := range c.Listeners {
		a := c.Listeners[i].Auth
		if a == nil {
			continue
		}
		for _, l := range stored.Listeners {
			if l.Name != c.Listeners[i].Name || l.Auth == nil {
				continue
			}
			for j := range a.Users {
				if a.Users[j].Password != Redacted {
					continue
				}
				for _, u := range l.Auth.Users {
					if u.Username == a.Users[j].Username {
						a.Users[j].Password = u.Password
					}
				}
			}
		}
	}
}

// StripURLLogins removes a login (userinfo) from the url of each upstream
// and returns the names of the upstreams that had one. Validate refuses such
// urls; versions before 0.2.2 accepted them for http upstreams, but never
// used the login, and the admin API showed it unredacted. A config file
// written by such a version is cleaned with this when it is loaded.
func StripURLLogins(c *Config) []string {
	var names []string
	for i := range c.Upstreams {
		pu, err := url.Parse(c.Upstreams[i].URL)
		if err != nil || pu.User == nil {
			continue
		}
		pu.User = nil
		c.Upstreams[i].URL = pu.String()
		names = append(names, c.Upstreams[i].Name)
	}
	return names
}
