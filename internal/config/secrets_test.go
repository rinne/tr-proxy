package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestRedactAndMerge(t *testing.T) {
	stored := mustParse(t, sample)
	stored.WireGuard[0].Peer.PresharedKey = testKey
	stored.Upstreams = append(stored.Upstreams, Upstream{Name: "T", Type: "http", URL: "http://t/",
		Auth: &UpstreamAuth{Type: "bearer", Token: "tok"}})

	red := Redact(stored)
	data, _ := json.Marshal(red)
	for _, secret := range []string{`"p"`, `"pw"`, `"tok"`} {
		if strings.Contains(string(data), secret) {
			t.Errorf("redacted config still contains %s", secret)
		}
	}
	if red.Keys[0].SecretKey != Redacted || red.Keys[0].PublicKey == "" {
		t.Errorf("key not redacted or public key missing: %+v", red.Keys[0])
	}
	if red.WireGuard[1].Peer.PresharedKey != "" {
		t.Error("an absent preshared key became a placeholder")
	}
	if stored.Keys[0].SecretKey != testKey {
		t.Error("Redact modified its input")
	}

	// A round trip of the redacted form restores everything.
	back, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	MergeSecrets(back, stored)
	if !reflect.DeepEqual(back, stored) {
		t.Errorf("merge did not restore the config:\n got %+v\nwant %+v", back, stored)
	}

	// A placeholder with nothing stored behind it is rejected.
	back, _ = Parse(data)
	back.Keys[0].Name = "renamed"
	back.WireGuard[0].LocalKey, back.WireGuard[1].LocalKey = "renamed", "renamed"
	MergeSecrets(back, stored)
	if err := Validate(back, testPorts); err == nil || !strings.Contains(err.Error(), "secretKey must be given") {
		t.Errorf("renamed key with a placeholder: %v", err)
	}

	// New values given in the write win over stored ones.
	back, _ = Parse(data)
	back.Listeners[0].Auth.Users[0].Password = "new-pw"
	MergeSecrets(back, stored)
	if back.Listeners[0].Auth.Users[0].Password != "new-pw" {
		t.Error("a new password was overwritten by the stored one")
	}
}

func TestStripURLLogins(t *testing.T) {
	c := New()
	c.Upstreams = []Upstream{
		{Name: "a", Type: "http", URL: "https://user:secret@proxy.example:8443/"},
		{Name: "b", Type: "http", URL: "http://proxy.example/"},
		{Name: "c", Type: "socks5", URL: "socks5://u@socks.example:1080"},
	}
	names := StripURLLogins(c)
	if len(names) != 2 || names[0] != "a" || names[1] != "c" {
		t.Fatalf("names = %q, want [a c]", names)
	}
	for i, want := range []string{"https://proxy.example:8443/", "http://proxy.example/", "socks5://socks.example:1080"} {
		if c.Upstreams[i].URL != want {
			t.Errorf("upstream %d: url %q, want %q", i, c.Upstreams[i].URL, want)
		}
	}
}
