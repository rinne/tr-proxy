package router

import (
	"reflect"
	"testing"

	"tr-proxy/internal/config"
)

func TestSelect(t *testing.T) {
	c := config.New()
	c.Listeners = []config.Listener{
		{Name: "main", Type: "socks5", Port: 1080},
		{Name: "office", Type: "http", Port: 1081, Default: "Office1"},
	}
	c.Rules = []config.Rule{
		{Name: "corp", Match: []string{"*.corp.example.com", "10.20.0.0/16"}, Via: config.Via{"Office1", "Office2"}},
		{Name: "range", Match: []string{"1.2.3.4-1.2.3.7"}, Via: config.Via{"H-Proxy"}, ExceptListeners: []string{"office"}},
		{Name: "main-only", Match: []string{"only.example.com"}, Via: config.Via{"block"}, OnlyListeners: []string{"main"}},
		{Name: "first", Match: []string{"twice.example.com"}, Via: config.Via{"A"}},
		{Name: "second", Match: []string{"twice.example.com"}, Via: config.Via{"B"}},
	}
	table, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		listener, host string
		rule           string
		via            []string
	}{
		{"main", "a.corp.example.com", "corp", []string{"Office1", "Office2"}},
		{"main", "A.Corp.Example.COM", "corp", []string{"Office1", "Office2"}},
		{"main", "corp.example.com", "", []string{"direct"}},
		{"main", "10.20.30.40", "corp", []string{"Office1", "Office2"}},
		{"main", "10.21.0.1", "", []string{"direct"}},
		{"main", "1.2.3.5", "range", []string{"H-Proxy"}},
		{"office", "1.2.3.5", "", []string{"Office1"}},
		{"main", "only.example.com", "main-only", []string{"block"}},
		{"office", "only.example.com", "", []string{"Office1"}},
		{"main", "twice.example.com", "first", []string{"A"}},
		{"main", "other.example.com", "", []string{"direct"}},
		{"office", "other.example.com", "", []string{"Office1"}},
		{"unknown-listener", "other.example.com", "", []string{"direct"}},
	}
	for _, tc := range cases {
		got := table.Select(tc.listener, tc.host)
		if got.Rule != tc.rule || !reflect.DeepEqual(got.Via, tc.via) {
			t.Errorf("Select(%q, %q) = %+v, want rule %q via %v", tc.listener, tc.host, got, tc.rule, tc.via)
		}
	}
}
