// Package router is the rule engine: it decides, for a destination requested
// on a listener, which rule applies and which egress names it points at. It
// knows nothing about health or dialing.
package router

import (
	"net/netip"

	"tr-proxy/internal/config"
)

// Table is a compiled rule list.
type Table struct {
	rules            []rule
	listenerDefaults map[string]string
	def              string
}

type rule struct {
	name     string
	matchers []config.Matcher
	via      []string
	only     map[string]bool // nil: no restriction
	except   map[string]bool
}

// Decision is the outcome for one destination.
type Decision struct {
	Rule string   // name of the matching rule; empty when a default applied
	Via  []string // egress names, in failover order; never empty
}

// Compile builds a Table from a validated config.
func Compile(c *config.Config) (*Table, error) {
	t := &Table{def: c.Default, listenerDefaults: map[string]string{}}
	for _, l := range c.Listeners {
		if l.Default != "" {
			t.listenerDefaults[l.Name] = l.Default
		}
	}
	for _, r := range c.Rules {
		cr := rule{name: r.Name, via: r.Via, only: set(r.OnlyListeners), except: set(r.ExceptListeners)}
		for _, m := range r.Match {
			pm, err := config.ParseMatcher(m)
			if err != nil {
				return nil, err
			}
			cr.matchers = append(cr.matchers, pm)
		}
		t.rules = append(t.rules, cr)
	}
	return t, nil
}

func set(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// Select returns the first rule in scope for the listener that matches host,
// or the listener's default, or the global default. host is a hostname or an
// IP address as the client sent it: an address is only compared with address
// matchers and a hostname only with hostname matchers.
func (t *Table) Select(listener, host string) Decision {
	ip, isIP := netip.Addr{}, false
	if a, err := netip.ParseAddr(host); err == nil {
		ip, isIP = a, true
	}
	for _, r := range t.rules {
		if r.only != nil && !r.only[listener] {
			continue
		}
		if r.except[listener] {
			continue
		}
		for _, m := range r.matchers {
			if isIP && m.MatchIP(ip) || !isIP && m.MatchHost(host) {
				return Decision{Rule: r.name, Via: r.via}
			}
		}
	}
	if d, ok := t.listenerDefaults[listener]; ok {
		return Decision{Via: []string{d}}
	}
	return Decision{Via: []string{t.def}}
}
