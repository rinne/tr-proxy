package wgkey

import "testing"

func TestKeys(t *testing.T) {
	secret, public, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Public(secret)
	if err != nil || got != public {
		t.Fatalf("Public(secret) = %q, %v; want %q", got, err, public)
	}
	if h, err := Hex(public); err != nil || len(h) != 64 {
		t.Fatalf("Hex = %q, %v", h, err)
	}
	for _, bad := range []string{"", "short", "!!!!"} {
		if _, err := Public(bad); err == nil {
			t.Errorf("Public(%q) accepted", bad)
		}
	}
}
