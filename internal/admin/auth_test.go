package admin

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestHOTPVectors(t *testing.T) {
	// RFC 4226, appendix D.
	secret := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, w := range want {
		if got := hotp(secret, uint64(counter)); got != w {
			t.Errorf("hotp(%d) = %s, want %s", counter, got, w)
		}
	}
	// RFC 6238, appendix B (SHA-1), truncated to six digits.
	if got := TOTPCode(secret, time.Unix(59, 0)); got != "287082" {
		t.Errorf("TOTP at 59s = %s, want 287082", got)
	}
	if got := TOTPCode(secret, time.Unix(1111111109, 0)); got != "081804" {
		t.Errorf("TOTP at 1111111109s = %s, want 081804", got)
	}
}

func newTestAuth(totp []byte) (*Auth, *time.Time) {
	a := NewAuth(Credentials{Username: "admin", Password: "secret", TOTPSecret: totp})
	now := time.Unix(1_800_000_000, 0)
	a.now = func() time.Time { return now }
	return a, &now
}

func TestLoginAndSessions(t *testing.T) {
	a, now := newTestAuth(nil)

	for _, bad := range [][2]string{{"admin", "wrong"}, {"root", "secret"}, {"", ""}} {
		if _, _, err := a.Login("192.0.2.1:1234", bad[0], bad[1], ""); !errors.Is(err, ErrBadLogin) {
			t.Errorf("Login(%q, %q) = %v, want ErrBadLogin", bad[0], bad[1], err)
		}
	}
	token, expires, err := a.Login("192.0.2.1:1234", "admin", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Valid(token) || a.Valid("nope") || a.Valid("") {
		t.Error("session validity is wrong")
	}
	if !expires.Equal(now.Add(sessionTTL)) {
		t.Errorf("expires %v", expires)
	}

	*now = now.Add(sessionTTL + time.Second)
	if a.Valid(token) {
		t.Error("session outlived its expiry")
	}

	token, _, _ = a.Login("192.0.2.1:1234", "admin", "secret", "")
	a.Logout(token)
	if a.Valid(token) {
		t.Error("session survived logout")
	}
}

func TestRateLimit(t *testing.T) {
	a, now := newTestAuth(nil)
	for i := 0; i < maxFailures; i++ {
		if _, _, err := a.Login("192.0.2.1:1234", "admin", "wrong", ""); !errors.Is(err, ErrBadLogin) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, _, err := a.Login("192.0.2.1:5678", "admin", "secret", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("after %d failures: %v, want ErrRateLimited", maxFailures, err)
	}
	// Another client is not locked out.
	if _, _, err := a.Login("192.0.2.2:1234", "admin", "secret", ""); err != nil {
		t.Fatalf("another address: %v", err)
	}
	*now = now.Add(failureWindow + time.Second)
	if _, _, err := a.Login("192.0.2.1:1234", "admin", "secret", ""); err != nil {
		t.Fatalf("after the window: %v", err)
	}
	if len(a.failures) != 0 {
		t.Errorf("failures of sources outside the window are kept: %v", a.failures)
	}
}

func TestRateLimitIPv6Prefix(t *testing.T) {
	a, _ := newTestAuth(nil)
	// Every attempt from another address of the same /64.
	for i := 0; i < maxFailures; i++ {
		client := fmt.Sprintf("[2001:db8:1:2::%x]:443", i+1)
		if _, _, err := a.Login(client, "admin", "wrong", ""); !errors.Is(err, ErrBadLogin) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, _, err := a.Login("[2001:db8:1:2::ffff]:443", "admin", "secret", ""); !errors.Is(err, ErrRateLimited) {
		t.Errorf("same /64: %v, want ErrRateLimited", err)
	}
	if _, _, err := a.Login("[2001:db8:1:3::1]:443", "admin", "secret", ""); err != nil {
		t.Errorf("another /64: %v", err)
	}
}

func TestRateLimitAllSources(t *testing.T) {
	a, now := newTestAuth(nil)
	for i := 0; i < maxFailuresAll; i++ {
		client := fmt.Sprintf("198.51.100.%d:1000", i)
		if _, _, err := a.Login(client, "admin", "wrong", ""); !errors.Is(err, ErrBadLogin) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, _, err := a.Login("203.0.113.9:1000", "admin", "secret", ""); !errors.Is(err, ErrRateLimited) {
		t.Errorf("after %d failures from many addresses: %v, want ErrRateLimited", maxFailuresAll, err)
	}
	*now = now.Add(failureWindow + time.Second)
	if _, _, err := a.Login("203.0.113.9:1000", "admin", "secret", ""); err != nil {
		t.Errorf("after the window: %v", err)
	}
}

func TestTOTP(t *testing.T) {
	secret := []byte("a totp secret")
	a, now := newTestAuth(secret)

	if _, _, err := a.Login("192.0.2.1:1234", "admin", "secret", ""); !errors.Is(err, ErrBadLogin) {
		t.Errorf("no code: %v", err)
	}
	if _, _, err := a.Login("192.0.2.1:1234", "admin", "secret", "000000"); !errors.Is(err, ErrBadLogin) {
		t.Errorf("wrong code: %v", err)
	}
	code := TOTPCode(secret, *now)
	if _, _, err := a.Login("192.0.2.1:1234", "admin", "wrong", code); !errors.Is(err, ErrBadLogin) {
		t.Errorf("right code, wrong password: %v", err)
	}
	// A wrong password does not use the code up.
	if _, _, err := a.Login("192.0.2.1:1234", "admin", "secret", code); err != nil {
		t.Fatalf("right code: %v", err)
	}
	if _, _, err := a.Login("192.0.2.1:1234", "admin", "secret", code); !errors.Is(err, ErrBadLogin) {
		t.Errorf("code reuse: %v", err)
	}

	// The previous step's code is accepted (clock drift), a much older one
	// is not.
	*now = now.Add(5 * time.Minute)
	if _, _, err := a.Login("192.0.2.1:1234", "admin", "secret", TOTPCode(secret, now.Add(-2*time.Minute))); !errors.Is(err, ErrBadLogin) {
		t.Errorf("old code: %v", err)
	}
	if _, _, err := a.Login("192.0.2.1:1234", "admin", "secret", TOTPCode(secret, now.Add(-totpStep))); err != nil {
		t.Errorf("previous step's code: %v", err)
	}
}
