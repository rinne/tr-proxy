package admin

import (
	"errors"
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
		if _, _, err := a.Login(bad[0], bad[1], ""); !errors.Is(err, ErrBadLogin) {
			t.Errorf("Login(%q, %q) = %v, want ErrBadLogin", bad[0], bad[1], err)
		}
	}
	token, expires, err := a.Login("admin", "secret", "")
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

	token, _, _ = a.Login("admin", "secret", "")
	a.Logout(token)
	if a.Valid(token) {
		t.Error("session survived logout")
	}
}

func TestRateLimit(t *testing.T) {
	a, now := newTestAuth(nil)
	for i := 0; i < maxFailures; i++ {
		if _, _, err := a.Login("admin", "wrong", ""); !errors.Is(err, ErrBadLogin) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, _, err := a.Login("admin", "secret", ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("after %d failures: %v, want ErrRateLimited", maxFailures, err)
	}
	*now = now.Add(failureWindow + time.Second)
	if _, _, err := a.Login("admin", "secret", ""); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

func TestTOTP(t *testing.T) {
	secret := []byte("a totp secret")
	a, now := newTestAuth(secret)

	if _, _, err := a.Login("admin", "secret", ""); !errors.Is(err, ErrBadLogin) {
		t.Errorf("no code: %v", err)
	}
	if _, _, err := a.Login("admin", "secret", "000000"); !errors.Is(err, ErrBadLogin) {
		t.Errorf("wrong code: %v", err)
	}
	code := TOTPCode(secret, *now)
	if _, _, err := a.Login("admin", "wrong", code); !errors.Is(err, ErrBadLogin) {
		t.Errorf("right code, wrong password: %v", err)
	}
	// A wrong password does not use the code up.
	if _, _, err := a.Login("admin", "secret", code); err != nil {
		t.Fatalf("right code: %v", err)
	}
	if _, _, err := a.Login("admin", "secret", code); !errors.Is(err, ErrBadLogin) {
		t.Errorf("code reuse: %v", err)
	}

	// The previous step's code is accepted (clock drift), a much older one
	// is not.
	*now = now.Add(5 * time.Minute)
	if _, _, err := a.Login("admin", "secret", TOTPCode(secret, now.Add(-2*time.Minute))); !errors.Is(err, ErrBadLogin) {
		t.Errorf("old code: %v", err)
	}
	if _, _, err := a.Login("admin", "secret", TOTPCode(secret, now.Add(-totpStep))); err != nil {
		t.Errorf("previous step's code: %v", err)
	}
}
