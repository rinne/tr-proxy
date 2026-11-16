// Package admin is the admin HTTP API: login, sessions, and the REST
// endpoints for configuration and status.
package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	sessionTTL = 12 * time.Hour

	// More than maxFailures failed logins within failureWindow lock the
	// login for everyone until the window has passed. The limit is global
	// because behind Docker's port publishing all clients tend to share one
	// source address.
	maxFailures   = 10
	failureWindow = time.Minute

	totpStep = 30 * time.Second
)

var (
	ErrBadLogin    = errors.New("wrong username, password or code")
	ErrRateLimited = errors.New("too many failed logins; try again in a minute")
)

// Credentials are the admin login, taken from the environment.
type Credentials struct {
	Username   string
	Password   string
	TOTPSecret []byte // nil: no second factor
}

// Auth checks logins and holds the sessions, in memory.
type Auth struct {
	user, pass [sha256.Size]byte
	totp       []byte
	now        func() time.Time

	mu          sync.Mutex
	sessions    map[string]time.Time // token to expiry
	failures    []time.Time
	lastCounter uint64 // last TOTP time step that was accepted
}

func NewAuth(c Credentials) *Auth {
	return &Auth{
		user:     sha256.Sum256([]byte(c.Username)),
		pass:     sha256.Sum256([]byte(c.Password)),
		totp:     c.TOTPSecret,
		now:      time.Now,
		sessions: map[string]time.Time{},
	}
}

// TOTPRequired reports whether logins need a code.
func (a *Auth) TOTPRequired() bool { return a.totp != nil }

// Login checks the credentials and opens a session.
func (a *Auth) Login(username, password, code string) (token string, expires time.Time, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()

	// Drop failures that have left the window.
	recent := a.failures[:0]
	for _, t := range a.failures {
		if now.Sub(t) < failureWindow {
			recent = append(recent, t)
		}
	}
	a.failures = recent
	if len(a.failures) >= maxFailures {
		return "", time.Time{}, ErrRateLimited
	}

	user, pass := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(password))
	ok := subtle.ConstantTimeCompare(user[:], a.user[:]) & subtle.ConstantTimeCompare(pass[:], a.pass[:])
	var counter uint64
	if a.totp != nil {
		var codeOK bool
		counter, codeOK = a.matchTOTP(code, now)
		if !codeOK {
			ok = 0
		}
	}
	if ok != 1 {
		a.failures = append(a.failures, now)
		return "", time.Time{}, ErrBadLogin
	}
	if a.totp != nil {
		a.lastCounter = counter // a code works once
	}

	for t, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, t)
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token = hex.EncodeToString(raw)
	expires = now.Add(sessionTTL)
	a.sessions[token] = expires
	return token, expires, nil
}

// Valid reports whether token names a live session.
func (a *Auth) Valid(token string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[token]
	return ok && a.now().Before(exp)
}

func (a *Auth) Logout(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, token)
}

// matchTOTP accepts the code of the current time step or a neighbouring
// one, unless that step or a later one has been used already.
func (a *Auth) matchTOTP(code string, now time.Time) (uint64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	current := uint64(now.Unix()) / uint64(totpStep.Seconds())
	for _, c := range []uint64{current - 1, current, current + 1} {
		if c > a.lastCounter && subtle.ConstantTimeCompare([]byte(hotp(a.totp, c)), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}

// TOTPCode returns the code for secret at time t (RFC 6238: SHA-1, six
// digits, 30-second steps).
func TOTPCode(secret []byte, t time.Time) string {
	return hotp(secret, uint64(t.Unix())/uint64(totpStep.Seconds()))
}

func hotp(secret []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}
