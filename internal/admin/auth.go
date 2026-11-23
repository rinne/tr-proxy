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
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	sessionTTL = 12 * time.Hour

	// maxFailures failed logins from one source within failureWindow lock
	// the login for that source until the window has passed; a source is
	// an IPv4 address or an IPv6 /64. Behind Docker's userland proxy all
	// clients can share one address, and then this is a lock for everyone,
	// as before. maxFailuresAll failed logins from all sources together
	// lock it for everyone, so that spreading the attempts over many
	// addresses does not allow unlimited guessing.
	maxFailures    = 10
	maxFailuresAll = 100
	failureWindow  = time.Minute

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
	sessions    map[string]time.Time   // token to expiry
	failures    map[string][]time.Time // by source, within failureWindow
	allFailures []time.Time            // all sources, within failureWindow
	lastCounter uint64                 // last TOTP time step that was accepted
}

func NewAuth(c Credentials) *Auth {
	return &Auth{
		user:     sha256.Sum256([]byte(c.Username)),
		pass:     sha256.Sum256([]byte(c.Password)),
		totp:     c.TOTPSecret,
		now:      time.Now,
		sessions: map[string]time.Time{},
		failures: map[string][]time.Time{},
	}
}

// TOTPRequired reports whether logins need a code.
func (a *Auth) TOTPRequired() bool { return a.totp != nil }

// source is what failed logins are counted by: the client's IPv4 address,
// or its IPv6 /64, so that one host cannot pick a fresh address for every
// attempt. client is a host:port, as in http.Request.RemoteAddr.
func source(client string) string {
	host, _, err := net.SplitHostPort(client)
	if err != nil {
		host = client
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().String()
	}
	return ip.String()
}

// recentOnly drops the times that have left the failure window.
func recentOnly(times []time.Time, now time.Time) []time.Time {
	recent := times[:0]
	for _, t := range times {
		if now.Sub(t) < failureWindow {
			recent = append(recent, t)
		}
	}
	return recent
}

// Login checks the credentials of a login from client (host:port) and opens
// a session.
func (a *Auth) Login(client, username, password, code string) (token string, expires time.Time, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()

	// Drop failures that have left the window, and sources without any.
	a.allFailures = recentOnly(a.allFailures, now)
	for src, times := range a.failures {
		if times = recentOnly(times, now); len(times) == 0 {
			delete(a.failures, src)
		} else {
			a.failures[src] = times
		}
	}
	src := source(client)
	if len(a.failures[src]) >= maxFailures || len(a.allFailures) >= maxFailuresAll {
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
		a.failures[src] = append(a.failures[src], now)
		a.allFailures = append(a.allFailures, now)
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
