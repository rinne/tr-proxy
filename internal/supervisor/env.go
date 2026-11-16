package supervisor

import (
	"encoding/base32"
	"fmt"
	"os"
	"strconv"
	"strings"

	"tr-proxy/internal/config"
)

// Env is the supervisor's environment (SPEC.md section 9).
type Env struct {
	AdminUsername string
	AdminPassword string
	// AdminTOTPSecret is the decoded secret; nil when TOTP is off.
	AdminTOTPSecret []byte
	AdminPort       int
	ProxyPorts      config.PortRange
	ConfigPath      string
	// RunDir holds the workers' unix sockets.
	RunDir string
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func adminPort() (int, error) {
	p, err := strconv.Atoi(getenv("ADMIN_PORT", "8080"))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("ADMIN_PORT must be a port number")
	}
	return p, nil
}

// LoadEnv reads and checks the environment. The admin username and password
// are required.
func LoadEnv() (*Env, error) {
	e := &Env{
		AdminUsername: os.Getenv("ADMIN_USERNAME"),
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),
		ConfigPath:    getenv("CONFIG_PATH", "/config/config.json"),
		RunDir:        getenv("RUN_DIR", "/run/tr-proxy"),
	}
	if e.AdminUsername == "" || e.AdminPassword == "" {
		return nil, fmt.Errorf("ADMIN_USERNAME and ADMIN_PASSWORD must be set")
	}

	if s := os.Getenv("ADMIN_TOTP_SECRET"); s != "" {
		s = strings.ToUpper(strings.TrimRight(strings.ReplaceAll(s, " ", ""), "="))
		secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
		if err != nil || len(secret) == 0 {
			return nil, fmt.Errorf("ADMIN_TOTP_SECRET is not valid base32")
		}
		e.AdminTOTPSecret = secret
	}

	var err error
	if e.AdminPort, err = adminPort(); err != nil {
		return nil, err
	}
	if e.ProxyPorts, err = config.ParsePortRange(getenv("PROXY_PORT_RANGE", "1080-1099")); err != nil {
		return nil, fmt.Errorf("PROXY_PORT_RANGE: %w", err)
	}
	if e.ProxyPorts.Contains(e.AdminPort) {
		return nil, fmt.Errorf("ADMIN_PORT %d is inside PROXY_PORT_RANGE %s", e.AdminPort, e.ProxyPorts)
	}
	return e, nil
}
