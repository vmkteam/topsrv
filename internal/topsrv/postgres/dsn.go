package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	defaultPGUser = "topsrv"
	defaultPGDB   = "postgres"
)

var pgPortRe = regexp.MustCompile(`(?m)^\s*port\s*=\s*(\d+)`)

// BuildDSN constructs a PostgreSQL DSN for auto-discovery.
// Instance is "host:port". Token is used to derive the password via SHA-256;
// if empty, the DSN has no password (peer/trust auth).
func BuildDSN(instance, token string) string {
	host, port, err := net.SplitHostPort(instance)
	if err != nil {
		host = instance
		port = "5432"
	}

	u := &url.URL{
		Scheme:   "postgres",
		Host:     net.JoinHostPort(host, port),
		Path:     defaultPGDB,
		RawQuery: "sslmode=disable",
	}

	if token != "" {
		u.User = url.UserPassword(defaultPGUser, DerivePassword(token))
	} else {
		u.User = url.User(defaultPGUser)
	}

	return u.String()
}

// DerivePassword returns the first 32 hex characters of SHA-256(token).
// This matches the algorithm in gatesrv useCrypto.ts:derivePassword().
func DerivePassword(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])[:32]
}

// parsePostgresPort reads postgresql.conf and extracts the port setting.
// Returns 0 if the file cannot be read or port is not set.
func parsePostgresPort(configPath string) int {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return 0
	}

	// Find the last uncommented "port = NNNN" line (last wins in postgresql.conf).
	var port int
	for _, m := range pgPortRe.FindAllStringSubmatch(string(data), -1) {
		line := strings.TrimSpace(m[0])
		if strings.HasPrefix(line, "#") {
			continue
		}
		if p, err := strconv.Atoi(m[1]); err == nil {
			port = p
		}
	}

	return port
}

// UpdateInstance replaces the port in instance string if configPath provides a non-default port.
// Used by discovery when PostgreSQL is configured to listen on a non-default port.
func UpdateInstance(instance, configPath string) string {
	if configPath == "" {
		return instance
	}
	port := parsePostgresPort(configPath)
	if port == 0 {
		return instance
	}

	host, _, err := net.SplitHostPort(instance)
	if err != nil {
		return instance
	}
	return fmt.Sprintf("%s:%d", host, port)
}
