// Package dockerapi reads the Docker Engine: how dockerd is configured — its
// arguments, daemon.json, the addresses it listens on — and, over its unix
// socket, a few GET endpoints. Parsing is pure; finding the daemon and
// reading its files is the caller's.
package dockerapi

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Protocols of Host.
const (
	ProtoUnix  = "unix"
	ProtoTCP   = "tcp"
	ProtoFD    = "fd" // a socket systemd passes (docker.socket)
	ProtoNpipe = "npipe"
)

// DefaultUnixSocket is where dockerd listens without -H or hosts.
const DefaultUnixSocket = "/var/run/docker.sock"

// Defaults of a TCP address (opts.DefaultHTTPHost, DefaultHTTPPort and
// DefaultTLSHTTPPort): "tcp://:2375" is localhost.
const (
	defaultTCPHost = "localhost"
	defaultTCPPort = "2375"
	defaultTLSPort = "2376"
)

// Host is an address dockerd listens on, normalized as dockerd does.
type Host struct {
	Proto string
	// Addr is the socket path for unix, host:port for tcp, the descriptor
	// for fd ("" for all of them).
	Addr string
}

func (h Host) String() string { return h.Proto + "://" + h.Addr }

var errBadHost = errors.New("dockerapi: invalid host")

// ParseHost is ParseDaemonHost of moby: "unix:///path", "tcp://host:port",
// "fd://" or "fd://3"; without a scheme the address is TCP; an empty host is
// localhost, an empty port 2375.
func ParseHost(s string) (Host, error) {
	s = strings.TrimSpace(s)
	proto, addr, ok := strings.Cut(s, "://")
	if !ok && proto != "" {
		addr, proto = proto, ProtoTCP
	}
	switch proto {
	case ProtoTCP:
		return parseTCP(addr)
	case ProtoUnix, ProtoNpipe:
		if strings.Contains(addr, "://") {
			return Host{}, errBadHost
		}
		if addr == "" && proto == ProtoUnix {
			addr = DefaultUnixSocket
		}
		return Host{Proto: proto, Addr: addr}, nil
	case ProtoFD:
		return Host{Proto: ProtoFD, Addr: addr}, nil
	}
	return Host{}, errBadHost
}

// parseTCP is ParseTCPAddr: no path, a port 1–65535 when given. A user
// part dockerd ignores, and so is it dropped here, never kept.
func parseTCP(addr string) (Host, error) {
	u, err := url.Parse("tcp://" + addr)
	if err != nil || u.Path != "" {
		return Host{}, errBadHost
	}
	host, port := u.Hostname(), u.Port()
	if port != "" {
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return Host{}, errBadHost
		}
	}
	if host == "" {
		host = defaultTCPHost
	}
	if port == "" {
		port = defaultTCPPort
	}
	return Host{Proto: ProtoTCP, Addr: net.JoinHostPort(host, port)}, nil
}

// DefaultHosts are what dockerd listens on with no host set: the unix
// socket, or with --tls the TLS port of localhost.
func DefaultHosts(tls bool) []Host {
	if tls {
		return []Host{{Proto: ProtoTCP, Addr: net.JoinHostPort(defaultTCPHost, defaultTLSPort)}}
	}
	return []Host{{Proto: ProtoUnix, Addr: DefaultUnixSocket}}
}

// ListenStreamHost is a ListenStream= of a socket unit (docker.socket):
// an absolute path is a unix socket, anything else a TCP port or address.
func ListenStreamHost(v string) (Host, error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return Host{}, errBadHost
	case strings.HasPrefix(v, "/"), strings.HasPrefix(v, "@"): // a path, or an abstract socket
		return Host{Proto: ProtoUnix, Addr: v}, nil
	case !strings.Contains(v, ":"): // a port alone: every address, dual-stack
		v = "[::]:" + v
	}
	return parseTCP(v)
}
