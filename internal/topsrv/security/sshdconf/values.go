package sshdconf

import (
	"slices"
	"strconv"
	"strings"
)

// CodeBadValue is a value sshd refuses for its keyword: servconf.c checks it
// on every line, the first value or not, and exits.
const CodeBadValue = "bad_value"

// servicesFile is where a2port looks up a Port given as a service name.
const servicesFile = "/etc/services"

// valueChecks are sshd's checks of a keyword's value, by canonical name;
// enum values are checked lowercased. A keyword without a check takes any
// text: user and group patterns, paths, host names. Port and the port of
// ListenAddress are checked by the parser, which reads servicesFile.
var valueChecks = buildValueChecks()

func buildValueChecks() map[string]func(string) bool {
	checks := map[string]func(string) bool{}
	add := func(check func(string) bool, names ...string) {
		for _, n := range names {
			checks[n] = check
		}
	}
	// multistate_flag
	add(oneOf("yes", "no"), "PasswordAuthentication", "KbdInteractiveAuthentication", "PermitEmptyPasswords",
		"PubkeyAuthentication", "HostbasedAuthentication", "HostbasedUsesNameFromPacketOnly",
		"GSSAPIAuthentication", "KerberosAuthentication", "X11Forwarding", "X11UseLocalhost",
		"AllowAgentForwarding", "PermitTTY", "PermitUserRC", "DisableForwarding", "ExposeAuthInfo",
		"StreamLocalBindUnlink", "RefuseConnection", "UsePAM", "StrictModes", "PrintMotd", "PrintLastLog",
		"IgnoreUserKnownHosts", "TCPKeepAlive", "UseDNS", "KerberosOrLocalPasswd", "KerberosTicketCleanup",
		"KerberosGetAFSToken", "GSSAPICleanupCredentials", "GSSAPIStrictAcceptorCheck")
	// without-password is normalized to prohibit-password before the check
	add(oneOf("yes", "no", "prohibit-password", "forced-commands-only"), "PermitRootLogin")
	add(oneOf("yes", "no", "shosts-only"), "IgnoreRhosts")
	add(oneOf("yes", "no", "all", "local", "remote"), "AllowTcpForwarding", "AllowStreamLocalForwarding")
	add(oneOf("yes", "no", "point-to-point", "ethernet"), "PermitTunnel")
	add(oneOf("yes", "no", "clientspecified"), "GatewayPorts")
	add(oneOf("yes", "no", "delayed"), "Compression")
	add(oneOf("inet", "inet6", "any"), "AddressFamily")
	add(oneOf("quiet", "fatal", "error", "info", "verbose", "debug", "debug1", "debug2", "debug3"), "LogLevel")
	add(oneOf("daemon", "user", "auth", "authpriv",
		"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"), "SyslogFacility")
	add(oneOf("md5", "sha256"), "FingerprintHash")
	add(isInt, "MaxAuthTries", "MaxSessions", "ClientAliveCountMax", "RequiredRSASize")
	add(isTime, "LoginGraceTime", "ClientAliveInterval")
	add(isMaxStartups, "MaxStartups")
	add(isAlgorithmList, "Ciphers", "MACs", "KexAlgorithms", "HostKeyAlgorithms", "PubkeyAcceptedAlgorithms",
		"HostbasedAcceptedAlgorithms", "CASignatureAlgorithms")
	add(isAuthMethods, "AuthenticationMethods")
	return checks
}

func oneOf(values ...string) func(string) bool {
	return func(v string) bool { return slices.Contains(values, v) }
}

// isInt is atoi_err of misc.c: 0 to INT_MAX.
func isInt(v string) bool {
	n, err := strconv.ParseInt(v, 10, 32)
	return err == nil && n >= 0
}

// isTime is convtime of misc.c: numbers, each with an optional unit, as
// 90, 2m or 1h30m.
func isTime(v string) bool {
	if v == "" {
		return false
	}
	digits := false
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9':
			digits = true
		case strings.ContainsRune("sSmMhHdDwW", c) && digits:
			digits = false
		default:
			return false
		}
	}
	return true
}

// isMaxStartups: start:rate:full or a single number.
func isMaxStartups(v string) bool {
	parts := strings.Split(v, ":")
	if len(parts) != 1 && len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if !isInt(p) {
			return false
		}
	}
	return true
}

// isAlgorithmList: a comma-separated list with an optional +, - or ^ in
// front. sshd knows the names, all lower case; here only their characters
// are checked, patterns of a "-" list included.
func isAlgorithmList(v string) bool {
	if v != "" && strings.ContainsRune("+-^", rune(v[0])) {
		v = v[1:]
	}
	for name := range strings.SplitSeq(v, ",") {
		if name == "" {
			return false
		}
		for _, c := range name {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && !strings.ContainsRune("@.-_*?", c) {
				return false
			}
		}
	}
	return true
}

// authMethods are the methods AuthenticationMethods may list (auth2.c).
var authMethods = oneOf("publickey", "password", "keyboard-interactive", "hostbased", "gssapi-with-mic", "none")

// isAuthMethods is one AuthenticationMethods list: "any", or methods
// joined by commas, each with an optional :device (bsdauth, pam), which
// sshd cuts off before it looks the method up.
func isAuthMethods(v string) bool {
	if v == "any" {
		return true
	}
	for m := range strings.SplitSeq(v, ",") {
		name, device, hasDevice := strings.Cut(m, ":")
		if !authMethods(name) || hasDevice && !isLowerWord(device) {
			return false
		}
	}
	return true
}

func isLowerWord(s string) bool {
	for _, c := range s {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return s != ""
}

// validPort is a2port of misc.c: 1 to 65535, or a TCP service name from
// /etc/services.
func (p *parser) validPort(v string) bool {
	if n, err := strconv.Atoi(v); err == nil {
		return n > 0 && n <= 65535
	}
	if p.services == nil {
		p.services = readServices(p.files.ReadFile)
	}
	return p.services[v]
}

// readServices returns the TCP service names and aliases of /etc/services;
// none when it cannot be read, as getservbyname finds nothing then.
func readServices(readFile func(string) ([]byte, error)) map[string]bool {
	names := map[string]bool{}
	b, err := readFile(servicesFile)
	if err != nil {
		return names
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) < 2 || !strings.HasSuffix(f[1], "/tcp") {
			continue
		}
		names[f[0]] = true
		for _, alias := range f[2:] {
			names[alias] = true
		}
	}
	return names
}

// validListenAddress checks the port of one ListenAddress value as sshd
// does: a bare IPv6 address (two colons or more, no brackets) has none,
// else a port after host: or [address]: must pass a2port. The host and the
// rdomain words that may follow are names.
func (p *parser) validListenAddress(v string) bool {
	if strings.Count(v, ":") > 1 && !strings.Contains(v, "[") {
		return true
	}
	host := v
	if strings.HasPrefix(v, "[") {
		_, after, ok := strings.Cut(v, "]")
		if !ok {
			return false
		}
		host = after
		if host == "" {
			return true
		}
		if host[0] != ':' {
			return false
		}
	}
	_, port, hasPort := strings.Cut(host, ":")
	return !hasPort || p.validPort(port)
}

// validCriteria reports whether sshd accepts the arguments of a Match line:
// pairs of a criterion it knows and a pattern, Invalid-User a token of its
// own, All only alone. Patterns are names or addresses sshd takes as
// written; a LocalPort must pass a2port.
func (p *parser) validCriteria(args []string) bool {
	for i := 0; i < len(args); i++ {
		name := strings.ToLower(args[i])
		if name == "invalid-user" {
			continue
		}
		if i+1 == len(args) || args[i+1] == "" { // "Missing Match criteria"
			return false
		}
		i++
		switch name {
		case "user", "group", "host", "address", "localaddress", "rdomain", "version":
		case "localport":
			if !p.validPort(args[i]) {
				return false
			}
		default: // All among others, or a criterion sshd does not know
			return false
		}
	}
	return true
}

// validValue reports whether sshd accepts v for keyword name.
func (p *parser) validValue(name, v string) bool {
	switch name {
	case "Port":
		return p.validPort(v)
	case "ListenAddress":
		return p.validListenAddress(v)
	}
	check, ok := valueChecks[name]
	return !ok || check(v)
}
