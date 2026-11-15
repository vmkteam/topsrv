package dockerapi

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
)

// DefaultConfigFile is daemon.json of a rootful dockerd without
// --config-file.
const DefaultConfigFile = "/etc/docker/daemon.json"

// Settings are what dockerd is told by flags or daemon.json. A field is nil
// when neither sets it: the default of the engine version applies. dockerd
// refuses to start when a flag and daemon.json set the same option, so one
// source per option is in force.
type Settings struct {
	Hosts      []string // -H / "hosts", as written
	ConfigFile string   // --config-file; flags only

	UserlandProxy      *bool
	IPTables           *bool
	IP6Tables          *bool
	AllowDirectRouting *bool
	ICC                *bool // inter-container communication on the default bridge
	NoNewPrivileges    *bool
	LiveRestore        *bool
	TLS                *bool
	TLSVerify          *bool
	FirewallBackend    *string // iptables, nftables
	DefaultBindIP      *string // --ip: where -p binds without an address
	UsernsRemap        *string // user[:group] or "default"
}

// setBool sets a boolean option by its flag name (= daemon.json key); false
// for a name it does not track.
func (s *Settings) setBool(name string, v bool) bool {
	switch name {
	case "userland-proxy":
		s.UserlandProxy = &v
	case "iptables":
		s.IPTables = &v
	case "ip6tables":
		s.IP6Tables = &v
	case "allow-direct-routing":
		s.AllowDirectRouting = &v
	case "icc":
		s.ICC = &v
	case "no-new-privileges":
		s.NoNewPrivileges = &v
	case "live-restore":
		s.LiveRestore = &v
	case "tls":
		s.TLS = &v
	case "tlsverify":
		s.TLSVerify = &v
	default:
		return false
	}
	return true
}

// setString sets a string option by its flag name; other names are not
// tracked.
func (s *Settings) setString(name, v string) {
	switch name {
	case "firewall-backend":
		s.FirewallBackend = &v
	case "ip":
		s.DefaultBindIP = &v
	case "userns-remap":
		s.UsernsRemap = &v
	case "config-file":
		s.ConfigFile = v
	case "host", "H":
		s.Hosts = append(s.Hosts, v)
	}
}

// boolOptions are the boolean options setBool takes (a test keeps the two
// in step): such a flag takes no separate value.
var boolOptions = []string{"userland-proxy", "iptables", "ip6tables", "allow-direct-routing", "icc",
	"no-new-privileges", "live-restore", "tls", "tlsverify"}

func isBoolOption(name string) bool { return slices.Contains(boolOptions, name) }

// ParseArgs reads the options of a dockerd command line (pflag syntax:
// --name=value, --name value, -H value, -Hvalue; a boolean --name or
// --name=false). argv[0] is the program. dockerd takes no positional
// arguments, so a word after an unknown flag is that flag's value. The rest
// of the line is never kept: it may carry secrets.
func ParseArgs(argv []string) Settings {
	var s Settings
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		var name, value string
		hasValue := false
		switch {
		case a == "--":
			return s
		case strings.HasPrefix(a, "--"):
			name, value, hasValue = strings.Cut(a[2:], "=")
		case strings.HasPrefix(a, "-H"):
			name, value, hasValue = "H", strings.TrimPrefix(a[2:], "="), len(a) > 2
		case strings.HasPrefix(a, "-"):
			name = a[1:]
		default:
			continue // a value of an option not tracked
		}
		if isBoolOption(name) {
			v := true
			if hasValue {
				var err error
				if v, err = strconv.ParseBool(value); err != nil {
					continue // dockerd would not start
				}
			}
			s.setBool(name, v)
			continue
		}
		if !hasValue && i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
			i++
			value, hasValue = argv[i], true
		}
		if hasValue {
			s.setString(name, value)
		}
	}
	return s
}

// errConfigType: a key of daemon.json has a value of another type than
// dockerd takes; it refuses to start with the file.
var errConfigType = errors.New("dockerapi: daemon.json value of the wrong type")

// ParseConfig reads daemon.json. An error means dockerd refuses the file
// (bad JSON, a tracked key of the wrong type); what was read is returned
// anyway. Keys not tracked are ignored, their values never kept.
func ParseConfig(b []byte) (Settings, error) {
	var (
		s   Settings
		raw map[string]json.RawMessage
	)
	if err := json.Unmarshal(b, &raw); err != nil {
		return s, err
	}
	var bad error
	for key, v := range raw {
		var err error
		switch key {
		case "hosts":
			err = strictUnmarshal(v, &s.Hosts)
		case "firewall-backend", "ip", "userns-remap":
			var str string
			if err = strictUnmarshal(v, &str); err == nil {
				s.setString(key, str)
			}
		default:
			var flag bool
			if !isBoolOption(key) {
				continue
			}
			if err = strictUnmarshal(v, &flag); err == nil {
				s.setBool(key, flag)
			}
		}
		if err != nil {
			bad = errConfigType
		}
	}
	return s, bad
}

// strictUnmarshal refuses null and a value of another type.
func strictUnmarshal(v json.RawMessage, dst any) error {
	if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
		return errConfigType
	}
	return json.Unmarshal(v, dst)
}

// Merge returns the options in force: a flag, else daemon.json. Hosts are
// ResolveHosts'.
func Merge(flags, file Settings) Settings {
	return Settings{
		ConfigFile:         flags.ConfigFile,
		UserlandProxy:      cmp.Or(flags.UserlandProxy, file.UserlandProxy),
		IPTables:           cmp.Or(flags.IPTables, file.IPTables),
		IP6Tables:          cmp.Or(flags.IP6Tables, file.IP6Tables),
		AllowDirectRouting: cmp.Or(flags.AllowDirectRouting, file.AllowDirectRouting),
		ICC:                cmp.Or(flags.ICC, file.ICC),
		NoNewPrivileges:    cmp.Or(flags.NoNewPrivileges, file.NoNewPrivileges),
		LiveRestore:        cmp.Or(flags.LiveRestore, file.LiveRestore),
		TLS:                cmp.Or(flags.TLS, file.TLS),
		TLSVerify:          cmp.Or(flags.TLSVerify, file.TLSVerify),
		FirewallBackend:    cmp.Or(flags.FirewallBackend, file.FirewallBackend),
		DefaultBindIP:      cmp.Or(flags.DefaultBindIP, file.DefaultBindIP),
		UsernsRemap:        cmp.Or(flags.UsernsRemap, file.UsernsRemap),
	}
}
