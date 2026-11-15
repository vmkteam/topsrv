package security

import (
	"regexp"
	"slices"
	"strings"
)

// nssConfig is the part of /etc/nsswitch.conf that says where identities
// and sudo rules come from.
type nssConfig struct {
	Passwd   []string `json:"passwd"`
	Group    []string `json:"group"`
	Shadow   []string `json:"shadow"`
	Sudoers  []string `json:"sudoers"`
	Netgroup []string `json:"netgroup"`
	// ExternalIdentities: users or groups also come from a directory (sss,
	// ldap, winbind, nis): some of them, and their sudo rules, are not in the
	// files the agent reads. The systemd source does not count: it is the
	// Debian and Ubuntu default and only adds DynamicUser and homed users.
	ExternalIdentities bool `json:"externalIdentities"`
}

// externalNSS are the sources that serve identities from a directory.
var externalNSS = []string{"sss", "ldap", "winbind", "nis", "nisplus", "hesiod"}

// nssSource is the shape of a service name; anything else is sent as
// "invalid".
var nssSource = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// parseNSSwitch reads the databases the collector needs. Actions in brackets
// ([NOTFOUND=return]) are skipped; a database listed twice keeps its first
// line, as glibc does.
func parseNSSwitch(b []byte) nssConfig {
	var c nssConfig
	dbs := map[string]*[]string{"passwd": &c.Passwd, "group": &c.Group, "shadow": &c.Shadow, "sudoers": &c.Sudoers, "netgroup": &c.Netgroup}
	for line := range strings.SplitSeq(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		db, rest, ok := strings.Cut(line, ":")
		dst := dbs[strings.TrimSpace(db)]
		if !ok || dst == nil || *dst != nil {
			continue
		}
		*dst = []string{}
		inAction := false
		for src := range strings.FieldsSeq(strings.ToLower(rest)) {
			if strings.HasPrefix(src, "[") || inAction {
				inAction = !strings.HasSuffix(src, "]")
				continue
			}
			if !nssSource.MatchString(src) {
				src = valueInvalid
			}
			*dst = append(*dst, src)
		}
	}
	for _, srcs := range [][]string{c.Passwd, c.Group, c.Shadow} {
		if slices.ContainsFunc(srcs, func(s string) bool { return slices.Contains(externalNSS, s) }) {
			c.ExternalIdentities = true
		}
	}
	return c
}
