package sudoers

import (
	"strconv"
	"strings"
)

// DoasRule is one rule of doas.conf (OpenDoas, Alpine): "permit|deny
// [options] identity [as target] [cmd command [args]]". The command is
// never kept, only whether the rule is restricted to one.
type DoasRule struct {
	Source    string
	Permit    bool
	Principal string // a user, or :group
	Nopass    bool
	Persist   bool
	Keepenv   bool
	AsRoot    bool // no target, or root
	Cmd       bool
}

// ParseDoas parses doas.conf; lines it cannot read are refs, never text.
func ParseDoas(file string, b []byte) ([]DoasRule, []Ref) {
	var (
		rules []DoasRule
		errs  []Ref
	)
	for _, l := range logicalLines(b) {
		text, _, _ := strings.Cut(l.text, "#")
		f := strings.Fields(text)
		if len(f) == 0 {
			continue
		}
		r, ok := doasRule(f)
		if !ok {
			errs = append(errs, Ref{File: file, Line: l.n, Code: CodeSyntax})
			continue
		}
		r.Source = file + ":" + strconv.Itoa(l.n)
		rules = append(rules, r)
	}
	return rules, errs
}

func doasRule(f []string) (DoasRule, bool) {
	var r DoasRule
	switch f[0] {
	case "permit":
		r.Permit = true
	case "deny":
	default:
		return r, false
	}
	i := 1
options:
	for ; i < len(f); i++ {
		switch f[i] {
		case "nopass":
			r.Nopass = true
		case "persist":
			r.Persist = true
		case "keepenv":
			r.Keepenv = true
		case "nolog":
		case "setenv":
			for i < len(f) && !strings.HasSuffix(f[i], "}") {
				i++ // the variables are not kept
			}
		default:
			break options
		}
	}
	if i >= len(f) {
		return r, false
	}
	r.Principal, i = f[i], i+1
	r.AsRoot = true
	if i+1 < len(f) && f[i] == "as" {
		r.AsRoot, i = f[i+1] == "root", i+2
	}
	r.Cmd = i < len(f) && f[i] == "cmd"
	return r, true
}
