// Package sudoers parses a sudo policy (sudoers(5)) into the facts a posture
// check needs — who may run what as whom, with or without a password —
// without running sudo or visudo. Command texts are parsed for their flags
// and never kept. Files are read through the caller.
package sudoers

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Limits of one parse.
const (
	maxDepth = 128 // sudo's own include depth
	maxFiles = 512
)

// Codes of Ref.Code.
const (
	CodeSyntax       = "syntax"
	CodeIncludeDepth = "include_depth"
	CodeIncludeLoop  = "include_loop"
	CodeTooManyFiles = "too_many_files"
)

// Files reads the policy: ReadFile one file with the caller's size limit,
// ReadDir the names in an includedir.
type Files struct {
	ReadFile func(path string) ([]byte, error)
	ReadDir  func(dir string) ([]string, error)
}

// Policy is the parsed policy.
type Policy struct {
	// Rules in file order: sudo applies the last match, so order matters.
	Rules    []Rule
	Defaults Defaults
	Scoped   []ScopedDefault
	Files    []string
	// Ignored are includedir entries sudo skips: names with a "." or
	// ending in "~" (sudoers.d/admin.conf is never read).
	Ignored    []string
	Errors     []Ref
	ReadErrors []ReadError
}

// Rule is one user specification for one host list.
type Rule struct {
	Source string
	// Principals as written, aliases expanded: user, %group, #uid, %#gid,
	// +netgroup, ALL; "!" for a negation.
	Principals []string
	HostsAll   bool
	// Runas is nil without a runas spec: sudo's runas_default, root.
	Runas       *Runas
	CommandsAll bool // ALL among the commands
	NopasswdAll bool // every command without a password
	NopasswdAny bool // some command without a password
	Setenv      bool // SETENV, which ALL implies
}

// Runas is a runas spec, aliases expanded.
type Runas struct {
	Users  []string
	Groups []string
	// HasNegation: "(ALL, !root)" — reported, never a protection
	// (CVE-2019-14287).
	HasNegation bool
}

// Defaults are the global Defaults in force after the whole policy, nil
// when not set.
type Defaults struct {
	Authenticate *bool // !authenticate: no password for anyone
	RootPW       *bool
	UsePTY       *bool
	EnvKeepLD    bool // LD_* kept in the environment of commands
}

// ScopedDefault is a Defaults line bound to users, hosts, commands or runas
// users that sets a tracked flag.
type ScopedDefault struct {
	Source         string
	Binding        string // user, host, command, runas
	List           []string
	NoAuthenticate bool
	RootPW         bool
	EnvKeepLD      bool
}

// Ref points at a line, never at its text.
type Ref struct {
	File string
	Line int
	Code string
}

// Source is "file:line".
func (r Ref) Source() string { return r.File + ":" + strconv.Itoa(r.Line) }

// ReadError is a file that was named but could not be read.
type ReadError struct {
	Path string
	Err  error
}

// tags of a command spec; they last until another tag overrides them.
var tags = []string{"NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV", "LOG_INPUT", "NOLOG_INPUT",
	"LOG_OUTPUT", "NOLOG_OUTPUT", "MAIL", "NOMAIL", "FOLLOW", "NOFOLLOW", "INTERCEPT", "NOINTERCEPT"}

// digests may prefix a command: "sha256:abc /bin/ls".
var digests = []string{"sha224", "sha256", "sha384", "sha512"}

// commandOption is an option before a command: CWD=/srv, ROLE=…, NOTAFTER=….
var commandOption = regexp.MustCompile(`^(ROLE|TYPE|CWD|CHROOT|NOTBEFORE|NOTAFTER|TIMEOUT|APPARMOR_PROFILE|PRIVS|LIMITPRIVS)=\S*\s*`)

var aliasName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// commaSpace normalises "alice, bob" to "alice,bob" before the user and host
// lists are told apart by whitespace.
var commaSpace = regexp.MustCompile(`\s*,\s*`)

// cutSpace cuts s at its first space or tab.
func cutSpace(s string) (before, after string) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// aliasKinds by keyword.
var aliasKinds = map[string]string{"User_Alias": "user", "Runas_Alias": "runas", "Host_Alias": "host", "Cmnd_Alias": "cmnd", "Cmd_Alias": "cmnd"}

type rawRule struct {
	source       string
	users, hosts []string
	cmnds        string
}

type parser struct {
	files    Files
	hostname string
	policy   *Policy
	aliases  map[string]map[string][]string // kind → name → members
	expanded map[string][]string            // kind + name → members, aliases expanded
	raw      []rawRule
	stack    []string
}

// Parse reads the policy starting at main. hostname is the short host name,
// for %h in include paths.
func Parse(main, hostname string, files Files) *Policy {
	p := &parser{files: files, hostname: hostname, policy: &Policy{}, aliases: map[string]map[string][]string{}, expanded: map[string][]string{}}
	p.parseFile(main, 0, false)
	for _, r := range p.raw {
		p.policy.Rules = append(p.policy.Rules, p.expand(r))
	}
	return p.policy
}

func (p *parser) parseFile(name string, depth int, missingOK bool) {
	switch {
	case depth > maxDepth:
		p.policy.Errors = append(p.policy.Errors, Ref{File: name, Code: CodeIncludeDepth})
		return
	case slices.Contains(p.stack, name):
		p.policy.Errors = append(p.policy.Errors, Ref{File: name, Code: CodeIncludeLoop})
		return
	case len(p.policy.Files) >= maxFiles:
		p.policy.Errors = append(p.policy.Errors, Ref{File: name, Code: CodeTooManyFiles})
		return
	}
	b, err := p.files.ReadFile(name)
	switch {
	case missingOK && errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		p.policy.ReadErrors = append(p.policy.ReadErrors, ReadError{Path: name, Err: err})
		return
	}
	p.policy.Files = append(p.policy.Files, name)
	p.stack = append(p.stack, name)
	defer func() { p.stack = p.stack[:len(p.stack)-1] }()
	for _, l := range logicalLines(b) {
		p.parseLine(name, l, depth)
	}
}

type line struct {
	text string
	n    int
}

// logicalLines joins lines continued with a trailing backslash.
func logicalLines(b []byte) []line {
	var (
		out   []line
		cur   strings.Builder
		start int
	)
	for i, l := range strings.Split(string(b), "\n") {
		l = strings.TrimRight(l, "\r")
		if cur.Len() == 0 {
			start = i + 1
		}
		if trailing := len(l) - len(strings.TrimRight(l, `\`)); trailing%2 == 1 {
			cur.WriteString(l[:len(l)-1])
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(l)
		out = append(out, line{text: cur.String(), n: start})
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, line{text: cur.String(), n: start})
	}
	return out
}

func (p *parser) parseLine(file string, l line, depth int) {
	ref := Ref{File: file, Line: l.n}
	s := strings.TrimSpace(l.text)
	if dir, rest, ok := directive(s); ok {
		p.include(file, dir, rest, depth, ref)
		return
	}
	s = strings.TrimSpace(stripComment(s))
	if s == "" {
		return
	}
	first, rest := cutSpace(s)
	switch {
	case strings.HasPrefix(first, "Defaults"):
		p.defaults(s, ref)
	case aliasKinds[first] != "":
		p.alias(aliasKinds[first], rest, ref)
	default:
		p.userSpec(s, ref)
	}
}

// directive recognises @include, #include, @includedir and #includedir.
func directive(s string) (name, rest string, ok bool) {
	for _, d := range []string{"@includedir", "#includedir", "@include", "#include"} {
		if r, found := strings.CutPrefix(s, d); found && (r == "" || r[0] == ' ' || r[0] == '\t') {
			return d[1:], strings.TrimSpace(r), true
		}
	}
	return "", "", false
}

func (p *parser) include(file, dir, arg string, depth int, ref Ref) {
	target := unquotePath(arg)
	if target == "" {
		p.syntaxError(ref)
		return
	}
	target = strings.ReplaceAll(target, "%h", p.hostname)
	if !path.IsAbs(target) {
		target = path.Join(path.Dir(file), target) // relative to the including file, sudo 1.9.1+
	}
	if dir == "include" {
		p.parseFile(target, depth+1, false)
		return
	}
	names, err := p.files.ReadDir(target)
	if err != nil {
		return // a missing includedir is not an error
	}
	slices.Sort(names)
	for _, n := range names {
		if strings.Contains(n, ".") || strings.HasSuffix(n, "~") {
			p.policy.Ignored = append(p.policy.Ignored, path.Join(target, n))
			continue
		}
		p.parseFile(path.Join(target, n), depth+1, true)
	}
}

// unquotePath reads a path that is quoted, or has its spaces escaped.
func unquotePath(s string) string {
	if strings.HasPrefix(s, `"`) {
		end := strings.LastIndex(s, `"`)
		if end <= 0 {
			return ""
		}
		return strings.ReplaceAll(s[1:end], `\"`, `"`)
	}
	s, _, _ = strings.Cut(strings.ReplaceAll(s, `\ `, "\x00"), " ")
	return strings.ReplaceAll(s, "\x00", " ")
}

// stripComment cuts a "#" comment; "#" before a digit is a uid (#1000).
func stripComment(s string) string {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case c == '#' && !quoted && (i+1 == len(s) || s[i+1] < '0' || s[i+1] > '9'):
			return s[:i]
		}
	}
	return s
}

// splitTop splits s where at says, outside quotes and parentheses and not
// escaped.
func splitTop(s string, at func(i int) bool) []string {
	var (
		out    []string
		depth  int
		quoted bool
		start  int
	)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case quoted:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth == 0 && at(i):
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// splitAt splits s at a separator byte, as splitTop.
func splitAt(s string, sep byte) []string {
	return splitTop(s, func(i int) bool { return s[i] == sep })
}

// list splits a comma list, items trimmed.
func list(s string) []string {
	var out []string
	for _, item := range splitAt(s, ',') {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (p *parser) alias(kind, s string, ref Ref) {
	for _, def := range splitAt(s, ':') {
		name, members, ok := strings.Cut(def, "=")
		name = strings.TrimSpace(name)
		if !ok || !aliasName.MatchString(name) {
			p.syntaxError(ref)
			continue
		}
		if p.aliases[kind] == nil {
			p.aliases[kind] = map[string][]string{}
		}
		p.aliases[kind][name] = list(members)
	}
}

// userSpec parses "users hosts = commands [: hosts = commands ...]".
func (p *parser) userSpec(s string, ref Ref) {
	specs := hostSpecs(s)
	if len(specs) == 0 {
		p.syntaxError(ref)
		return
	}
	left, cmnds, _ := strings.Cut(specs[0], "=")
	fields := strings.Fields(commaSpace.ReplaceAllString(strings.TrimSpace(left), ","))
	if len(fields) != 2 {
		p.syntaxError(ref)
		return
	}
	users := list(fields[0])
	source := ref.Source()
	p.raw = append(p.raw, rawRule{source: source, users: users, hosts: list(fields[1]), cmnds: cmnds})
	for _, spec := range specs[1:] {
		hosts, cmnds, ok := strings.Cut(spec, "=")
		if !ok {
			p.syntaxError(ref)
			continue
		}
		p.raw = append(p.raw, rawRule{source: source, users: users, hosts: list(hosts), cmnds: cmnds})
	}
}

// hostSpecs splits a user spec at the ":" that start another host list: not
// the colon of a tag (NOPASSWD:), a digest (sha256:) or a runas group.
func hostSpecs(s string) []string {
	if !strings.Contains(s, "=") {
		return nil
	}
	return splitTop(s, func(i int) bool { return s[i] == ':' && !tagOrDigestBefore(s[:i]) })
}

func tagOrDigestBefore(s string) bool {
	i := len(s)
	for i > 0 && (s[i-1] >= 'A' && s[i-1] <= 'Z' || s[i-1] >= 'a' && s[i-1] <= 'z' || s[i-1] >= '0' && s[i-1] <= '9' || s[i-1] == '_') {
		i--
	}
	word := s[i:]
	return slices.Contains(tags, word) || slices.Contains(digests, word)
}

func (p *parser) defaults(s string, ref Ref) {
	head, rest := cutSpace(s)
	binding, bound := "", []string(nil)
	if len(head) > len("Defaults") {
		binding = map[byte]string{':': "user", '@': "host", '!': "command", '>': "runas"}[head[len("Defaults")]]
		if binding == "" {
			p.syntaxError(ref)
			return
		}
		bound = list(head[len("Defaults")+1:])
	}
	sd := ScopedDefault{Source: ref.Source(), Binding: binding, List: bound}
	tracked := false
	for _, param := range list(rest) {
		tracked = p.defaultParam(&sd, param) || tracked
	}
	if binding != "" && tracked {
		p.policy.Scoped = append(p.policy.Scoped, sd)
	}
}

// defaultParam applies one Defaults parameter: to the global Defaults when
// the line is not bound, and to sd. It reports whether a tracked flag of a
// bound line is set.
func (p *parser) defaultParam(sd *ScopedDefault, param string) bool {
	global := sd.Binding == ""
	on := !strings.HasPrefix(param, "!")
	name, value, _ := strings.Cut(strings.TrimPrefix(param, "!"), "=")
	op := ""
	if strings.HasSuffix(name, "+") || strings.HasSuffix(name, "-") {
		op, name = name[len(name)-1:], name[:len(name)-1]
	}
	switch strings.TrimSpace(name) {
	case "authenticate":
		sd.NoAuthenticate = !on
		if global {
			p.policy.Defaults.Authenticate = &on
		}
		return !on
	case "rootpw":
		sd.RootPW = on
		if global {
			p.policy.Defaults.RootPW = &on
		}
		return on
	case "use_pty":
		if global {
			p.policy.Defaults.UsePTY = &on
		}
	case "env_keep":
		ld := strings.Contains(strings.Trim(strings.TrimSpace(value), `"`), "LD_")
		switch {
		case op == "-" && ld:
			ld = false
		case op == "+" && !ld:
			ld = p.policy.Defaults.EnvKeepLD
		}
		sd.EnvKeepLD = ld
		if global {
			p.policy.Defaults.EnvKeepLD = ld
		}
		return ld
	}
	return false
}

func (p *parser) syntaxError(ref Ref) {
	ref.Code = CodeSyntax
	p.policy.Errors = append(p.policy.Errors, ref)
}

// expand resolves the aliases of a rule and reads its command list for
// flags. Tags and runas carry over to the following commands, as in sudo.
func (p *parser) expand(r rawRule) Rule {
	rule := Rule{Source: r.source, Principals: p.resolve("user", r.users, 0)}
	rule.HostsAll = slices.Contains(p.resolve("host", r.hosts, 0), "ALL")
	nopass, setenv := false, false
	commands, nopassCount := 0, 0
	for _, item := range list(r.cmnds) {
		s := strings.TrimSpace(item)
		if strings.HasPrefix(s, "(") {
			end := strings.IndexByte(s, ')')
			if end < 0 {
				break
			}
			rule.Runas = p.runas(rule.Runas, s[1:end])
			s = strings.TrimSpace(s[end+1:])
		}
		for loc := commandOption.FindStringIndex(s); loc != nil; loc = commandOption.FindStringIndex(s) {
			s = s[loc[1]:]
		}
		for {
			tag, rest, ok := strings.Cut(s, ":")
			if !ok || !slices.Contains(tags, strings.TrimSpace(tag)) {
				break
			}
			switch strings.TrimSpace(tag) {
			case "NOPASSWD":
				nopass = true
			case "PASSWD":
				nopass = false
			case "SETENV":
				setenv = true
			case "NOSETENV":
				setenv = false
			}
			s = strings.TrimSpace(rest)
		}
		f := strings.Fields(s)
		if len(f) == 0 || strings.HasPrefix(s, "!") {
			continue // a negated command grants nothing
		}
		name := f[0]
		if d, _, ok := strings.Cut(name, ":"); ok && slices.Contains(digests, d) && len(f) > 1 {
			name = f[1] // "sha256:… /bin/ls"
		}
		all := slices.Contains(p.resolve("cmnd", []string{name}, 0), "ALL")
		commands++
		if nopass {
			nopassCount++
		}
		rule.CommandsAll = rule.CommandsAll || all
		rule.Setenv = rule.Setenv || setenv || all
	}
	rule.NopasswdAny = nopassCount > 0
	rule.NopasswdAll = commands > 0 && nopassCount == commands
	return rule
}

func (p *parser) runas(prev *Runas, spec string) *Runas {
	users, groups, _ := strings.Cut(spec, ":")
	r := &Runas{Users: p.resolve("runas", list(users), 0), Groups: append([]string{}, list(groups)...)}
	for _, x := range slices.Concat(r.Users, r.Groups) {
		r.HasNegation = r.HasNegation || strings.HasPrefix(x, "!")
	}
	if prev != nil {
		r.Users = slices.Compact(slices.Sorted(slices.Values(append(prev.Users, r.Users...))))
		r.Groups = slices.Compact(slices.Sorted(slices.Values(append(prev.Groups, r.Groups...))))
		r.HasNegation = r.HasNegation || prev.HasNegation
	}
	return r
}

// maxExpanded caps the members an alias expands to: aliases that each use
// the next one several times would grow exponentially.
const maxExpanded = 4096

// resolve expands aliases of a kind in items, recursively; a negated alias
// negates its members. Each alias is expanded once and the result reused.
func (p *parser) resolve(kind string, items []string, depth int) []string {
	out := []string{}
	for _, item := range items {
		neg := false
		for strings.HasPrefix(item, "!") {
			item, neg = strings.TrimSpace(item[1:]), !neg
		}
		if _, ok := p.aliases[kind][item]; ok && depth < 16 {
			for _, m := range p.aliasMembers(kind, item, depth) {
				if neg {
					m = negated(m)
				}
				out = append(out, m)
			}
		} else {
			if neg {
				item = "!" + item
			}
			out = append(out, item)
		}
		if len(out) > maxExpanded {
			return out[:maxExpanded]
		}
	}
	return out
}

// aliasMembers returns the members of an alias with nested aliases
// expanded, computed once.
func (p *parser) aliasMembers(kind, name string, depth int) []string {
	key := kind + "\x00" + name
	if m, ok := p.expanded[key]; ok {
		return m
	}
	p.expanded[key] = nil // a loop expands to nothing
	m := p.resolve(kind, p.aliases[kind][name], depth+1)
	p.expanded[key] = m
	return m
}

func negated(m string) string {
	if rest, ok := strings.CutPrefix(m, "!"); ok {
		return rest
	}
	return "!" + m
}
