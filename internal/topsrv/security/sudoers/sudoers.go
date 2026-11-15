// Package sudoers parses a sudo policy (sudoers(5)) into the facts a posture
// check needs — who may run what as whom, with or without a password —
// without running sudo or visudo. Command texts are parsed for their flags
// and never kept. Files are read through the caller.
package sudoers

import (
	"errors"
	"io/fs"
	"maps"
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
	maxRules = 500 // the receiving side caps a snapshot at 1 MB
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
	Rules []Rule
	// Truncated: more than maxRules rules; the ones after are not listed.
	Truncated bool
	Defaults  Defaults
	Scoped    []ScopedDefault
	Files     []string
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
	// CommandNegation: a command excluded with "!" (ALL, !/bin/su) — never
	// a protection: a copy of the binary under another name runs.
	CommandNegation bool
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
	EnvKeepLD    bool    // LD_* kept in the environment of commands
	TargetPW     *bool   // the password of the target user, not the caller's
	RunasPW      *bool   // the password of runas_default
	Timeout      *string // timestamp_timeout as written, "invalid" when sudo would refuse it
	Logfile      *bool   // a log file is set (its path is not kept)
}

// ScopedDefault is a Defaults line bound to users, hosts, commands or runas
// users that sets a tracked flag.
type ScopedDefault struct {
	Source  string
	Binding string // user, host, command, runas
	// List is the binding, aliases expanded; nil for a command binding:
	// commands are never sent.
	List           []string
	NoAuthenticate bool
	RootPW         bool
	EnvKeepLD      bool
	TargetPW       bool
	RunasPW        bool
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

// defaultsBinding is the blank sudo allows after the binding character.
var defaultsBinding = regexp.MustCompile(`^(Defaults[:@!>])\s+`)

// cutSpace cuts s at its first space or tab.
func cutSpace(s string) (before, after string) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// Alias kinds, and the Defaults bindings that share their names.
const (
	kindUser    = "user"
	kindHost    = "host"
	kindRunas   = "runas"
	kindCmnd    = "cmnd"
	bindCommand = "command"
)

// aliasKinds by keyword.
var aliasKinds = map[string]string{"User_Alias": kindUser, "Runas_Alias": kindRunas, "Host_Alias": kindHost, "Cmnd_Alias": kindCmnd, "Cmd_Alias": kindCmnd}

type rawRule struct {
	ref          Ref
	users, hosts []string
	cmnds        string
}

type parser struct {
	files    Files
	hostname string
	policy   *Policy
	aliases  map[string]map[string][]string // kind → name → members
	expanded map[string][]string            // kind + name → members, aliases expanded
	scoped   []ScopedDefault                // aliases expanded at the end
	envLD    map[string]bool                // the LD_* names the global env_keep keeps
	raw      []rawRule
	stack    []string
}

// Parse reads the policy starting at main. hostname is the short host name,
// for %h in include paths.
func Parse(main, hostname string, files Files) *Policy {
	p := &parser{files: files, hostname: hostname, policy: &Policy{}, aliases: map[string]map[string][]string{}, expanded: map[string][]string{}}
	p.parseFile(main, 0, false)
	for _, r := range p.raw {
		if len(p.policy.Rules) == maxRules {
			p.policy.Truncated = true
			break
		}
		p.policy.Rules = append(p.policy.Rules, p.expand(r))
	}
	bindingKinds := map[string]string{kindUser: kindUser, kindHost: kindHost, kindRunas: kindRunas}
	for _, sd := range p.scoped {
		if kind, ok := bindingKinds[sd.Binding]; ok {
			sd.List = p.resolve(kind, sd.List, 0)
		} else {
			sd.List = nil // a command binding: commands are never sent
		}
		p.policy.Scoped = append(p.policy.Scoped, sd)
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
		if _, _, isDirective := directive(strings.TrimSpace(l)); !isDirective {
			l = strings.TrimRight(stripComment(l), " \t") // a comment ends at the newline, a "\\" in it continues nothing
		}
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
		if !errors.Is(err, fs.ErrNotExist) { // a missing includedir is not an error, an unreadable one is
			p.policy.ReadErrors = append(p.policy.ReadErrors, ReadError{Path: target, Err: err})
		}
		return
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
	fields := splitFields(commaSpace.ReplaceAllString(strings.TrimSpace(left), ","))
	if len(fields) != 2 {
		p.syntaxError(ref)
		return
	}
	users := names(list(fields[0]))
	p.raw = append(p.raw, rawRule{ref: ref, users: users, hosts: names(list(fields[1])), cmnds: cmnds})
	for _, spec := range specs[1:] {
		hosts, cmnds, ok := strings.Cut(spec, "=")
		if !ok {
			p.syntaxError(ref)
			continue
		}
		p.raw = append(p.raw, rawRule{ref: ref, users: users, hosts: names(list(hosts)), cmnds: cmnds})
	}
}

// splitFields splits at whitespace outside quotes and not escaped:
// "%domain\\ admins ALL" has two fields.
func splitFields(s string) []string {
	var out []string
	for _, f := range splitTop(s, func(i int) bool { return s[i] == ' ' || s[i] == '\t' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// names unquotes and unescapes user and host names: "%domain admins",
// %domain\\ admins.
func names(items []string) []string {
	for i, it := range items {
		if len(it) >= 2 && it[0] == '"' && it[len(it)-1] == '"' {
			it = it[1 : len(it)-1]
		} else if strings.HasPrefix(it, "!\"") && strings.HasSuffix(it, "\"") && len(it) >= 3 {
			it = "!" + it[2:len(it)-1]
		}
		items[i] = strings.NewReplacer(`\ `, " ", `\,`, ",", `\:`, ":", `\=`, "=", `\\`, `\`).Replace(it)
	}
	return items
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
	s = strings.TrimRight(s, " \t") // sudo allows "NOPASSWD :"
	i := len(s)
	for i > 0 && (s[i-1] >= 'A' && s[i-1] <= 'Z' || s[i-1] >= 'a' && s[i-1] <= 'z' || s[i-1] >= '0' && s[i-1] <= '9' || s[i-1] == '_') {
		i--
	}
	word := s[i:]
	return slices.Contains(tags, word) || slices.Contains(digests, word)
}

func (p *parser) defaults(s string, ref Ref) {
	s = defaultsBinding.ReplaceAllString(s, "$1") // "Defaults: alice" is "Defaults:alice"
	s = commaSpace.ReplaceAllString(s, ",")       // "Defaults:alice, bob"
	head, rest := cutSpace(s)
	binding, bound := "", []string(nil)
	if len(head) > len("Defaults") {
		binding = map[byte]string{':': kindUser, '@': kindHost, '!': bindCommand, '>': kindRunas}[head[len("Defaults")]]
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
		p.scoped = append(p.scoped, sd)
	}
}

// timeoutRe is a timeout sudo takes: minutes, maybe fractional or negative
// (never expires), or a sum of days, hours, minutes and seconds.
var timeoutRe = regexp.MustCompile(`^(-?[0-9]{1,9}(\.[0-9]{1,6})?|([0-9]{1,9}[dDhHmMsS]){1,4})$`)

// timeoutValue is timestamp_timeout as written: "!timestamp_timeout" is 0,
// a value sudo refuses is "invalid".
func timeoutValue(on bool, value string) *string {
	v := strings.Trim(strings.TrimSpace(value), `"`)
	switch {
	case !on:
		v = "0"
	case !timeoutRe.MatchString(v):
		v = "invalid"
	}
	return &v
}

// defaultParam applies one Defaults parameter: to the global Defaults when
// the line is not bound, and to sd. It reports whether a tracked flag of a
// bound line is set.
func (p *parser) defaultParam(sd *ScopedDefault, param string) bool {
	on := !strings.HasPrefix(param, "!")
	name, value, _ := strings.Cut(strings.TrimPrefix(param, "!"), "=")
	op := ""
	if strings.HasSuffix(name, "+") || strings.HasSuffix(name, "-") {
		op, name = name[len(name)-1:], name[:len(name)-1]
	}
	d := &p.policy.Defaults
	if sd.Binding != "" {
		d = &Defaults{} // a bound line leaves the global Defaults alone
	}
	switch strings.TrimSpace(name) {
	case "authenticate":
		d.Authenticate, sd.NoAuthenticate = &on, !on
		return !on
	case "rootpw":
		d.RootPW, sd.RootPW = &on, on
		return on
	case "targetpw":
		d.TargetPW, sd.TargetPW = &on, on
		return on
	case "runaspw":
		d.RunasPW, sd.RunasPW = &on, on
		return on
	case "use_pty":
		d.UsePTY = &on
	case "logfile": // logfile=/path or !logfile; the path is not kept
		d.Logfile = &on
	case "timestamp_timeout":
		d.Timeout = timeoutValue(on, value)
	case "env_keep":
		return p.envKeep(sd, op, value)
	}
	return false
}

// envKeep applies an env_keep line: whether some LD_* name stays in the
// environment of commands after it.
func (p *parser) envKeep(sd *ScopedDefault, op, value string) bool {
	set := maps.Clone(p.envLD) // a bound line applies on top of the global list
	if op == "" {
		set = map[string]bool{}
	}
	for name := range strings.FieldsSeq(strings.Trim(strings.TrimSpace(value), `"`)) {
		if !strings.HasPrefix(name, "LD_") {
			continue
		}
		if op == "-" {
			delete(set, name)
			continue
		}
		if set == nil {
			set = map[string]bool{}
		}
		set[name] = true
	}
	sd.EnvKeepLD = len(set) > 0
	if sd.Binding == "" {
		p.envLD, p.policy.Defaults.EnvKeepLD = set, len(set) > 0
	}
	return len(set) > 0
}

func (p *parser) syntaxError(ref Ref) {
	ref.Code = CodeSyntax
	p.policy.Errors = append(p.policy.Errors, ref)
}

// expand resolves the aliases of a rule and reads its command list for
// flags. Tags and runas carry over to the following commands, as in sudo.
func (p *parser) expand(r rawRule) Rule {
	rule := Rule{Source: r.ref.Source(), Principals: p.resolve(kindUser, r.users, 0)}
	rule.HostsAll = slices.Contains(p.resolve(kindHost, r.hosts, 0), "ALL")
	nopass := false
	setenv := 0 // the SETENV tag: 1 set, -1 NOSETENV, 0 neither
	commands, nopassCount := 0, 0
	defaultRunas := false // a command before any runas spec runs as runas_default
	for _, item := range list(r.cmnds) {
		s := strings.TrimSpace(item)
		if strings.HasPrefix(s, "(") {
			end := strings.IndexByte(s, ')')
			if end < 0 {
				p.syntaxError(r.ref)
				break
			}
			rule.Runas = p.runas(rule.Runas, s[1:end])
			s = strings.TrimSpace(s[end+1:])
		}
		defaultRunas = defaultRunas || rule.Runas == nil
		for loc := commandOption.FindStringIndex(s); loc != nil; loc = commandOption.FindStringIndex(s) {
			s = s[loc[1]:]
		}
		s = cutTags(s, &nopass, &setenv)
		f := strings.Fields(s)
		if len(f) == 0 || strings.HasPrefix(s, "!") {
			rule.CommandNegation = rule.CommandNegation || len(f) > 0
			continue // a negated command grants nothing
		}
		name := f[0]
		if d, _, ok := strings.Cut(name, ":"); ok && slices.Contains(digests, d) && len(f) > 1 {
			name = f[1] // "sha256:… /bin/ls"
		}
		members := p.resolve(kindCmnd, []string{name}, 0)
		all := slices.Contains(members, "ALL")
		rule.CommandNegation = rule.CommandNegation || slices.ContainsFunc(members, isNegated)
		commands++
		if nopass {
			nopassCount++
		}
		rule.CommandsAll = rule.CommandsAll || all
		rule.Setenv = rule.Setenv || setenv == 1 || all && setenv == 0 // ALL implies SETENV unless NOSETENV says no
	}
	rule.NopasswdAny = nopassCount > 0
	rule.NopasswdAll = commands > 0 && nopassCount == commands
	if rule.Runas != nil && defaultRunas && !slices.Contains(rule.Runas.Users, "root") {
		rule.Runas.Users = append(rule.Runas.Users, "root") // "ALL, (postgres) psql": ALL runs as root
		slices.Sort(rule.Runas.Users)
	}
	return rule
}

// cutTags strips the tags before a command and applies them: they carry
// over to the following commands of the line.
func cutTags(s string, nopass *bool, setenv *int) string {
	for {
		tag, rest, ok := strings.Cut(s, ":")
		tag = strings.TrimSpace(tag)
		if !ok || !slices.Contains(tags, tag) {
			return s
		}
		switch tag {
		case "NOPASSWD":
			*nopass = true
		case "PASSWD":
			*nopass = false
		case "SETENV":
			*setenv = 1
		case "NOSETENV":
			*setenv = -1
		}
		s = strings.TrimSpace(rest)
	}
}

func isNegated(item string) bool { return strings.HasPrefix(item, "!") }

func (p *parser) runas(prev *Runas, spec string) *Runas {
	users, groups, _ := strings.Cut(spec, ":")
	r := &Runas{Users: p.resolve(kindRunas, list(users), 0), Groups: p.resolve(kindRunas, list(groups), 0)}
	for _, x := range slices.Concat(r.Users, r.Groups) {
		r.HasNegation = r.HasNegation || strings.HasPrefix(x, "!")
	}
	if prev != nil {
		r.Users = append(slices.Compact(slices.Sorted(slices.Values(append(prev.Users, r.Users...)))), []string{}...)
		r.Groups = append(slices.Compact(slices.Sorted(slices.Values(append(prev.Groups, r.Groups...)))), []string{}...)
		r.HasNegation = r.HasNegation || prev.HasNegation
	}
	if r.Users == nil {
		r.Users = []string{}
	}
	if r.Groups == nil {
		r.Groups = []string{}
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
