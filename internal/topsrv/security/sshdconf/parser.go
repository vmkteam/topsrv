// Package sshdconf parses sshd_config the way OpenSSH sshd does (servconf.c,
// misc.c), without running sshd: the effective global values with the line
// each came from, Match blocks apart, Include expanded. Files are read
// through the caller, which decides how untrusted paths are opened.
package sshdconf

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Limits of one parse.
const (
	maxIncludeDepth = 16  // sshd's own: deeper is an error, which is also how it shows loops
	maxFiles        = 256 // files read in one parse
)

// sshDir is SSHDIR: relative Include paths are relative to it.
const sshDir = "/etc/ssh"

// SourceCmdline is Value.Source of what the command line set.
const SourceCmdline = "cmdline"

// Files reads the configuration: ReadFile one file, with the caller's size
// limit; ReadDir the names in a directory, for Include patterns.
type Files struct {
	ReadFile func(path string) ([]byte, error)
	ReadDir  func(dir string) ([]string, error)
}

// Value is the value of a keyword and where it came from.
type Value struct {
	// Values: one for a scalar, every value for an accumulating keyword, the
	// whole first line for a list keyword (AuthorizedKeysFile).
	Values []string
	// Source is "file:line" or "cmdline".
	Source string
}

// MatchBlock is one Match block with what it sets.
type MatchBlock struct {
	Criteria []string
	Source   string
	Keys     map[string]Value
}

// Ref points at a line, never at its text.
type Ref struct {
	File string
	Line int
	Code string
}

// Source is "file:line", or "cmdline" for what the command line set.
func (r Ref) Source() string {
	if r.File == SourceCmdline {
		return SourceCmdline
	}
	return r.File + ":" + strconv.Itoa(r.Line)
}

// ReadError is a file that was named but could not be read.
type ReadError struct {
	Path string
	Err  error
}

// Config is the parsed configuration.
type Config struct {
	// Global holds the keywords set outside Match blocks, by canonical name
	// (PermitRootLogin), as sshd applies them before any Match.
	Global      map[string]Value
	MatchBlocks []*MatchBlock
	// Files are the files read, in order.
	Files []string
	// Unknown are keywords upstream sshd does not know, Code is the keyword
	// when it looks like one: distribution patches add their own
	// (DebianBanner), so they do not make the configuration invalid here.
	Unknown []Ref
	// Errors are lines sshd refuses to start with.
	Errors     []Ref
	ReadErrors []ReadError
}

// Valid reports whether sshd would accept the files: no line it refuses,
// and every file read.
func (c *Config) Valid() bool { return len(c.Errors) == 0 && len(c.ReadErrors) == 0 }

type parser struct {
	files     Files
	cfg       *Config
	portsFlag bool
	services  map[string]bool // TCP service names, read on the first Port that is not a number
}

// Parse reads the configuration flags name: -f, then -o before the files
// (they win) and -p (it drops the Port lines of the files).
func Parse(flags Flags, files Files) *Config {
	p := &parser{files: files, cfg: &Config{Global: map[string]Value{}}, portsFlag: len(flags.Ports) > 0}
	cmdline := Ref{File: SourceCmdline}
	for _, port := range flags.Ports {
		p.set(nil, keywords["port"], []string{port}, cmdline)
	}
	for _, o := range flags.Options {
		kw, args, code := splitLine(o)
		if k, ok := lookup(kw); ok && code == "" && k.class != include && k.class != match {
			p.set(nil, k, args, cmdline)
		}
	}
	p.parseFile(flags.ConfigFile, 0, nil, false)
	return p.cfg
}

// parseFile parses one file. block is the Match block in force where the
// file was included, nil for the global context; a Match inside the file
// ends with it. missingOK: a literal Include of a file that does not exist
// is glob(3) finding nothing, not an error.
func (p *parser) parseFile(name string, depth int, block *MatchBlock, missingOK bool) {
	if len(p.cfg.Files) >= maxFiles {
		p.cfg.Errors = append(p.cfg.Errors, Ref{File: name, Code: CodeTooManyFiles})
		return
	}
	b, err := p.files.ReadFile(name)
	switch {
	case missingOK && errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		p.cfg.ReadErrors = append(p.cfg.ReadErrors, ReadError{Path: name, Err: err})
		return
	}
	p.cfg.Files = append(p.cfg.Files, name)
	cur := block
	for n, line := range strings.Split(string(b), "\n") {
		ref := Ref{File: name, Line: n + 1}
		kw, args, code := splitLine(line)
		switch {
		case kw == "":
			continue
		case code != "":
			p.fail(ref, code)
			continue
		}
		k, ok := lookup(kw)
		if !ok {
			ref.Code = keywordCode(kw)
			p.cfg.Unknown = append(p.cfg.Unknown, ref)
			continue
		}
		switch k.class {
		case ignored:
		case include:
			p.include(args, depth, cur, ref)
		case match:
			cur = p.match(args, cur, ref)
		case scalar, accumulate, firstLine:
			if cur != nil && k.global {
				p.fail(ref, CodeNotInMatch)
				continue
			}
			p.set(cur, k, args, ref)
		}
	}
}

// include parses each file an Include argument names: relative to /etc/ssh,
// a pattern without matches is no error.
func (p *parser) include(args []string, depth int, cur *MatchBlock, ref Ref) {
	if len(args) == 0 {
		p.fail(ref, CodeMissingArgument)
		return
	}
	if depth+1 > maxIncludeDepth {
		p.fail(ref, CodeIncludeDepth)
		return
	}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "/") {
			arg = path.Join(sshDir, arg)
		}
		literal := !HasMeta(arg)
		names, errs := Glob(arg, p.files.ReadDir)
		p.cfg.ReadErrors = append(p.cfg.ReadErrors, errs...) // drop-ins unknown: RHEL keeps sshd_config.d at 0700
		for _, name := range names {
			p.parseFile(name, depth+1, cur, literal)
		}
	}
}

// match starts a Match block; "Match All" returns to the global context.
func (p *parser) match(args []string, cur *MatchBlock, ref Ref) *MatchBlock {
	if len(args) == 0 {
		p.fail(ref, CodeBadMatch)
		return cur
	}
	if len(args) == 1 && strings.EqualFold(args[0], "all") {
		return nil
	}
	if !p.validCriteria(args) {
		p.fail(ref, CodeBadMatch) // sshd exits; the criteria are never stored, so never sent
		return cur
	}
	b := &MatchBlock{Criteria: args, Source: ref.Source(), Keys: map[string]Value{}}
	p.cfg.MatchBlocks = append(p.cfg.MatchBlocks, b)
	return b
}

// set stores a keyword's values in the global context (block nil) or in a
// Match block, by the keyword's class.
func (p *parser) set(block *MatchBlock, k keyword, args []string, ref Ref) {
	source := ref.Source()
	if k.name == "Port" && p.portsFlag && source != SourceCmdline {
		return // -p overrides the Port lines of the files: sshd skips them unchecked
	}
	if len(args) == 0 {
		p.fail(ref, CodeMissingArgument)
		return
	}
	dst := p.cfg.Global
	if block != nil {
		dst = block.Keys
	}
	if k.class == scalar {
		if len(args) > 1 {
			p.fail(ref, CodeExtraArguments)
		}
		args = args[:1]
	}
	if k.enum {
		args = []string{normalizeEnum(k.name, args[0])}
	}
	if slices.ContainsFunc(args, func(v string) bool { return !p.validValue(k.name, v) }) {
		p.fail(ref, CodeBadValue) // sshd exits; the value is never stored, so never sent
		return
	}
	prev, seen := dst[k.name]
	switch k.class {
	case accumulate:
		if k.name == "Subsystem" {
			args = []string{strings.Join(args, " ")}
		}
		if seen {
			prev.Values = append(prev.Values, args...)
			dst[k.name] = prev
			return
		}
		dst[k.name] = Value{Values: args, Source: source}
	case firstLine:
		if !seen {
			dst[k.name] = Value{Values: args, Source: source}
		}
	case scalar:
		if !seen {
			dst[k.name] = Value{Values: args, Source: source}
		}
	case ignored, include, match: // not values
	}
}

func (p *parser) fail(ref Ref, code string) {
	ref.Code = code
	p.cfg.Errors = append(p.cfg.Errors, ref)
}

// normalizeEnum lowercases an enum value; without-password is the old name
// of prohibit-password.
func normalizeEnum(name, v string) string {
	v = strings.ToLower(v)
	if name == "PermitRootLogin" && v == "without-password" {
		return "prohibit-password"
	}
	return v
}

// keywordCode is an unknown keyword as it may be sent: only what looks like
// a distribution keyword — CamelCase letters, DebianBanner, GSSAPIKeyExchange.
// Anything else, digits included, could be the first word of a file that was
// never a config (a key, a token) and is sent as "invalid".
func keywordCode(kw string) string {
	if len(kw) == 0 || len(kw) > 40 || kw[0] < 'A' || kw[0] > 'Z' || strings.ToUpper(kw) == kw {
		return "invalid"
	}
	for _, c := range kw {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return "invalid"
		}
	}
	return kw
}
