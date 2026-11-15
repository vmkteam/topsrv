package security

import (
	"context"
	"slices"
	"strconv"
	"strings"
)

// APT configuration files: the parts directory first, then the main file,
// as pkgInitConfig of apt-pkg reads them (APT_CONFIG is left out: it is
// the environment of whoever runs apt).
const (
	aptConfDir  = "/etc/apt/apt.conf.d"
	aptConfMain = "/etc/apt/apt.conf"
)

// aptMaxIncludeDepth is apt's own: a file deeper than this may not include
// ("Too many nested includes").
const aptMaxIncludeDepth = 10

// Limits of the agent on one APT configuration read. Reaching one is a gap,
// not a line apt refuses: nothing more is read.
const (
	aptMaxFiles      = 128
	aptMaxNodes      = 20000 // a node per tag and list item
	aptCtxCheckLines = 1024  // lines between checks of the section budget
)

// Codes of lines apt refuses (configuration.cc). apt stops reading the file
// there, and the files including it, goes on with the next file, and every
// apt command fails until the line is fixed.
const (
	aptCodeBlockNoName     = "block_without_name"
	aptCodeMalformedTag    = "malformed_tag"
	aptCodeExtraJunk       = "extra_junk"
	aptCodeDirectiveNested = "directive_not_top_level"
	aptCodeBadDirective    = "unsupported_directive"
	aptCodeClearNoTree     = "clear_without_tree"
	aptCodeJunkAtEnd       = "junk_at_end"
	aptCodeIncludeDepth    = "include_depth"
)

// aptFiles reads the configuration: readFile one file, readDir the names in
// a directory.
type aptFiles struct {
	readFile func(path string) ([]byte, error)
	readDir  func(dir string) ([]string, error)
}

// aptNode is one item of the configuration tree. Tags match case-
// insensitively, as Configuration::Lookup does; a list item has no tag.
type aptNode struct {
	tag      string
	value    string
	children []*aptNode
}

// aptConfig is the merged APT configuration with what reading it found.
type aptConfig struct {
	ctx   context.Context
	io    aptFiles
	root  aptNode
	nodes int
	files []string  // read, in order
	gaps  gapList   // named but unreadable, or past a limit: not read
	errs  []lineRef // lines apt refuses, one per file at most
	halt  bool      // a limit or the budget was reached: nothing more is read
}

// readAPTConfig reads the configuration as pkgInitConfig does: every file,
// even after one apt refuses.
func readAPTConfig(ctx context.Context, files aptFiles) *aptConfig {
	c := &aptConfig{ctx: ctx, io: files}
	c.readDir(aptConfDir, 0, true)
	c.readFile(aptConfMain, 0, true)
	return c
}

// valid: apt accepts the configuration, and all of it was read.
func (c *aptConfig) valid() bool { return len(c.errs) == 0 && len(c.gaps) == 0 }

// readDir reads the files of dir apt would read, in byte order of their
// names, each one even after a failed one (ReadConfigDir). False when apt
// refuses one of them.
func (c *aptConfig) readDir(dir string, depth int, missingOK bool) bool {
	names, err := c.io.readDir(dir)
	if err != nil {
		c.gap(dir, err, missingOK)
		return true
	}
	names = slices.DeleteFunc(names, func(n string) bool { return !aptPartName(n) })
	slices.Sort(names)
	ok := true
	for _, n := range names {
		ok = c.readFile(dir+"/"+n, depth, false) && ok
	}
	return ok
}

// gap records a source that could not be read; a missing one is not a gap
// when apt does without it.
func (c *aptConfig) gap(path string, err error, missingOK bool) {
	if missingOK {
		c.gaps.optional(path, err)
		return
	}
	c.gaps.add(path, err)
}

// stop ends the read at path: a limit of the agent or the section budget.
func (c *aptConfig) stop(path string, err error) {
	c.gaps.add(path, err)
	c.halt = true
}

// aptPartName is GetListOfFilesInDir of fileutl.cc with extension "conf"
// and no extension allowed: letters, digits, "_", "-", ":" and ".", not a
// leading or trailing dot; with a dot, the extension must be "conf".
// apt.conf.d/50unattended-upgrades.dpkg-old is skipped.
func aptPartName(n string) bool {
	if n == "" || n[0] == '.' || n[len(n)-1] == '.' {
		return false
	}
	for _, c := range n {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("_-:.", c) {
			return false
		}
	}
	dot := strings.LastIndexByte(n, '.')
	return dot < 0 || n[dot+1:] == "conf"
}

// readFile reads one file into the tree. False when apt refuses a line of
// it, or of a file it includes.
func (c *aptConfig) readFile(name string, depth int, missingOK bool) bool {
	switch {
	case c.halt:
		return true
	case c.ctx.Err() != nil:
		c.stop(name, c.ctx.Err())
		return true
	case len(c.files) >= aptMaxFiles:
		c.stop(name, errTooLarge)
		return true
	}
	b, err := c.io.readFile(name)
	if err != nil {
		c.gap(name, err, missingOK)
		return true
	}
	c.files = append(c.files, name)
	r := aptReader{cfg: c, name: name, depth: depth}
	return r.read(string(b))
}

// aptReader is ReadConfigFile of configuration.cc for one file.
type aptReader struct {
	cfg    *aptConfig
	name   string
	depth  int
	line   int
	buf    strings.Builder // the statement read so far, it may span lines
	parent string          // the tag of the enclosing block
	stack  []string        // parents of the enclosing blocks
}

func (r *aptReader) fail(code string) bool {
	r.cfg.errs = append(r.cfg.errs, lineRef{File: r.name, Line: r.line, Code: code})
	return false
}

// read returns false when apt refuses a line; a read stopped by a limit is
// not apt's doing.
func (r *aptReader) read(text string) bool {
	inComment := false
	for line := range strings.SplitSeq(text, "\n") {
		if r.line++; r.line%aptCtxCheckLines == 0 && r.cfg.ctx.Err() != nil {
			r.cfg.stop(r.name, r.cfg.ctx.Err())
		}
		if r.cfg.halt {
			return true
		}
		var frag string
		frag, inComment = aptStripComments(line, inComment)
		if !r.statements(frag) {
			return r.cfg.halt
		}
	}
	if r.buf.Len() > 0 {
		return r.fail(aptCodeJunkAtEnd)
	}
	return true
}

// aptStripComments drops "//" and "#" comments outside quotes — "#clear"
// and "#include" are directives — and /* */ comments, which may span lines.
func aptStripComments(line string, inComment bool) (string, bool) {
	if inComment {
		end := strings.Index(line, "*/")
		if end < 0 {
			return "", true
		}
		line = line[end+2:]
	}
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '"':
			inQuote = !inQuote
		case inQuote:
		case strings.HasPrefix(line[i:], "//"),
			line[i] == '#' && !strings.HasPrefix(line[i:], "#clear") && !strings.HasPrefix(line[i:], "#include") &&
				!strings.HasPrefix(line[i:], "#x-apt-configure-index"):
			line = line[:i]
		}
	}
	if !strings.Contains(line, "/*") {
		return line, false
	}
	var out strings.Builder
	inQuote = false
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '"':
			inQuote = !inQuote
			out.WriteByte('"')
		case !inQuote && strings.HasPrefix(line[i:], "/*"):
			end := strings.Index(line[i+2:], "*/")
			if end < 0 {
				return out.String(), true
			}
			i += 2 + end + 1
		default:
			out.WriteByte(line[i])
		}
	}
	return out.String(), false
}

// statements processes a comment-free fragment: each "{", ";" or "}"
// outside quotes ends what the buffer holds.
func (r *aptReader) statements(frag string) bool {
	start, inQuote := 0, false
	for i := range len(frag) {
		c := frag[i]
		if c == '"' {
			inQuote = !inQuote
		}
		if inQuote || c != '{' && c != ';' && c != '}' {
			continue
		}
		r.appendBuf(frag[start:i])
		start = i + 1
		if !r.statement(c) || r.cfg.halt {
			return false // apt refused it, or a limit stopped the read
		}
	}
	r.appendBuf(frag[start:])
	return true
}

func (r *aptReader) appendBuf(s string) {
	if s = strings.TrimSpace(s); s == "" {
		return
	}
	if r.buf.Len() > 0 {
		r.buf.WriteByte(' ')
	}
	r.buf.WriteString(s)
}

// statement handles the buffer ended by term.
func (r *aptReader) statement(term byte) bool {
	if r.buf.Len() == 0 {
		if term == '{' {
			return r.fail(aptCodeBlockNoName)
		}
		if term == '}' {
			r.pop()
		}
		return true
	}
	rest := r.buf.String()
	tag, ok := aptQuoteWord(&rest)
	if !ok {
		return r.fail(aptCodeMalformedTag)
	}
	word, ok := aptCWord(&rest)
	if !ok {
		word, ok = aptQuoteWord(&rest)
	}
	noWord := false
	if !ok {
		if term == '{' {
			noWord = true
		} else {
			word, tag = tag, ""
		}
	}
	if rest != "" {
		return r.fail(aptCodeExtraJunk)
	}
	if term == '{' {
		r.open(tag)
		tag = ""
	}
	item := r.itemName(term, tag)
	switch {
	case strings.HasPrefix(tag, "#"):
		if r.parent != "" {
			return r.fail(aptCodeDirectiveNested)
		}
		if !r.directive(tag[1:], word) {
			return false
		}
	case tag == "" && !noWord && word == "#clear":
		return r.fail(aptCodeClearNoTree)
	case !noWord:
		if !r.cfg.set(item, word) {
			r.cfg.stop(r.name, errTooLarge)
			return false
		}
	}
	r.buf.Reset()
	if term == '}' {
		r.pop()
	}
	return true
}

// open enters the block a "{" starts.
func (r *aptReader) open(tag string) {
	r.stack = append(r.stack, r.parent)
	if r.parent == "" {
		r.parent = tag
	} else {
		r.parent += "::" + tag
	}
}

// itemName is the full name a statement sets: its tag in the enclosing
// block, or the block itself for the value of "tag value {".
func (r *aptReader) itemName(term byte, tag string) string {
	switch {
	case r.parent == "":
		return tag
	case term != '{' || tag != "":
		return r.parent + "::" + tag
	default:
		return r.parent
	}
}

func (r *aptReader) pop() {
	if len(r.stack) == 0 {
		r.parent = ""
		return
	}
	r.parent, r.stack = r.stack[len(r.stack)-1], r.stack[:len(r.stack)-1]
}

func (r *aptReader) directive(name, word string) bool {
	switch name {
	case "clear":
		r.cfg.clear(word)
	case "include":
		if r.depth > aptMaxIncludeDepth {
			return r.fail(aptCodeIncludeDepth)
		}
		if len(word) > 2 && strings.HasSuffix(word, "/") {
			return r.cfg.readDir(strings.TrimSuffix(word, "/"), r.depth+1, false)
		}
		return r.cfg.readFile(word, r.depth+1, false)
	case "x-apt-configure-index":
	default:
		return r.fail(aptCodeBadDirective)
	}
	return true
}

// aptQuoteWord is ParseQuoteWord of strutl.cc: a word up to whitespace
// outside quotes and brackets, quotes removed, %xx decoded.
func aptQuoteWord(s *string) (string, bool) {
	str := strings.TrimLeft(*s, " ")
	if str == "" {
		return "", false
	}
	end := 0
	for end < len(str) && !aptSpace(str[end]) {
		if c := str[end]; c == '"' || c == '[' {
			closing := byte('"')
			if c == '[' {
				closing = ']'
			}
			closeAt := strings.IndexByte(str[end+1:], closing)
			if closeAt < 0 {
				return "", false
			}
			end += 1 + closeAt
		}
		end++
	}
	var w strings.Builder
	for i := 0; i < end; i++ {
		if str[i] == '%' && i+2 < end {
			if b, err := strconv.ParseUint(str[i+1:i+3], 16, 8); err == nil {
				w.WriteByte(byte(b))
				i += 2
				continue
			}
		}
		if str[i] != '"' {
			w.WriteByte(str[i])
		}
	}
	*s = strings.TrimLeft(str[end:], aptSpaces)
	return w.String(), true
}

// aptCWord is ParseCWord of strutl.cc: only quoted strings, consecutive
// ones joined by a space; false at anything unquoted.
func aptCWord(s *string) (string, bool) {
	str := strings.TrimLeft(*s, " ")
	if str == "" {
		return "", false
	}
	var w strings.Builder
	for i := 0; i < len(str); i++ {
		switch {
		case str[i] == '"':
			end := strings.IndexByte(str[i+1:], '"')
			if end < 0 {
				return "", false
			}
			w.WriteString(str[i+1 : i+1+end])
			i += 1 + end
		case !aptSpace(str[i]):
			return "", false
		case i > 0 && aptSpace(str[i-1]):
		default:
			w.WriteByte(' ')
		}
	}
	*s = ""
	return w.String(), true
}

// aptSpaces are isspace(3) in the C locale.
const aptSpaces = " \t\n\r\v\f"

func aptSpace(c byte) bool { return strings.IndexByte(aptSpaces, c) >= 0 }

// lookup returns the node of name, creating it when create is set: an
// empty last segment ("A::") always appends a list item.
func (c *aptConfig) lookup(name string, create bool) *aptNode {
	n := &c.root
	for seg := range strings.SplitSeq(name, "::") {
		var next *aptNode
		if seg != "" {
			for _, ch := range n.children {
				if strings.EqualFold(ch.tag, seg) {
					next = ch
					break
				}
			}
		}
		if next == nil {
			if !create || c.nodes >= aptMaxNodes {
				return nil
			}
			next = &aptNode{tag: seg}
			n.children = append(n.children, next)
			c.nodes++
		}
		n = next
	}
	return n
}

// set is Configuration::Set; false when the tree is full.
func (c *aptConfig) set(name, value string) bool {
	n := c.lookup(name, true)
	if n == nil {
		return false
	}
	n.value = value
	return true
}

// clear is Configuration::Clear: the value and everything under the node.
func (c *aptConfig) clear(name string) {
	if n := c.lookup(name, false); n != nil {
		n.value, n.children = "", nil
	}
}

// value returns the value of name; nil when it is not set.
func (c *aptConfig) value(name string) *string {
	n := c.lookup(name, false)
	if n == nil || n.value == "" {
		return nil
	}
	return &n.value
}

// list returns the values under name in order, as FindVector does.
func (c *aptConfig) list(name string) []string {
	out := []string{}
	if n := c.lookup(name, false); n != nil {
		for _, ch := range n.children {
			out = append(out, ch.value)
		}
	}
	return out
}
