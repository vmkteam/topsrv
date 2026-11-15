package security

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
)

// APT configuration files: the parts directory first, then the main file,
// as pkgInitConfig of apt-pkg reads them (APT_CONFIG is left out: it is
// the environment of whoever runs apt).
const (
	aptConfDir  = "/etc/apt/apt.conf.d"
	aptConfMain = "/etc/apt/apt.conf"
)

// Limits of one APT configuration read.
const (
	aptMaxIncludeDepth = 10 // apt's own: "Too many nested includes"
	aptMaxFiles        = 128
	aptMaxNodes        = 20000 // a node per tag and list item
)

// Codes of lines apt refuses (configuration.cc): apt stops reading there
// and every apt command fails until the line is fixed.
const (
	aptCodeBlockNoName     = "block_without_name"
	aptCodeMalformedTag    = "malformed_tag"
	aptCodeExtraJunk       = "extra_junk"
	aptCodeDirectiveNested = "directive_not_top_level"
	aptCodeBadDirective    = "unsupported_directive"
	aptCodeClearNoTree     = "clear_without_tree"
	aptCodeJunkAtEnd       = "junk_at_end"
	aptCodeIncludeDepth    = "include_depth"
	aptCodeTooManyFiles    = "too_many_files"
	aptCodeTooManyNodes    = "too_many_nodes"
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
	root  aptNode
	nodes int
	// files read, in order; readErrs the ones named but unreadable.
	files    []string
	readErrs []aptReadError
	// err is the line apt stopped at; nil when apt accepts the files.
	err *lineRef
}

type aptReadError struct {
	path string
	err  error
}

// readAPTConfig reads the configuration as apt does.
func readAPTConfig(files aptFiles) *aptConfig {
	c := &aptConfig{}
	if c.readDir(files, aptConfDir, 0, true) {
		c.readFile(files, aptConfMain, 0, true)
	}
	return c
}

// readDir reads the files of dir apt would read, in byte order of their
// names. False when apt would stop.
func (c *aptConfig) readDir(files aptFiles, dir string, depth int, missingOK bool) bool {
	names, err := files.readDir(dir)
	if err != nil {
		if !missingOK || !errors.Is(err, fs.ErrNotExist) {
			c.readErrs = append(c.readErrs, aptReadError{dir, err})
		}
		return true
	}
	names = slices.DeleteFunc(names, func(n string) bool { return !aptPartName(n) })
	slices.Sort(names)
	for _, n := range names {
		if !c.readFile(files, dir+"/"+n, depth, false) {
			return false
		}
	}
	return true
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

// readFile reads one file into the tree. False when apt would stop.
func (c *aptConfig) readFile(files aptFiles, name string, depth int, missingOK bool) bool {
	if len(c.files) >= aptMaxFiles {
		c.err = &lineRef{File: name, Code: aptCodeTooManyFiles}
		return false
	}
	b, err := files.readFile(name)
	if err != nil {
		if !missingOK || !errors.Is(err, fs.ErrNotExist) {
			c.readErrs = append(c.readErrs, aptReadError{name, err})
		}
		return true
	}
	c.files = append(c.files, name)
	r := aptReader{cfg: c, files: files, name: name, depth: depth}
	return r.read(string(b))
}

// aptReader is ReadConfigFile of configuration.cc for one file.
type aptReader struct {
	cfg    *aptConfig
	files  aptFiles
	name   string
	depth  int
	line   int
	buf    string   // the statement read so far, it may span lines
	parent string   // the tag of the enclosing block
	stack  []string // parents of the enclosing blocks
}

func (r *aptReader) fail(code string) bool {
	r.cfg.err = &lineRef{File: r.name, Line: r.line, Code: code}
	return false
}

func (r *aptReader) read(text string) bool {
	inComment := false
	for n, line := range strings.Split(text, "\n") {
		r.line = n + 1
		var frag string
		frag, inComment = aptStripComments(line, inComment)
		if !r.statements(frag) {
			return false
		}
	}
	if r.buf != "" {
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
		if !r.statement(c) {
			return false
		}
	}
	r.appendBuf(frag[start:])
	return true
}

func (r *aptReader) appendBuf(s string) {
	if s = strings.TrimSpace(s); s == "" {
		return
	}
	if r.buf != "" {
		r.buf += " "
	}
	r.buf += s
}

// statement handles the buffer ended by term.
func (r *aptReader) statement(term byte) bool {
	if r.buf == "" {
		if term == '{' {
			return r.fail(aptCodeBlockNoName)
		}
		if term == '}' {
			r.pop()
		}
		return true
	}
	rest := r.buf
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
	item := r.item(term, &tag)
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
			return r.fail(aptCodeTooManyNodes)
		}
	}
	r.buf = ""
	if term == '}' {
		r.pop()
	}
	return true
}

// item opens a block for "{" and returns the full name the statement sets.
func (r *aptReader) item(term byte, tag *string) string {
	if term == '{' {
		r.stack = append(r.stack, r.parent)
		if r.parent == "" {
			r.parent = *tag
		} else {
			r.parent += "::" + *tag
		}
		*tag = ""
	}
	switch {
	case r.parent == "":
		return *tag
	case term != '{' || *tag != "":
		return r.parent + "::" + *tag
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
		if r.depth >= aptMaxIncludeDepth {
			return r.fail(aptCodeIncludeDepth)
		}
		if len(word) > 2 && strings.HasSuffix(word, "/") {
			return r.cfg.readDir(r.files, strings.TrimSuffix(word, "/"), r.depth+1, false)
		}
		return r.cfg.readFile(r.files, word, r.depth+1, false)
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
		for _, pair := range [...][2]byte{{'"', '"'}, {'[', ']'}} {
			if str[end] != pair[0] {
				continue
			}
			closeAt := strings.IndexByte(str[end+1:], pair[1])
			if closeAt < 0 {
				return "", false
			}
			end += 1 + closeAt
		}
		end++
	}
	var w strings.Builder
	for i := 0; i < end; i++ {
		switch {
		case str[i] == '%' && i+2 < end && isHex(str[i+1]) && isHex(str[i+2]):
			w.WriteByte(unhex(str[i+1])<<4 | unhex(str[i+2]))
			i += 2
		case str[i] != '"':
			w.WriteByte(str[i])
		}
	}
	*s = strings.TrimLeftFunc(str[end:], func(r rune) bool { return r < 0x80 && aptSpace(byte(r)) })
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

func aptSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

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
