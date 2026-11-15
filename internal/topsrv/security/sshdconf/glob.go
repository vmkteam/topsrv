package sshdconf

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"
	"syscall"
)

// Match reports whether name matches a glob(3) pattern: "*" any run, "?"
// one byte, "[...]" a class with ranges and "[!...]" its negation, "\" an
// escape. A leading "." in name is matched only by a literal one, unlike
// filepath.Match. The match is iterative with one backtrack point per
// star, so a hostile pattern cannot make it exponential.
func Match(pattern, name string) bool {
	if strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".") && !strings.HasPrefix(pattern, `\.`) {
		return false
	}
	p, n := 0, 0
	starP, starN := -1, -1
	for n < len(name) {
		if p < len(pattern) {
			switch c := pattern[p]; c {
			case '*':
				starP, starN = p, n
				p++
				continue
			case '?':
				p, n = p+1, n+1
				continue
			case '[':
				if next, ok := classStep(pattern, p, name[n]); ok {
					p, n = next, n+1
					continue
				}
			case '\\':
				if p+1 < len(pattern) && pattern[p+1] == name[n] {
					p, n = p+2, n+1
					continue
				}
			default:
				if c == name[n] {
					p, n = p+1, n+1
					continue
				}
			}
		}
		if starP < 0 {
			return false
		}
		starN++
		p, n = starP+1, starN
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// classStep matches c at the class starting at pattern[p]; a "[" without a
// closing "]" is a literal "[". It returns the pattern index past it.
func classStep(pattern string, p int, c byte) (next int, ok bool) {
	in, next, closed := matchClass(pattern, p, c)
	if !closed {
		return p + 1, c == '['
	}
	return next, in
}

// matchClass matches c against the class starting at pattern[start] == '['.
// It returns whether c is in the class, the index past the class, and
// whether the class is closed at all.
func matchClass(pattern string, start int, c byte) (ok bool, next int, valid bool) {
	i := start + 1
	negate := i < len(pattern) && pattern[i] == '!'
	if negate {
		i++
	}
	first := true
	for i < len(pattern) {
		if pattern[i] == ']' && !first {
			return ok != negate, i + 1, true
		}
		first = false
		lo := pattern[i]
		if lo == '\\' && i+1 < len(pattern) {
			i++
			lo = pattern[i]
		}
		hi := lo
		if i+2 < len(pattern) && pattern[i+1] == '-' && pattern[i+2] != ']' {
			hi = pattern[i+2]
			i += 2
		}
		if lo <= c && c <= hi {
			ok = true
		}
		i++
	}
	return false, 0, false
}

// HasMeta reports whether a pattern needs matching.
func HasMeta(s string) bool { return strings.ContainsAny(s, `*?[\`) }

// Glob expands an absolute pattern component by component, listing with
// readDir only the directories a pattern component needs. The result is
// sorted bytewise, as glob(3) sorts; a literal pattern comes back as it is,
// and whether it exists is up to the reader. A directory that exists but
// cannot be listed is returned in errs: its matches are unknown, not none.
func Glob(pattern string, readDir func(dir string) ([]string, error)) (matches []string, errs []ReadError) {
	matches = []string{"/"}
	for comp := range strings.SplitSeq(strings.Trim(path.Clean(pattern), "/"), "/") {
		var next []string
		for _, dir := range matches {
			if !HasMeta(comp) {
				next = append(next, path.Join(dir, comp))
				continue
			}
			names, err := readDir(dir)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
					errs = append(errs, ReadError{Path: dir, Err: err})
				}
				continue
			}
			for _, name := range names {
				if Match(comp, name) {
					next = append(next, path.Join(dir, name))
				}
			}
		}
		matches = next
	}
	slices.Sort(matches)
	return matches, errs
}
