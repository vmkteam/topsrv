package sshdconf

import "strings"

// Results of PatternList, as match_pattern_list of OpenSSH's match.c.
const (
	ListNegated = -1 // a "!pattern" matched: a negation wins
	ListNone    = 0
	ListMatch   = 1
)

// PatternList matches name against a comma-separated list of patterns as
// sshd matches Match User and Group: case-sensitive, "!" negates a pattern,
// and a negated match wins over any other.
func PatternList(name, list string) int {
	got := ListNone
	for p := range strings.SplitSeq(list, ",") {
		negated := strings.HasPrefix(p, "!")
		if !matchPattern(name, strings.TrimPrefix(p, "!")) {
			continue
		}
		if negated {
			return ListNegated
		}
		got = ListMatch
	}
	return got
}

// matchPattern is match_pattern of match.c: "*" any run, "?" one byte,
// nothing else special. Iterative, one backtrack point per star.
func matchPattern(s, pattern string) bool {
	si, pi := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			si++
			pi++
		case pi < len(pattern) && pattern[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			mark++
			si, pi = mark, star+1
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
