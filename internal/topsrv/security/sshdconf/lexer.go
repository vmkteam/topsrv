package sshdconf

import "strings"

// Codes of Ref.Code for lines sshd refuses.
const (
	CodeUnterminatedQuote = "unterminated_quote"
	CodeMissingArgument   = "missing_argument"
	CodeExtraArguments    = "extra_arguments"
	CodeNotInMatch        = "not_allowed_in_match"
	CodeIncludeDepth      = "include_depth"
	CodeTooManyFiles      = "too_many_files"
	CodeBadMatch          = "bad_match"
)

// whitespace is WHITESPACE of OpenSSH misc.h.
const whitespace = " \t\r\n"

// splitLine splits a configuration line the way sshd does: the keyword ends
// at whitespace or at one "=", the rest is split like argv_split() of
// misc.c — quotes, backslash escapes, and "#" starting a comment only at the
// start of a token. An empty keyword means a blank or comment line.
func splitLine(line string) (kw string, args []string, code string) {
	line = strings.TrimRight(line, whitespace+"\f")
	s := strings.TrimLeft(line, whitespace)
	if s == "" || s[0] == '#' {
		return "", nil, ""
	}
	end := strings.IndexAny(s, " \t\r\n=\"")
	if end < 0 {
		return s, nil, ""
	}
	kw, s = s[:end], s[end:]
	// One "=" may separate the keyword, with whitespace around it or not.
	if s[0] == '=' {
		s = strings.TrimLeft(s[1:], whitespace)
	} else if s = strings.TrimLeft(s, whitespace); strings.HasPrefix(s, "=") {
		s = strings.TrimLeft(s[1:], whitespace)
	}
	args, ok := argvSplit(s)
	if !ok {
		return kw, nil, CodeUnterminatedQuote
	}
	return kw, args, ""
}

// argvSplit is argv_split() of OpenSSH misc.c with terminate_on_comment.
func argvSplit(s string) ([]string, bool) {
	var args []string
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			continue
		}
		if s[i] == '#' {
			break
		}
		var (
			arg   strings.Builder
			quote byte
		)
		for ; i < len(s); i++ {
			c := s[i]
			switch {
			case c == '\\' && i+1 < len(s) && (s[i+1] == '\'' || s[i+1] == '"' || s[i+1] == '\\' || quote == 0 && s[i+1] == ' '):
				i++
				arg.WriteByte(s[i])
				continue
			case quote == 0 && (c == ' ' || c == '\t'):
			case quote == 0 && (c == '"' || c == '\''):
				quote = c
				continue
			case quote != 0 && c == quote:
				quote = 0
				continue
			default:
				arg.WriteByte(c)
				continue
			}
			break // unquoted whitespace ends the token
		}
		if quote != 0 {
			return nil, false
		}
		args = append(args, arg.String())
	}
	return args, true
}
