package topsrv

import "unicode/utf8"

// TruncateAtRune returns s[:n] adjusted backwards to a UTF-8 rune boundary, so
// the result is valid UTF-8 whenever s is.
//
// Every caller cuts a byte budget, not a character count — Prometheus label
// values are capped in bytes, and so is the ingest payload — but cutting at a
// raw byte offset splits multi-byte runes (Cyrillic, CJK) and produces invalid
// UTF-8. That is not cosmetic downstream: encoding/json/v2 refuses to marshal
// a string containing invalid UTF-8, and a single such value fails the whole
// batch it happens to sit in, not just that one field.
func TruncateAtRune(s string, n int) string {
	if n >= len(s) {
		return s
	}
	if n <= 0 {
		return ""
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
