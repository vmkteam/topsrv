package topsrv

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTruncateAtRune(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"hello", 3, "hel"},
		{"hello", 10, "hello"}, // n >= len → unchanged
		{"hello", 0, ""},
		{"hello", -1, ""},
		{"яяя", 1, ""},  // 1 byte mid-rune → rewind to 0
		{"яяя", 2, "я"}, // 2 bytes = one rune
		{"яяя", 3, "я"}, // 3 bytes mid-rune of second → rewind
		{"яяя", 4, "яя"},
		{"a" + "я" + "b", 2, "a"}, // cut into the middle of `я`
		{"a" + "я" + "b", 3, "aя"},
	}
	for _, tt := range tests {
		got := TruncateAtRune(tt.in, tt.n)
		assert.Equal(t, tt.want, got, "TruncateAtRune(%q, %d)", tt.in, tt.n)
		assert.True(t, utf8.ValidString(got), "TruncateAtRune(%q, %d) produced invalid UTF-8: %q", tt.in, tt.n, got)
	}
}

// The reason the helper exists: encoding/json/v2 refuses to marshal a string
// holding invalid UTF-8, so a byte-offset cut of a multi-byte value does not
// merely mangle that field — it fails the marshal, and every batch encoder in
// this tree aborts the whole batch on the first error.
func TestTruncateAtRune_KeepsValueMarshalable(t *testing.T) {
	s := strings.Repeat("я", 20) // 40 bytes, every rune 2 bytes wide

	_, err := json.Marshal(s[:15]) // odd offset → mid-rune
	require.Error(t, err, "precondition: a mid-rune byte cut must fail to marshal")

	out, err := json.Marshal(TruncateAtRune(s, 15))
	require.NoError(t, err)
	assert.Equal(t, `"`+strings.Repeat("я", 7)+`"`, string(out))
}
