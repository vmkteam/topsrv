package sshdconf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPatternList(t *testing.T) {
	cases := []struct {
		name, list string
		want       int
	}{
		{"alice", "alice", ListMatch},
		{"alice", "bob,alice", ListMatch},
		{"alice", "a*", ListMatch},
		{"alice", "al?ce", ListMatch},
		{"alice", "*,!alice", ListNegated},
		{"alice", "!bob", ListNone},  // a negation alone matches nothing
		{"Alice", "alice", ListNone}, // case-sensitive
		{".hidden", "*", ListMatch},  // no glob(3) leading-dot rule
		{"deploy-01", "deploy-*,!deploy-0?", ListNegated},
		{"aaa", "*a*a*a*", ListMatch},
		{"aab", "*a*a*a*", ListNone},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, PatternList(tc.name, tc.list), "%s ~ %s", tc.name, tc.list)
	}
}
