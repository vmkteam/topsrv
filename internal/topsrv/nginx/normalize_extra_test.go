package nginx

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Normalization gaps found on production traffic, 2026-09-07.
func TestNormalizePath_ProdGaps(t *testing.T) {
	hex48 := strings.Repeat("0123456789abcdef", 3)
	for _, tc := range []struct{ in, want string }{
		{"/%u002f%u002eenv%u002elocal", "/:slug"}, // %uXXXX — non-standard unicode escape used by scanners
		{"/" + hex48 + ".flv", "/:hash.flv"},      // a hash longer than 32 hex used to leave a tail: /:hash3e49…
		{"/" + hex48[:32] + ".flv", "/:hash.flv"}, // 32 hex works as before
		{"/static/%E2%9C%93", "/static/:slug"},    // plain percent-encoding still handled
	} {
		assert.Equal(t, tc.want, normalizePath(tc.in), tc.in)
	}
}
