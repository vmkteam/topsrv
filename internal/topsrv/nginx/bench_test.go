package nginx

import (
	"strings"
	"testing"
)

// Representative URI shapes from real traffic: clean paths, UUID/numeric IDs,
// hyphenated slugs, TLS-handshake garbage from scanners, long transliterated
// slugs and base64url tokens. mixed_case_clean is the worst case for the
// hasUpper gate: the regex runs but finds nothing to replace.
var normalizePathBenchCases = []struct {
	name string
	path string
}{
	{"clean_short", "/api/users/profile"},
	{"clean_deep", "/api/v1/users/profile/settings/notifications"},
	{"mixed_case_clean", "/API/Users/Profile/Settings"},
	{"numeric_id", "/api/users/12345/profile"},
	{"uuid", "/api/users/e1f2c3a4-b5d6-7890-1234-567890abcdef/profile"},
	{"hex_hash", "/media/d41d8cd98f00b204e9800998ecf8427e/thumb.jpg"},
	{"hyphen_slug", "/blog/why-go-is-great-for-systems-programming"},
	{"slug_with_id", "/articles/tommy-brewster-6401345/"},
	{"php", "/wp-content/uploads/index.php"},
	{"scanner_env", "/.env"},
	{"tls_handshake", `/\x16\x03\x01\x00\xCA\x01\x00\x00\xC6\x03\x03\x87(\xC7a\xDF\xDC\x19\xB4\xB9\x10\x93\x0F\x1EQ\xD7WX=D1\x94\xB4A\xA9\xB1\xF9`},
	{"long_translit_slug", "/product/-ultrabalance-zhelezo-khelatnoe-premium-iron-chelated-premium-with-bioperine-vitamini-khelat-s-piperinom-417587/"},
	{"long_base64url_token", "/NrEvh6tMN89fyP8TglRaD5mwSRlVEej3QpFsmTeWO5ruhygoPovMxET15o3xAj4cuXrnNSo-Lf96Ay3nlY5VNiU2mLMbPdXd_6zcgMIcsg0"},
	{"already_normalized", "/api/:id/:rest"},
	{"very_long_300b", "/api/" + strings.Repeat("segment-", 40) + "tail"},
}

func BenchmarkNormalizePath(b *testing.B) {
	for _, tc := range normalizePathBenchCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				_ = normalizePath(tc.path)
			}
		})
	}
}
