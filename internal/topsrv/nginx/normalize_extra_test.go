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

// Per-file and per-page URIs that slipped through normalization and gave a
// host thousands of new series a day, 2026-11-14.
func TestNormalizePath_MediaFilesAndTitles(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// media file names in the last segment collapse, the extension stays (lowercased)
		{"/gallery/photo_2023-05-12_14-33-21.png", "/gallery/:file.png"},
		{"/gallery/IMG_0042.JPG", "/gallery/:file.jpg"},
		{"/gallery/Xk3pQ9zL.jpg", "/gallery/:file.jpg"},
		{"/gallery/clip.mp4_snapshot_00.05.120.png", "/gallery/:file.png"},
		{"/logo.svg", "/:file.svg"},
		{"/video/trailer.MP4", "/video/:file.mp4"},
		{"/apple-touch-icon.png", "/:slug.png"}, // already a single marker — kept
		{"/favicon.ico", "/favicon.ico"},        // .ico is not collapsed
		{"/robots.txt", "/robots.txt"},          // nor are non-media files
		{"/gallery/.png", "/gallery/.png"},      // dotfile, not a name with an extension
		{"/a/b/photo.jpg", "/a/b/:rest"},        // depth cap still applies
		{"photo.jpg", ":file.jpg"},              // no slash at all (absolute-form or junk request target)
		{"example.com:443", "example.com:443"},  // CONNECT target

		// wiki-style page titles collapse into :slug
		{"/wiki/Main_Page", "/wiki/:slug"},
		{"/wiki/Star_Trek:_The_Next_Generation", "/wiki/:slug"},
		{"/wiki/Hello_world", "/wiki/:slug"},
		{"/wiki/2001_A_Space_Odyssey", "/wiki/:slug"},                   // a leading number must not become :id first
		{"/wiki/List_of_tallest_buildings_in_the_world", "/wiki/:slug"}, // long title, not a :rest token

		// identifiers and codes keep their names
		{"/api/get_user", "/api/get_user"},
		{"/en_US/", "/en_US/"},
		{"/docs/README_FIRST", "/docs/README_FIRST"},
		{"/wiki/Paris", "/wiki/Paris"}, // a single-word title has no separator to tell it from a route
	} {
		assert.Equal(t, tc.want, normalizePath(tc.in), tc.in)
	}
}
