//go:build linux

package packages

import (
	"strings"
	"testing"
)

func TestRpmParseSrcRpm(t *testing.T) {
	m := &Rpm{}
	cases := []struct {
		in       string
		wantName string
		wantVer  string
	}{
		// Standard: name has no hyphens.
		{"openssl-1.1.1k-7.el8_6.src.rpm", "openssl", "1.1.1k-7.el8_6"},
		// Tricky: name contains hyphens — last two hyphens split version/release,
		// everything before is the source name. Vulners CVE mapping depends on this.
		{"kernel-headers-5.14.0-362.el9.src.rpm", "kernel-headers", "5.14.0-362.el9"},
		{"libnss-systemd-252.16-1.fc39.src.rpm", "libnss-systemd", "252.16-1.fc39"},
		// Without .src suffix (some rpm builds).
		{"foo-1.0-1.rpm", "foo", "1.0-1"},
		// Degenerate cases — must not panic.
		{"foo", "foo", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		gotName, gotVer := m.parseSrcRpm(tc.in)
		if gotName != tc.wantName || gotVer != tc.wantVer {
			t.Errorf("parseSrcRpm(%q) = (%q, %q), want (%q, %q)",
				tc.in, gotName, gotVer, tc.wantName, tc.wantVer)
		}
	}
}

func TestDpkgParseSource(t *testing.T) {
	m := &Dpkg{}
	cases := []struct {
		raw, binary string
		wantName    string
		wantVer     string
	}{
		// Empty Source: → fallback to binary name (Debian convention).
		{"", "openssl", "openssl", ""},
		// Just a source name, no version in parens.
		{"openssl", "libssl3", "openssl", ""},
		// Source with version.
		{"openssl (1.1.1-1ubuntu2)", "libssl3", "openssl", "1.1.1-1ubuntu2"},
		// Malformed: open paren without close — graceful degradation, no panic.
		{"openssl (", "libssl3", "openssl", ""},
		// Whitespace around tokens.
		{"  foo   ( 1.2.3 )  ", "x", "foo", "1.2.3"},
	}
	for _, tc := range cases {
		gotName, gotVer := m.parseSource(tc.raw, tc.binary)
		if gotName != tc.wantName || gotVer != tc.wantVer {
			t.Errorf("parseSource(%q, %q) = (%q, %q), want (%q, %q)",
				tc.raw, tc.binary, gotName, gotVer, tc.wantName, tc.wantVer)
		}
	}
}

func TestDpkgParseRFC822(t *testing.T) {
	m := &Dpkg{}
	// Two packages, multi-line Description (continuation with leading space),
	// blank-line separator between records.
	in := `Package: foo
Version: 1.0
Description: short
 long line continues
 second continued line

Package: bar
Version: 2.0
Description: another
`
	records, err := m.parseRFC822(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseRFC822: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if got := records[0]["Package"]; got != "foo" {
		t.Errorf("record[0].Package = %q, want foo", got)
	}
	if got := records[0]["Description"]; got != "short\nlong line continues\nsecond continued line" {
		t.Errorf("record[0].Description continuation broken: %q", got)
	}
	if got := records[1]["Version"]; got != "2.0" {
		t.Errorf("record[1].Version = %q, want 2.0", got)
	}
}

func TestDpkgParseRFC822Empty(t *testing.T) {
	m := &Dpkg{}
	records, err := m.parseRFC822(strings.NewReader(""))
	if err != nil {
		t.Fatalf("parseRFC822(empty): %v", err)
	}
	if len(records) != 0 {
		t.Errorf("got %d records, want 0", len(records))
	}
}

func TestApkSetChecksum(t *testing.T) {
	m := &Apk{}
	cases := []struct {
		in       string
		wantDig  string
		wantAlgo string
	}{
		{"", "", ""},
		{"Q1abc123", "abc123", "sha1"},
		{"Q2xyz789", "xyz789", "sha256"},
		{"raw-no-prefix", "raw-no-prefix", ""}, // forward-compat: unknown prefix → keep raw
	}
	for _, tc := range cases {
		var p Package
		m.setChecksum(&p, tc.in)
		if p.SigDigest != tc.wantDig || p.SigAlgorithm != tc.wantAlgo {
			t.Errorf("setChecksum(%q) = (%q, %q), want (%q, %q)",
				tc.in, p.SigDigest, p.SigAlgorithm, tc.wantDig, tc.wantAlgo)
		}
	}
}

func TestRpmExtractKeyID(t *testing.T) {
	m := &Rpm{}
	cases := []struct {
		fields []string
		want   string
	}{
		// Standard rpm PGP string.
		{[]string{"RSA/SHA256, Mon Nov 20 12:00:00, Key ID 199e2f91fd431d51"}, "199e2f91fd431d51"},
		// Lowercase normalization.
		{[]string{"Key ID ABCD1234"}, "abcd1234"},
		// Fallback to second field when first empty.
		{[]string{"", "DSA, Key ID 1234abcd5678"}, "1234abcd5678"},
		// No match at all.
		{[]string{"", ""}, ""},
		{[]string{"no key id here"}, ""},
	}
	for _, tc := range cases {
		got := m.extractKeyID(tc.fields...)
		if got != tc.want {
			t.Errorf("extractKeyID(%v) = %q, want %q", tc.fields, got, tc.want)
		}
	}
}
