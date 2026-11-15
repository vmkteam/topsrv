package security

import (
	"path"
	"slices"
	"strings"
)

// PAM service directories: the administrator's, then the vendor's, whose
// files apply where /etc/pam.d has none of the same name (Linux-PAM
// vendordir: openSUSE, Fedora with libeconf).
var pamDirs = []string{"/etc/pam.d", "/usr/lib/pam.d"}

// collectPAMNullok lists the PAM service files where pam_unix takes nullok
// for auth or password: an empty password then logs in (sshd with
// PermitEmptyPasswords, su, login). nil without PAM (Alpine): no service
// directory.
func collectPAMNullok(sc *scanCtx, gaps *gapList) []string {
	var (
		out   []string
		found bool
		seen  = map[string]bool{}
	)
	for _, dir := range pamDirs {
		infos, err := sc.readDirFiles(dir)
		gaps.optional(dir, err)
		if err == nil {
			found = true
		}
		for _, fi := range infos {
			if seen[fi.Name()] {
				continue // overridden in /etc/pam.d
			}
			seen[fi.Name()] = true
			p := dir + "/" + fi.Name()
			b, err := sc.read(p, smallFileLimit)
			if err != nil {
				gaps.add(p, err)
				continue
			}
			if pamUnixNullok(string(b)) {
				out = append(out, p)
			}
		}
	}
	if !found {
		return nil
	}
	slices.Sort(out)
	return append([]string{}, out...)
}

// pamUnixNullok: a line "auth|password <control> pam_unix.so … nullok",
// the control a word or a [bracket] list, a leading "-" on the type (PAM
// skips the line if the module is missing). nullok_secure (old Debian)
// counts.
func pamUnixNullok(text string) bool {
	for line := range strings.SplitSeq(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		if typ := strings.ToLower(strings.TrimPrefix(f[0], "-")); typ != "auth" && typ != "password" {
			continue
		}
		module := 2
		if strings.HasPrefix(f[1], "[") {
			for module = 1; module < len(f) && !strings.Contains(f[module], "]"); module++ {
			}
			module++
		}
		if module >= len(f) || path.Base(f[module]) != "pam_unix.so" {
			continue
		}
		if slices.ContainsFunc(f[module+1:], func(a string) bool { return a == "nullok" || a == "nullok_secure" }) {
			return true
		}
	}
	return false
}
