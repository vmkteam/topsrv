package security

import (
	"errors"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// login.defs of shadow-utils: /etc/login.defs, or the vendor file under
// /usr/etc when /etc has none (libeconf builds, openSUSE), then drop-ins.
const (
	pathLoginDefs       = "/etc/login.defs"
	pathLoginDefsVendor = "/usr/etc/login.defs"
)

// loginDefsChecks are the keys sent, with the form shadow-utils takes; any
// other form is sent as "invalid", the rest of the file never.
var loginDefsChecks = map[string]*regexp.Regexp{
	"ENCRYPT_METHOD":       regexp.MustCompile(`^(DES|MD5|SHA256|SHA512|BCRYPT|YESCRYPT)$`),
	"PASS_MAX_DAYS":        reNumber,
	"PASS_MIN_DAYS":        reNumber,
	"PASS_WARN_AGE":        reNumber,
	"UID_MIN":              reNumber,
	"UID_MAX":              reNumber,
	"SYS_UID_MIN":          reNumber,
	"SYS_UID_MAX":          reNumber,
	"GID_MIN":              reNumber,
	"GID_MAX":              reNumber,
	"SHA_CRYPT_MIN_ROUNDS": reNumber,
	"SHA_CRYPT_MAX_ROUNDS": reNumber,
	"YESCRYPT_COST_FACTOR": reNumber,
	"FAIL_DELAY":           reNumber,
	"LOGIN_RETRIES":        reNumber,
	"UMASK":                reOctalMode,
	"HOME_MODE":            reOctalMode,
	"USERGROUPS_ENAB":      regexp.MustCompile(`^(?i:yes|no)$`),
}

var (
	reNumber    = regexp.MustCompile(`^-?[0-9]{1,10}$`)
	reOctalMode = regexp.MustCompile(`^0?[0-7]{3,4}$`)
)

// collectLoginDefs reads the keys of loginDefsChecks; nil without a file.
// Later lines win, as getdef.c keeps the last value.
func collectLoginDefs(sc *scanCtx, gaps *gapList) map[string]string {
	base := pathLoginDefs
	if !sc.exists(base) && sc.exists(pathLoginDefsVendor) {
		base = pathLoginDefsVendor
	}
	dropins := map[string]string{} // name → path; /etc overrides /usr/etc
	for _, dir := range []string{pathLoginDefsVendor + ".d", pathLoginDefs + ".d"} {
		infos, err := sc.readDirFiles(dir)
		gaps.optional(dir, err)
		for _, fi := range infos {
			if strings.HasSuffix(fi.Name(), ".conf") {
				dropins[fi.Name()] = dir + "/" + fi.Name()
			}
		}
	}
	files := make([]string, 0, 1+len(dropins))
	files = append(files, base)
	for _, name := range slices.Sorted(maps.Keys(dropins)) {
		files = append(files, dropins[name])
	}
	var out map[string]string
	for _, p := range files {
		b, err := sc.read(p, smallFileLimit)
		if err != nil {
			gaps.optional(p, err)
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		for line := range strings.SplitSeq(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			re, ok := loginDefsChecks[f[0]]
			if !ok {
				continue
			}
			v := strings.Trim(f[1], `"`)
			if !re.MatchString(v) {
				v = valueInvalid
			}
			out[f[0]] = v
		}
	}
	return out
}

// collectShells reads /etc/shells: the shells chsh and pam_shells accept.
// Without the file glibc's getusershell() takes /bin/sh and /bin/csh; nil
// when it is unreadable.
func collectShells(sc *scanCtx, gaps *gapList) map[string]bool {
	b, err := sc.read("/etc/shells", smallFileLimit)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return map[string]bool{"/bin/sh": true, "/bin/csh": true}
	case err != nil:
		gaps.add("/etc/shells", err)
		return nil
	}
	out := map[string]bool{}
	for line := range strings.SplitSeq(string(b), "\n") {
		if l := strings.TrimSpace(line); l != "" && l[0] != '#' {
			out[l] = true
		}
	}
	return out
}
