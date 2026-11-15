package security

import (
	"context"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Sources of the accounts section.
const (
	pathPasswd   = "/etc/passwd"
	pathShadow   = "/etc/shadow"
	pathGroup    = "/etc/group"
	pathGshadow  = "/etc/gshadow"
	pathNSSwitch = "/etc/nsswitch.conf"
	codeFields   = "fields" // lineRef.Code: wrong number of fields
	codeID       = "id"     // lineRef.Code: a uid or gid that is no number
	algoBcrypt   = "bcrypt"
)

// accountsFileLimit caps passwd, shadow and group: a shared host with a few
// thousand users is well under it.
const accountsFileLimit = 8 << 20

// maxUsers listed. The receiving side caps the security data at 1 MB, and a
// user is about 150 bytes of JSON.
const maxUsers = 2000

// systemd gives DynamicUser= services uids from this range.
const dynamicUIDMin, dynamicUIDMax = 61184, 65519

// privilegedGroupNames: membership that is root or close to it. The docker,
// lxd and incus-admin groups are root in all but name.
var privilegedGroupNames = []string{"root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "incus-admin", "libvirt", "disk", "shadow"}

// Values of account.PW.
const (
	pwEmpty        = "empty"        // no password at all
	pwNone         = "none"         // a marker, see Marker: no password login
	pwLockedHash   = "lockedHash"   // "!" before a hash: locked, the hash kept
	pwHash         = "hash"         // a hash in shadow, see Algo
	pwHashInPasswd = "hashInPasswd" // a hash in world-readable passwd
)

// pwMarkers are sent as they are: they say how an account is closed and are
// no secret. sshd without PAM treats only a leading "!" as locked, "*" is a
// password that never matches (platform.c) — the difference matters. Any
// other text that is not a hash is "other": the field may hold anything, a
// plain password included.
var pwMarkers = []string{"!", "!!", "!*", "*", "*LK*", "*NP*", "x", "LK", "NP"}

// hashAlgos by crypt(5) prefix.
var hashAlgos = []struct{ prefix, algo string }{
	{"$y$", "yescrypt"},
	{"$gy$", "gost-yescrypt"},
	{"$7$", "scrypt"},
	{"$6$", "sha512"},
	{"$5$", "sha256"},
	{"$2a$", algoBcrypt},
	{"$2b$", algoBcrypt},
	{"$2x$", algoBcrypt},
	{"$2y$", algoBcrypt},
	{"$1$", "md5"},
}

// accountsData is the accounts section.
type accountsData struct {
	Users []account `json:"users"`
	// Truncated: more than maxUsers; the anomalies still cover every user.
	Truncated        bool                `json:"truncated,omitempty"`
	PrivilegedGroups map[string][]string `json:"privilegedGroups"`
	Anomalies        accountAnomalies    `json:"anomalies"`
	// NISCompat: passwd or group has NIS "+"/"-" lines, users the agent does
	// not see.
	NISCompat bool       `json:"nisCompat,omitempty"`
	NSS       *nssConfig `json:"nss"`
	Files     []fileMeta `json:"files"`
	Malformed []lineRef  `json:"malformed,omitempty"`
}

// account is one passwd user. GECOS is never read into it, the hash never
// leaves the host: only its class, algorithm and a keyed token that changes
// with the password.
type account struct {
	Name       string  `json:"name"`
	UID        int64   `json:"uid"`
	GID        int64   `json:"gid"`
	Shell      string  `json:"shell"`
	ShellClass string  `json:"shellClass"`
	PW         *string `json:"pw"` // null: shadow unread, or no shadow entry for "x"
	Marker     string  `json:"marker,omitempty"`
	Algo       string  `json:"algo,omitempty"`
	PWToken    string  `json:"pwToken,omitempty"`
	// LastChangeDays is the shadow field as kept: days since 1970-01-01 of
	// the last change, 0 — change at next login.
	LastChangeDays *int64 `json:"lastChangeDays"`
	// Expired: the account expiry date passed, or the password expired and
	// its inactive period ran out. Either blocks key logins too.
	Expired     *bool `json:"expired"`
	DynamicUser bool  `json:"dynamicUser,omitempty"`

	home string // for authorizedKeys, not sent
}

type accountAnomalies struct {
	UID0Users      []string `json:"uid0Users"`
	DuplicateUIDs  []int64  `json:"duplicateUids"`
	DuplicateNames []string `json:"duplicateNames"`
	// PasswdShadowMismatch: users with "x" in passwd and no shadow entry,
	// and shadow entries without a passwd user. null when shadow is unread.
	PasswdShadowMismatch []string `json:"passwdShadowMismatch"`
}

// accountsResult is what authorizedKeys builds on: every user, not only the
// listed ones, with home directories.
type accountsResult struct {
	users []account
}

type passwdEntry struct {
	name, pw, home, shell string
	uid, gid              int64
}

type shadowEntry struct {
	pw                                 string
	lastChange, max, inactive, expires *int64
}

type groupEntry struct {
	gid     int64
	members []string
}

func collectAccounts(_ context.Context, sc *scanCtx) (Section, any) {
	b, err := sc.read(pathPasswd, accountsFileLimit)
	if err != nil {
		return unknown(reasonOf(err)), nil
	}
	var (
		d    accountsData
		gaps gapList
	)
	users, malformed, compat := parsePasswd(b)
	d.Malformed, d.NISCompat = malformed, compat

	var shadow map[string]shadowEntry
	if b, err := sc.read(pathShadow, accountsFileLimit); err == nil {
		shadow, malformed = parseShadow(b)
		d.Malformed = append(d.Malformed, malformed...)
	} else {
		gaps.add(pathShadow, err)
	}
	var groups map[string]groupEntry
	if b, err := sc.read(pathGroup, accountsFileLimit); err == nil {
		groups, malformed, compat = parseGroup(b)
		d.Malformed = append(d.Malformed, malformed...)
		d.NISCompat = d.NISCompat || compat
	} else {
		gaps.add(pathGroup, err)
	}
	if b, err := sc.read(pathNSSwitch, smallFileLimit); err == nil {
		nss := parseNSSwitch(b)
		d.NSS = &nss
	} else {
		gaps.optional(pathNSSwitch, err) // musl has no NSS
	}

	all := buildAccounts(sc, users, shadow)
	d.Users = all
	if len(all) > maxUsers {
		d.Users, d.Truncated = all[:maxUsers], true
	}
	d.Anomalies = accountAnomaliesOf(users, shadow)
	d.Malformed = d.Malformed[:min(len(d.Malformed), maxLineRefs)]
	if groups != nil {
		d.PrivilegedGroups = privilegedMembers(users, groups)
	}
	d.Files = filesMeta(sc, []string{pathPasswd, pathShadow, pathGroup, pathGshadow})
	return collected(gaps, d), &accountsResult{users: all}
}

// parsePasswd parses name:pw:uid:gid:gecos:home:shell. GECOS is skipped
// unread. NIS compat lines ("+", "-", "+@netgroup") are not users.
func parsePasswd(b []byte) (users []passwdEntry, malformed []lineRef, nisCompat bool) {
	for n, line := range lines(b) {
		if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			nisCompat = true
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 7 || f[0] == "" {
			malformed = append(malformed, lineRef{File: pathPasswd, Line: n, Code: codeFields})
			continue
		}
		uid, err1 := strconv.ParseInt(f[2], 10, 64)
		gid, err2 := strconv.ParseInt(f[3], 10, 64)
		if err1 != nil || err2 != nil || uid < 0 || gid < 0 {
			malformed = append(malformed, lineRef{File: pathPasswd, Line: n, Code: codeID})
			continue
		}
		// Cloned: the result outlives the pass, the file must not.
		users = append(users, passwdEntry{name: strings.Clone(f[0]), pw: f[1], uid: uid, gid: gid, home: strings.Clone(f[5]), shell: strings.Clone(f[6])})
	}
	return users, malformed, nisCompat
}

// parseShadow parses name:pw:lastchg:min:max:warn:inactive:expire:reserved.
// An empty number is nil. A name listed twice keeps its first entry, as
// getspnam does.
func parseShadow(b []byte) (map[string]shadowEntry, []lineRef) {
	out := map[string]shadowEntry{}
	var malformed []lineRef
	for n, line := range lines(b) {
		f := strings.Split(line, ":")
		if len(f) < 8 || f[0] == "" {
			malformed = append(malformed, lineRef{File: pathShadow, Line: n, Code: codeFields})
			continue
		}
		if _, dup := out[f[0]]; dup {
			continue
		}
		out[f[0]] = shadowEntry{pw: f[1], lastChange: optInt(f[2]), max: optInt(f[4]), inactive: optInt(f[6]), expires: optInt(f[7])}
	}
	return out, malformed
}

// parseGroup parses name:pw:gid:members.
func parseGroup(b []byte) (groups map[string]groupEntry, malformed []lineRef, nisCompat bool) {
	groups = map[string]groupEntry{}
	for n, line := range lines(b) {
		if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			nisCompat = true
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 4 || f[0] == "" {
			malformed = append(malformed, lineRef{File: pathGroup, Line: n, Code: codeFields})
			continue
		}
		gid, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil || gid < 0 {
			malformed = append(malformed, lineRef{File: pathGroup, Line: n, Code: codeID})
			continue
		}
		if _, dup := groups[f[0]]; dup {
			continue
		}
		var members []string
		for m := range strings.SplitSeq(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		groups[f[0]] = groupEntry{gid: gid, members: members}
	}
	return groups, malformed, nisCompat
}

// lines yields the non-empty, non-comment lines of b with their 1-based
// numbers.
func lines(b []byte) func(yield func(int, string) bool) {
	return func(yield func(int, string) bool) {
		n := 0
		for line := range strings.SplitSeq(string(b), "\n") {
			n++
			line = strings.TrimSuffix(line, "\r")
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !yield(n, line) {
				return
			}
		}
	}
}

func optInt(s string) *int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

// buildAccounts classifies every user. A passwd field other than "x" is
// what the system uses: shadow is not consulted then.
func buildAccounts(sc *scanCtx, users []passwdEntry, shadow map[string]shadowEntry) []account {
	today := sc.today()
	out := make([]account, 0, len(users))
	for _, u := range users {
		a := account{
			Name: u.name, UID: u.uid, GID: u.gid, Shell: u.shell, ShellClass: shellClass(u.shell),
			DynamicUser: u.uid >= dynamicUIDMin && u.uid <= dynamicUIDMax,
			home:        u.home,
		}
		switch s, ok := shadow[u.name]; {
		case u.pw != "x":
			a.setPW(sc, classifyPW(u.pw, true))
		case ok:
			a.setPW(sc, classifyPW(s.pw, false))
			a.LastChangeDays = s.lastChange
			expired := s.expired(today)
			a.Expired = &expired
		}
		out = append(out, a)
	}
	return out
}

func (a *account) setPW(sc *scanCtx, c pwClass) {
	a.PW, a.Marker, a.Algo = &c.pw, c.marker, c.algo
	if c.hash != "" {
		a.PWToken = sc.key.token(a.Name, c.hash)
	}
}

// expired follows pam_unix: an expiry date reached, or a password past its
// maximum age plus the inactive period.
func (s shadowEntry) expired(today int64) bool {
	if s.expires != nil && *s.expires >= 0 && today >= *s.expires {
		return true
	}
	return s.lastChange != nil && *s.lastChange > 0 && s.max != nil && *s.max >= 0 &&
		s.inactive != nil && *s.inactive >= 0 && today-*s.lastChange > *s.max+*s.inactive
}

// pwClass is a classified password field; hash is the part a password change
// changes, the input of the token: the hash without the lock prefix, so
// locking an account does not look like a new password.
type pwClass struct {
	pw, marker, algo, hash string
}

func classifyPW(field string, inPasswd bool) pwClass {
	if field == "" {
		return pwClass{pw: pwEmpty}
	}
	hash := strings.TrimLeft(field, "!")
	if algo := hashAlgo(hash); algo != "" {
		switch {
		case inPasswd:
			return pwClass{pw: pwHashInPasswd, algo: algo, hash: hash}
		case len(hash) < len(field):
			return pwClass{pw: pwLockedHash, algo: algo, hash: hash}
		}
		return pwClass{pw: pwHash, algo: algo, hash: hash}
	}
	marker := "other"
	if i := slices.Index(pwMarkers, field); i >= 0 {
		marker = pwMarkers[i] // the constant, not a slice of the shadow file
	}
	return pwClass{pw: pwNone, marker: marker}
}

// hashAlgo names the crypt(5) scheme of s: "other" for an unknown $id$,
// "des" for 13 characters of the crypt alphabet, "" for what is no hash.
func hashAlgo(s string) string {
	for _, h := range hashAlgos {
		if strings.HasPrefix(s, h.prefix) {
			return h.algo
		}
	}
	switch {
	case strings.HasPrefix(s, "$") && strings.Count(s, "$") >= 2:
		return "other"
	case len(s) == 13 && strings.Trim(s, "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") == "":
		return "des"
	}
	return ""
}

// Values of account.ShellClass.
const (
	shellLogin   = "login"
	shellNologin = "nologin"
	shellFalse   = "false"
	shellOther   = "other"
)

// loginShells are interactive shells; an empty field means /bin/sh.
var loginShells = []string{"sh", "bash", "rbash", "dash", "ash", "zsh", "ksh", "mksh", "fish", "tcsh", "csh"}

func shellClass(shell string) string {
	base := filepath.Base(shell)
	switch {
	case shell == "" || slices.Contains(loginShells, base):
		return shellLogin
	case base == "nologin":
		return shellNologin
	case base == "false":
		return shellFalse
	}
	return shellOther
}

func accountAnomaliesOf(users []passwdEntry, shadow map[string]shadowEntry) accountAnomalies {
	a := accountAnomalies{UID0Users: []string{}, DuplicateUIDs: []int64{}, DuplicateNames: []string{}}
	byUID, byName := map[int64]int{}, map[string]int{}
	for _, u := range users {
		if u.uid == 0 {
			a.UID0Users = append(a.UID0Users, u.name)
		}
		byUID[u.uid]++
		byName[u.name]++
	}
	for uid, n := range byUID {
		if n > 1 {
			a.DuplicateUIDs = append(a.DuplicateUIDs, uid)
		}
	}
	for name, n := range byName {
		if n > 1 {
			a.DuplicateNames = append(a.DuplicateNames, name)
		}
	}
	slices.Sort(a.DuplicateUIDs)
	slices.Sort(a.DuplicateNames)
	if shadow == nil {
		return a
	}
	a.PasswdShadowMismatch = []string{}
	for _, u := range users {
		if _, ok := shadow[u.name]; u.pw == "x" && !ok {
			a.PasswdShadowMismatch = append(a.PasswdShadowMismatch, u.name)
		}
	}
	for name := range shadow {
		if byName[name] == 0 {
			a.PasswdShadowMismatch = append(a.PasswdShadowMismatch, strings.Clone(name)) // not a slice of the shadow file
		}
	}
	slices.Sort(a.PasswdShadowMismatch)
	a.PasswdShadowMismatch = slices.Compact(a.PasswdShadowMismatch)
	return a
}

// privilegedMembers lists the members of each privileged group present:
// those in the member list and those whose primary group it is.
func privilegedMembers(users []passwdEntry, groups map[string]groupEntry) map[string][]string {
	out := map[string][]string{}
	for _, name := range privilegedGroupNames {
		g, ok := groups[name]
		if !ok {
			continue
		}
		members := slices.Clone(g.members)
		for _, u := range users {
			if u.gid == g.gid {
				members = append(members, u.name)
			}
		}
		slices.Sort(members)
		out[name] = slices.Compact(members)
		if out[name] == nil {
			out[name] = []string{}
		}
	}
	return out
}
