package security

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/vmkteam/topsrv/internal/topsrv/security/sshdconf"
)

// Limits of one authorized_keys file.
const (
	authKeysFileLimit = 1 << 20
	maxKeysPerFile    = 2000
)

// Values of authKeysFile.Status.
const (
	keysOK              = "ok"
	keysMissing         = "missing"
	keysUnreadable      = "unreadable"        // EACCES: NFS root_squash, not "no keys"
	keysSkippedRemoteFS = "skipped_remote_fs" // on a network or automount filesystem, not touched
	keysIgnoredBySSHD   = "ignored_by_sshd"   // StrictModes, or not a regular file
	keysTooLarge        = "too_large"
)

// authKeysData is the authorizedKeys section. A user not listed has none of
// the files sshd would read for them.
type authKeysData struct {
	Users []authKeysUser `json:"users"`
	// ConfigKnown: the paths come from the sshd configuration; false — it
	// was unreadable, and sshd's default paths were walked.
	ConfigKnown bool `json:"configKnown"`
	// KeysExternal: AuthorizedKeysCommand is set, keys may come from it too.
	KeysExternal  bool `json:"keysExternal"`
	TrustedUserCA bool `json:"trustedUserCA"`
}

type authKeysUser struct {
	Name  string         `json:"name"`
	Files []authKeysFile `json:"files"`
}

type authKeysFile struct {
	Path      string    `json:"path"`
	Status    string    `json:"status"`
	Keys      []authKey `json:"keys,omitempty"`
	Truncated bool      `json:"truncated,omitempty"` // more than maxKeysPerFile keys
}

func collectAuthorizedKeys(_ context.Context, sc *scanCtx) Section {
	acc, _ := sc.result(SectionAccounts).(*accountsResult)
	if acc == nil {
		return unknown(ReasonNotFound) // no users to walk
	}
	sshd, known := sc.result(SectionSSHD).(*sshdResult)
	switch {
	case known && sshd.notInstalled:
		return Section{Status: StatusNA}
	case !known:
		sshd = &sshdResult{authorizedKeysFiles: defaultAuthorizedKeysFiles, strictModes: true}
	}
	if _, err := sc.mountTable(); err != nil {
		return unknown(reasonOf(err)) // home directories may be on autofs: nothing is touched
	}
	d := authKeysData{Users: []authKeysUser{}, ConfigKnown: known, KeysExternal: sshd.keysCommand, TrustedUserCA: sshd.trustedCA}
	seen := map[string]authKeysFile{}
	for _, u := range acc.users {
		var files []authKeysFile
		for _, pattern := range sshd.filesFor(u.Name) {
			for _, p := range expandKeysPath(sc, pattern, u) {
				key := p + "\x00" + strconv.FormatInt(u.UID, 10) + "\x00" + u.home
				f, ok := seen[key]
				if !ok {
					f = readKeysFile(sc, p, u, sshd.strictModes)
					seen[key] = f
				}
				if f.Status != keysMissing {
					files = append(files, f)
				}
			}
		}
		if files != nil {
			d.Users = append(d.Users, authKeysUser{Name: u.Name, Files: files})
		}
	}
	return ok(d)
}

// filesFor is AuthorizedKeysFile for a user: a "Match User" block's, or
// the global one.
func (r *sshdResult) filesFor(user string) []string {
	if f, ok := r.userKeysFiles[user]; ok {
		return f
	}
	return r.authorizedKeysFiles
}

// expandKeysPath expands the tokens of an AuthorizedKeysFile entry (%% %h
// %u %U), makes it absolute from home, and expands a glob (OpenSSH 10).
func expandKeysPath(sc *scanCtx, pattern string, u account) []string {
	if strings.EqualFold(pattern, "none") {
		return nil
	}
	p := strings.NewReplacer("%%", "%", "%h", u.home, "%u", u.Name, "%U", strconv.FormatInt(u.UID, 10)).Replace(pattern)
	if !path.IsAbs(p) {
		if u.home == "" {
			return nil
		}
		p = path.Join(u.home, p)
	}
	p = path.Clean(p)
	if !strings.ContainsAny(p, "*?[") {
		return []string{p}
	}
	return globUser(sc, p)
}

// globUser expands a pattern over user directories, with sshd's glob(3)
// semantics.
func globUser(sc *scanCtx, pattern string) []string {
	matches := []string{"/"}
	for comp := range strings.SplitSeq(strings.Trim(pattern, "/"), "/") {
		var next []string
		for _, dir := range matches {
			if !strings.ContainsAny(comp, "*?[") {
				next = append(next, path.Join(dir, comp))
				continue
			}
			entries, err := sc.readDirUser(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if sshdconf.Match(comp, e.Name()) {
					next = append(next, path.Join(dir, e.Name()))
				}
			}
		}
		matches = next
	}
	return matches
}

// readKeysFile reads one authorized_keys file as sshd would: symlinks
// followed (each step checked against the mount table), only a regular
// file, StrictModes on the real path up to the real home directory. A file
// sshd ignores is still listed with its keys: they would work once fixed.
func readKeysFile(sc *scanCtx, p string, u account, strict bool) authKeysFile {
	f := authKeysFile{Path: p}
	resolved, err := sc.resolveUser(p)
	if err != nil {
		f.Status = keysStatusOf(err)
		return f
	}
	fi, err := sc.lstatUser(resolved)
	switch {
	case err != nil:
		f.Status = keysStatusOf(err)
		return f
	case !fi.Mode().IsRegular():
		f.Status = keysIgnoredBySSHD
		return f
	case fi.Size() > authKeysFileLimit:
		f.Status = keysTooLarge
		return f
	}
	b, err := sc.readUser(resolved, authKeysFileLimit)
	if err != nil {
		f.Status = keysStatusOf(err)
		return f
	}
	f.Status = keysOK
	if strict && !strictModesOK(sc, resolved, fi, u) {
		f.Status = keysIgnoredBySSHD
	}
	f.Keys = []authKey{}
	for line := range strings.SplitSeq(string(b), "\n") {
		k, ok := parseAuthKeyLine(line)
		if !ok {
			continue
		}
		if len(f.Keys) == maxKeysPerFile {
			f.Truncated = true
			break
		}
		f.Keys = append(f.Keys, k)
	}
	return f
}

// strictModesOK is sshd's auth_secure_path: the file and every directory up
// to the home directory are owned by root or the user and not writable by
// group or others.
func strictModesOK(sc *scanCtx, file string, fi fs.FileInfo, u account) bool {
	if !ownedSafely(fi, u.UID) {
		return false
	}
	home := ""
	if u.home != "" {
		home, _ = sc.resolveUser(u.home)
	}
	for dir := path.Dir(file); ; dir = path.Dir(dir) {
		dfi, err := sc.lstatUser(dir)
		if err != nil || !ownedSafely(dfi, u.UID) {
			return false
		}
		if dir == home || dir == "/" {
			return true
		}
	}
}

func ownedSafely(fi fs.FileInfo, uid int64) bool {
	owner, _ := fileOwner(fi)
	return (owner == 0 || owner == uid) && fi.Mode().Perm()&0o022 == 0
}

// keysStatusOf maps a read error to a file status: a path component that is
// not a directory is as missing to sshd as a file that is not there.
func keysStatusOf(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return keysMissing
	case errors.Is(err, errRemoteFS):
		return keysSkippedRemoteFS
	case errors.Is(err, errNotRegular), errors.Is(err, syscall.ELOOP):
		return keysIgnoredBySSHD
	case errors.Is(err, errTooLarge):
		return keysTooLarge
	}
	return keysUnreadable
}
