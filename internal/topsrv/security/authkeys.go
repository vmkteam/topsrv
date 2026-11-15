package security

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/vmkteam/topsrv/internal/topsrv/security/sshdconf"
)

// Limits of one authorized_keys file, and of the section: the receiving
// side caps a snapshot at 1 MB, a key is about 120 bytes of JSON.
const (
	authKeysFileLimit = 1 << 20
	maxKeysPerFile    = 2000
	maxKeysTotal      = 2000
)

// Values of authKeysFile.Status.
const (
	keysOK              = "ok"
	keysMissing         = "missing"
	keysUnreadable      = "unreadable"        // EACCES: NFS root_squash, not "no keys"
	keysRemoteFSSkipped = "remote_fs_skipped" // on a network or automount filesystem, not touched
	keysIgnoredBySSHD   = "ignored_by_sshd"   // StrictModes, or not a regular file
	keysTooLarge        = "too_large"
)

// authKeysData is the authorizedKeys section. A user not listed has none of
// the files sshd would read for them.
type authKeysData struct {
	Users []authKeysUser `json:"users"`
	// Truncated: more than maxKeysTotal keys in all; the files past it are
	// listed without keys.
	Truncated bool `json:"truncated,omitempty"`
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
	Path   string `json:"path"`
	Status string `json:"status"`
	// Keys is null when the file was not read, [] when it has none.
	Keys      []authKey `json:"keys"`
	Truncated bool      `json:"truncated,omitempty"` // more than maxKeysPerFile keys
}

func collectAuthorizedKeys(ctx context.Context, sc *scanCtx) Section {
	accSec, accRes, _ := sc.dep(SectionAccounts)
	acc, _ := accRes.(*accountsResult)
	if acc == nil {
		return unknown(cmp.Or(accSec.Reason, ReasonNotFound)) // no users to walk
	}
	var gaps gapList
	sshdSec, sshdRes, sshdRan := sc.dep(SectionSSHD)
	sshd, known := sshdRes.(*sshdResult)
	switch {
	case sshdSec.Status == StatusNA:
		return Section{Status: StatusNA}
	case !known:
		sshd = sshdResultOf(&sshdconf.Config{}) // sshd's default paths
		if sshdRan {
			gaps.add(sshdconf.DefaultConfig, reasonError(sshdSec.Reason))
		}
	}
	if _, err := sc.mountTable(); err != nil {
		return unknown(reasonOf(err)) // home directories may be on autofs: nothing is touched
	}
	d := authKeysData{Users: []authKeysUser{}, ConfigKnown: known, KeysExternal: sshd.keysCommand, TrustedUserCA: sshd.trustedCA}
	read := map[string]keysFile{} // a file shared by users is read once
	for _, u := range acc.users {
		if ctx.Err() != nil {
			return unknown(ReasonTimeout)
		}
		if files := userKeysFiles(sc, sshd, u, read, &gaps); files != nil {
			d.Users = append(d.Users, authKeysUser{Name: u.Name, Files: files})
		}
	}
	d.Truncated = capKeys(d.Users, maxKeysTotal)
	return collected(gaps, d)
}

// capKeys keeps at most limit keys in all, in order; it reports whether any
// were dropped.
func capKeys(users []authKeysUser, limit int) bool {
	truncated := false
	for i := range users {
		for j := range users[i].Files {
			f := &users[i].Files[j]
			if len(f.Keys) > limit {
				f.Keys, truncated = f.Keys[:limit], true
			}
			limit -= len(f.Keys)
		}
	}
	return truncated
}

// userKeysFiles walks the files sshd would read for u, missing ones left out.
// read caches files by path; StrictModes is checked per user, as it
// depends on the owner and home.
func userKeysFiles(sc *scanCtx, sshd *sshdResult, u account, read map[string]keysFile, gaps *gapList) []authKeysFile {
	var files []authKeysFile
	for _, pattern := range sshd.filesFor(u.Name) {
		paths, errs := expandKeysPath(sc, pattern, u)
		for _, e := range errs {
			gaps.add(e.Path, e.Err)
		}
		for _, p := range paths {
			kf, ok := read[p]
			if !ok {
				kf = readKeysFile(sc, p)
				read[p] = kf
				switch kf.Status {
				case keysUnreadable, keysRemoteFSSkipped, keysTooLarge: // keys there or not, unknown
					gaps.add(p, kf.err)
				}
			}
			if kf.Status == keysMissing {
				continue
			}
			f := kf.authKeysFile
			if f.Status == keysOK && (!readableBy(kf.fi, u) || sshd.strictModes && !strictModesOK(sc, kf.resolved, kf.fi, u)) {
				f.Status = keysIgnoredBySSHD
			}
			files = append(files, f)
		}
	}
	return files
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
// %u %U), makes it absolute from home, and expands a glob (OpenSSH 10);
// directories the glob could not list come back as errors.
func expandKeysPath(sc *scanCtx, pattern string, u account) ([]string, []sshdconf.ReadError) {
	if strings.EqualFold(pattern, "none") {
		return nil, nil
	}
	p := pattern
	if strings.Contains(p, "%") {
		p = strings.NewReplacer("%%", "%", "%h", u.home, "%u", u.Name, "%U", strconv.FormatInt(u.UID, 10)).Replace(p)
	}
	if !path.IsAbs(p) {
		p = path.Join("/", u.home, p) // an empty home: sshd reads /.ssh/authorized_keys
	}
	p = path.Clean(p)
	if !sshdconf.HasMeta(p) {
		return []string{p}, nil
	}
	return sshdconf.Glob(p, func(dir string) ([]string, error) { return entryNames(sc.readDirUser(dir)) })
}

// keysFile is one authorized_keys file as read, before StrictModes, which
// depends on the user.
type keysFile struct {
	authKeysFile
	resolved string
	fi       fs.FileInfo
	err      error // why it was not read; nil when read
}

// readKeysFile reads one authorized_keys file as sshd would: symlinks
// followed (each step checked against the mount table), only a regular
// file, up to authKeysFileLimit. A file sshd ignores is still listed with
// its keys: they would work once fixed.
func readKeysFile(sc *scanCtx, p string) keysFile {
	f := keysFile{Path: p}
	var (
		b   []byte
		err error
	)
	if f.resolved, err = sc.resolveUser(p); err == nil {
		b, f.fi, err = sc.readUser(f.resolved, authKeysFileLimit) // fi of the file read, for StrictModes
	}
	if err != nil {
		f.Status, f.err = keysStatusOf(err), err
		return f
	}
	f.Status, f.Keys = keysOK, []authKey{}
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

// readableBy: sshd opens the file as the user, not as root — a link to
// /root/.ssh/authorized_keys gives the user nothing. Root reads any file.
// Supplementary groups are not known here, only the primary one.
func readableBy(fi fs.FileInfo, u account) bool {
	uid, gid := fileOwner(fi)
	perm := fi.Mode().Perm()
	switch {
	case u.UID == 0:
		return true
	case uid == u.UID:
		return perm&0o400 != 0
	case gid == u.GID:
		return perm&0o040 != 0
	}
	return perm&0o004 != 0
}

func ownedSafely(fi fs.FileInfo, uid int64) bool {
	owner, _ := fileOwner(fi)
	return (owner == 0 || owner == uid) && fi.Mode().Perm()&0o022 == 0
}

// keysStatusOf is the file status of a read error, the reason as for any
// source, named as sshd sees the file: a path component that is not a
// directory is as missing to sshd as a file that is not there.
func keysStatusOf(err error) string {
	if errors.Is(err, syscall.ENOTDIR) {
		return keysMissing
	}
	switch reasonOf(err) {
	case ReasonNotFound:
		return keysMissing
	case ReasonRemoteFSSkipped:
		return keysRemoteFSSkipped
	case ReasonNotRegular:
		return keysIgnoredBySSHD
	case ReasonBudgetExceeded:
		return keysTooLarge
	case ReasonPermissionDenied, ReasonIOError, // root_squash, EIO
		ReasonParseError, ReasonTimeout, ReasonContainerEnv, ReasonUnsupportedPlatform, ReasonDumpInconsistent:
	}
	return keysUnreadable
}
