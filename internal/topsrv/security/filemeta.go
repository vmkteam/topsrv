package security

import (
	"fmt"
	"io/fs"
)

// fileMeta describes a file the agent read, never its content.
type fileMeta struct {
	Path string `json:"path"`
	// Mode is the octal permission bits with setuid, setgid and sticky: "0640".
	Mode string `json:"mode"`
	UID  int64  `json:"uid"`
	GID  int64  `json:"gid"`
}

// statFile returns the metadata of path, symlinks followed.
func statFile(sc *scanCtx, path string) (fileMeta, error) {
	fi, err := sc.stat(path)
	if err != nil {
		return fileMeta{}, err
	}
	uid, gid := fileOwner(fi)
	return fileMeta{Path: path, Mode: modeString(fi.Mode()), UID: uid, GID: gid}, nil
}

func modeString(m fs.FileMode) string {
	bits := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		bits |= 0o1000
	}
	return fmt.Sprintf("%04o", bits)
}

// lineRef points at a line the agent could not use: never its text, which
// may hold a secret.
type lineRef struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Code string `json:"code"`
}
