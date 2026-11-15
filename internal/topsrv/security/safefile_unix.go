//go:build unix

package security

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	openFlags = syscall.O_NONBLOCK | syscall.O_NOCTTY
	oNoFollow = syscall.O_NOFOLLOW
	// dirFlags: O_DIRECTORY fails a FIFO or a file with ENOTDIR before any
	// wait for a writer.
	dirFlags = syscall.O_DIRECTORY | syscall.O_NONBLOCK
)

// clearNonblock puts a checked regular file back to blocking reads: the flag
// only kept the open from hanging on a FIFO, and a FUSE filesystem may honour
// it and fail a read with EAGAIN.
func clearNonblock(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := rc.Control(func(fd uintptr) { setErr = syscall.SetNonblock(int(fd), false) }); err != nil {
		return err
	}
	return setErr
}

// privateFile: only the agent's own user owns fi and may read or write it.
func privateFile(fi os.FileInfo) bool {
	uid, _ := fileOwner(fi)
	return fi.Mode().Perm()&0o077 == 0 && uid == int64(os.Geteuid())
}

// fileOwner returns the owner uid and gid of fi.
func fileOwner(fi os.FileInfo) (uid, gid int64) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int64(st.Uid), int64(st.Gid)
}

// openNoSymlinks opens root/rel walking rel one component at a time with
// O_NOFOLLOW: a component that is a symlink, even one swapped in after the
// path was checked, fails the open (ELOOP) instead of being followed.
// Directories are opened O_DIRECTORY, so a FIFO in their place fails
// (ENOTDIR) without blocking. A file must be regular before and after the
// open; it is put back to blocking reads. root is trusted and followed.
func openNoSymlinks(root, rel string, dir bool) (*os.File, error) {
	fail := func(err error) (*os.File, error) { return nil, &fs.PathError{Op: opOpen, Path: rel, Err: err} }
	start := root
	if start == "" {
		start = "/"
	}
	fd, err := unix.Open(start, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	comps := strings.Split(strings.Trim(filepath.Clean("/"+rel), "/"), "/")
	for i, c := range comps {
		if c == "" {
			continue
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		last := i == len(comps)-1
		if last && !dir {
			var st unix.Stat_t
			if statErr := unix.Fstatat(fd, c, &st, unix.AT_SYMLINK_NOFOLLOW); statErr != nil {
				unix.Close(fd)
				return fail(statErr)
			}
			if st.Mode&unix.S_IFMT != unix.S_IFREG {
				unix.Close(fd)
				return fail(errNotRegular) // never opened: a device acts on open
			}
			flags |= unix.O_NOCTTY
		} else {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, c, flags, 0)
		unix.Close(fd)
		if openErr != nil {
			return fail(openErr)
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), rel)
	if dir {
		return f, nil
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return fail(errNotRegular)
	}
	if err := clearNonblock(f); err != nil {
		f.Close()
		return fail(err)
	}
	return f, nil
}
