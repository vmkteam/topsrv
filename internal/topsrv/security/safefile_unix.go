//go:build unix

package security

import (
	"os"
	"syscall"
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
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && fi.Mode().Perm()&0o077 == 0 && int(st.Uid) == os.Geteuid()
}
