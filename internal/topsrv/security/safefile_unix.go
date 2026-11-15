//go:build unix

package security

import (
	"os"
	"syscall"
)

const (
	openFlags = syscall.O_NONBLOCK | syscall.O_NOCTTY
	oNoFollow = syscall.O_NOFOLLOW
)

// privateFile: only the agent's own user owns fi and may read or write it.
func privateFile(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && fi.Mode().Perm()&0o077 == 0 && int(st.Uid) == os.Geteuid()
}
