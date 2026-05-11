//go:build unix

package botlog

import (
	"os"
	"syscall"
)

// fileUID returns the owning user id from a stat result. Unix-only.
func fileUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
