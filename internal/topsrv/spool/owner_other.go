//go:build !unix

package spool

import "os"

// fileUID has no owner to report off unix; the directory permissions are the
// only guard there.
func fileUID(_ os.FileInfo) (int, bool) {
	return 0, false
}
