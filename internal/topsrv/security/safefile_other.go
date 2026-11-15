//go:build !unix

package security

import "os"

// Off unix the collector reports unsupported_platform; the flags only keep
// the package building.
const (
	openFlags = 0
	oNoFollow = 0
	dirFlags  = 0
)

func clearNonblock(*os.File) error { return nil }

// privateFile has no owner to check off unix.
func privateFile(os.FileInfo) bool { return true }

// fileOwner has no owner to report off unix.
func fileOwner(os.FileInfo) (uid, gid int64) { return -1, -1 }
