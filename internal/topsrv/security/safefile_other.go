//go:build !unix

package security

import "os"

// Off unix the collector reports unsupported_platform; the flags only keep
// the package building.
const (
	openFlags = 0
	oNoFollow = 0
)

// privateFile has no owner to check off unix.
func privateFile(os.FileInfo) bool { return true }
