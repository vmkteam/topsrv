//go:build !unix

package botlog

import "os"

// fileUID is unsupported on non-unix targets — callers fall back to trusting
// directory perms when this returns ok=false.
func fileUID(_ os.FileInfo) (int, bool) {
	return 0, false
}
