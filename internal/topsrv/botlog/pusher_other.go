//go:build !unix

package botlog

import "os"

func fileUID(_ os.FileInfo) (int, bool) {
	return 0, false
}
