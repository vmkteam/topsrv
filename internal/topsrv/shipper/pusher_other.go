//go:build !unix

package shipper

import "os"

func fileUID(_ os.FileInfo) (int, bool) {
	return 0, false
}
