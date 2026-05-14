//go:build linux

package packages

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

// detectHost populates HostMeta from /etc/os-release + /proc/sys/kernel/osrelease.
// PackageManager is left empty — the caller fills it per-snapshot since one host
// may have multiple managers (rare: dpkg+rpm cohabitation in containers).
// `root` enables chroot-style scans (e.g. /mnt/host-root for sidecar deployments);
// the production collector passes "".
func detectHost(root string) HostMeta {
	h := HostMeta{
		KernelArch: runtime.GOARCH,
	}

	if f, err := os.Open(root + "/etc/os-release"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "ID":
				h.OsID = v
			case "VERSION_ID":
				h.OsVersionID = v
			case "VERSION_CODENAME":
				h.OsVersionCodename = v
			case "ID_LIKE":
				h.OsIDLike = strings.Fields(v)
			case "PRETTY_NAME":
				h.OsPrettyName = v
			}
		}
	}

	if b, err := os.ReadFile(root + "/proc/sys/kernel/osrelease"); err == nil {
		h.KernelRelease = strings.TrimSpace(string(b))
	}

	return h
}
