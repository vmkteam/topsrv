//go:build linux

package packages

import (
	"context"
	"os"

	"github.com/vmkteam/embedlog"
)

// managerFunc bundles a manager's name with its Scan method. No interface
// here on purpose — concrete types are clearer (Go philosophy: interfaces
// only when polymorphism is actually needed for dispatch). This struct just
// holds the dispatch pair, the implementations live on *Dpkg, *Rpm, *Apk.
type managerFunc struct {
	name string
	scan func(context.Context) (Snapshot, error)
}

// detectManagers probes the filesystem for marker files of each supported
// package manager and returns dispatch entries for every match. Order:
// dpkg first (Ubuntu/Debian) → rpm → apk. Hosts with multiple managers
// (containers with mixed origin) yield multiple entries.
//
// `root` enables chroot-style scans (e.g. /mnt/host-root); production passes "".
func detectManagers(logger embedlog.Logger, root string) []managerFunc {
	var out []managerFunc
	if fileExists(root + dpkgStatusPath) {
		d := NewDpkg(logger, root)
		out = append(out, managerFunc{name: d.Name(), scan: d.Scan})
	}
	if r := NewRpm(logger, root); r.findDB() != "" {
		out = append(out, managerFunc{name: r.Name(), scan: r.Scan})
	}
	if fileExists(root + apkInstalledPath) {
		a := NewApk(logger, root)
		out = append(out, managerFunc{name: a.Name(), scan: a.Scan})
	}
	return out
}

// fileExists hides the err-ignoring intent of Stat. Marker-file probes
// don't distinguish "missing" from "no permission" — both mean "skip".
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
