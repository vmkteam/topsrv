//go:build linux

package packages

import (
	"context"

	"github.com/vmkteam/topsrv/internal/topsrv/inventory"

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

// newManagers returns dispatch entries for the named managers, keeping their
// order. Names come from [Packages].Managers or inventory.Managers; unknown
// names are skipped.
//
// `root` enables chroot-style scans (e.g. /mnt/host-root); production passes "".
func newManagers(logger embedlog.Logger, root string, names []string) []managerFunc {
	out := make([]managerFunc, 0, len(names))
	for _, name := range names {
		switch name {
		case inventory.ManagerDpkg:
			d := NewDpkg(logger, root)
			out = append(out, managerFunc{name: d.Name(), scan: d.Scan})
		case inventory.ManagerRpm:
			r := NewRpm(logger, root)
			out = append(out, managerFunc{name: r.Name(), scan: r.Scan})
		case inventory.ManagerApk:
			a := NewApk(logger, root)
			out = append(out, managerFunc{name: a.Name(), scan: a.Scan})
		}
	}
	return out
}
