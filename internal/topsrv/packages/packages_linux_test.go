//go:build linux

package packages

import (
	"context"
	"testing"
	"time"

	"github.com/vmkteam/embedlog"
)

// Kernel packages are marked before the snapshot is cut to MaxPackages, so a
// pending kernel past the limit still sets RebootRequired.
func TestScanManagerMarksKernelsBeforeTruncation(t *testing.T) {
	c := NewCollector(embedlog.Logger{}, Config{})
	m := managerFunc{name: ManagerDpkg, scan: func(context.Context) (Snapshot, error) {
		return Snapshot{Manager: ManagerDpkg, Packages: []Package{
			deb("linux-image-6.8.0-90-generic", "6.8.0-90.91"),
			deb("linux-image-6.8.0-147-generic", "6.8.0-147.147"),
		}}, nil
	}}
	host := HostMeta{KernelRelease: "6.8.0-90-generic"}

	snap, _, ok := c.scanManager(t.Context(), m, host, 1, time.Now())
	if !ok {
		t.Fatal("scanManager failed")
	}
	if len(snap.Packages) != 1 || !snap.Packages[0].IsActiveKernel {
		t.Fatalf("packages = %+v, want only the active kernel", snap.Packages)
	}
	if !snap.RebootRequired {
		t.Error("pending kernel past the limit must still set RebootRequired")
	}
}

func TestBuildPendingPayloadsRebootRequired(t *testing.T) {
	host := HostMeta{OsID: "ubuntu", KernelRelease: "6.8.0-90-generic"}
	snaps := []Snapshot{
		{Manager: ManagerDpkg, RebootRequired: true},
		{Manager: ManagerRpm},
	}

	out := buildPendingPayloads(host, snaps, time.Now(), true)
	if len(out) != 2 {
		t.Fatalf("got %d payloads, want 2", len(out))
	}
	if !out[0].Host.RebootRequired || out[0].Host.PackageManager != ManagerDpkg {
		t.Errorf("dpkg payload host = %+v, want rebootRequired for dpkg", out[0].Host)
	}
	if out[1].Host.RebootRequired {
		t.Errorf("rpm payload host = %+v, want no rebootRequired", out[1].Host)
	}

	if got := buildPendingPayloads(host, snaps, time.Now(), false); got != nil {
		t.Errorf("push disabled: got %d payloads, want none", len(got))
	}
}
