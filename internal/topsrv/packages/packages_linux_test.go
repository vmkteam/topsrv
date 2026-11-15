//go:build linux

package packages

import (
	"context"
	"testing"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/inventory"

	"github.com/vmkteam/embedlog"
)

// Kernel packages are marked before the snapshot is cut to MaxPackages, so a
// pending kernel past the limit still sets RebootRequired.
func TestScanManagerMarksKernelsBeforeTruncation(t *testing.T) {
	c := NewCollector(embedlog.Logger{}, Config{})
	m := managerFunc{name: inventory.ManagerDpkg, scan: func(context.Context) (Snapshot, error) {
		return Snapshot{Manager: inventory.ManagerDpkg, Packages: []Package{
			deb("linux-image-6.8.0-90-generic", "6.8.0-90.91"),
			deb("linux-image-6.8.0-147-generic", "6.8.0-147.147"),
		}}, nil
	}}
	host := inventory.HostMeta{KernelRelease: "6.8.0-90-generic"}

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

// /var/run/reboot-required sets rebootRequired on dpkg without a newer
// kernel; other managers go by the kernel alone.
func TestScanManagerRebootRequiredFile(t *testing.T) {
	c := NewCollector(embedlog.Logger{}, Config{})
	rebootFilesRoot = rebootRoot(t, true, "libc6\n")
	t.Cleanup(func() { rebootFilesRoot = "" })
	host := inventory.HostMeta{KernelRelease: "6.8.0-90-generic"}
	scan := func(manager string) Snapshot {
		m := managerFunc{name: manager, scan: func(context.Context) (Snapshot, error) {
			return Snapshot{Manager: manager, Packages: []Package{deb("linux-image-6.8.0-90-generic", "6.8.0-90.91")}}, nil
		}}
		snap, _, ok := c.scanManager(t.Context(), m, host, 100, time.Now())
		if !ok {
			t.Fatal("scanManager failed")
		}
		return snap
	}

	dpkg := scan(inventory.ManagerDpkg)
	if !dpkg.RebootRequired || len(dpkg.RebootRequiredPackages) != 1 || dpkg.RebootRequiredPackages[0] != "libc6" {
		t.Errorf("dpkg: got %v %q, want a reboot for libc6", dpkg.RebootRequired, dpkg.RebootRequiredPackages)
	}
	if rpm := scan(inventory.ManagerRpm); rpm.RebootRequired || rpm.RebootRequiredPackages != nil {
		t.Errorf("rpm: got %v %q, want the kernel rule only", rpm.RebootRequired, rpm.RebootRequiredPackages)
	}
}

func TestBuildPendingPayloadsRebootRequired(t *testing.T) {
	host := inventory.HostMeta{OsID: "ubuntu", KernelRelease: "6.8.0-90-generic"}
	snaps := []Snapshot{
		{Manager: inventory.ManagerDpkg, RebootRequired: true},
		{Manager: inventory.ManagerRpm},
	}

	out := buildPendingPayloads(host, snaps, time.Now(), true)
	if len(out) != 2 {
		t.Fatalf("got %d payloads, want 2", len(out))
	}
	if !out[0].Host.RebootRequired || out[0].Host.PackageManager != inventory.ManagerDpkg {
		t.Errorf("dpkg payload host = %+v, want rebootRequired for dpkg", out[0].Host)
	}
	if out[1].Host.RebootRequired {
		t.Errorf("rpm payload host = %+v, want no rebootRequired", out[1].Host)
	}

	if got := buildPendingPayloads(host, snaps, time.Now(), false); got != nil {
		t.Errorf("push disabled: got %d payloads, want none", len(got))
	}
}

func TestBuildPendingPayloadsRebootPackages(t *testing.T) {
	host := inventory.HostMeta{OsID: "ubuntu"}
	snaps := []Snapshot{{Manager: inventory.ManagerDpkg, RebootRequired: true, RebootRequiredPackages: []string{"libc6"}}}

	out := buildPendingPayloads(host, snaps, time.Now(), true)

	if got := out[0].Host.RebootRequiredPackages; len(got) != 1 || got[0] != "libc6" {
		t.Errorf("host packages = %q, want libc6", got)
	}
}
