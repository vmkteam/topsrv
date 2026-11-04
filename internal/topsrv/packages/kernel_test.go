package packages

import (
	"slices"
	"testing"
)

// kernelCase is one package and the flag markKernelPackages must give it.
type kernelCase struct {
	pkg  Package
	want kernelState // kernelNone and kernelPending both mean "no flag"
}

func checkKernelFlags(t *testing.T, manager, kernelRelease string, cases []kernelCase, wantReboot bool) {
	t.Helper()
	pkgs := make([]Package, len(cases))
	for i, c := range cases {
		pkgs[i] = c.pkg
	}
	if got := markKernelPackages(manager, pkgs, kernelRelease); got != wantReboot {
		t.Errorf("rebootRequired = %v, want %v", got, wantReboot)
	}
	for i, c := range cases {
		p := pkgs[i]
		wantActive, wantOld := c.want == kernelActive, c.want == kernelOld
		if p.IsActiveKernel != wantActive || p.IsOldKernel != wantOld {
			t.Errorf("%s %s %s: active=%v old=%v, want active=%v old=%v",
				p.Name, p.Version, p.Release, p.IsActiveKernel, p.IsOldKernel, wantActive, wantOld)
		}
	}
}

func deb(name, version string) Package { return Package{Name: name, Version: version, Arch: "amd64"} }

func rpmPkg(name, version, release string) Package {
	return Package{Name: name, Version: version, Release: release, Arch: "x86_64"}
}

func TestMarkKernelPackagesDpkg(t *testing.T) {
	t.Run("ubuntu with a newer kernel waiting for reboot", func(t *testing.T) {
		checkKernelFlags(t, ManagerDpkg, "6.8.0-90-generic", []kernelCase{
			{deb("linux-image-6.8.0-90-generic", "6.8.0-90.91"), kernelActive},
			{deb("linux-modules-6.8.0-90-generic", "6.8.0-90.91"), kernelActive},
			{deb("linux-headers-6.8.0-90", "6.8.0-90.91"), kernelActive},
			{deb("linux-image-6.8.0-58-generic", "6.8.0-58.60+1"), kernelOld},
			{deb("linux-tools-6.8.0-58", "6.8.0-58.60"), kernelOld},
			{deb("linux-image-6.8.0-147-generic", "6.8.0-147.147"), kernelPending},
			{deb("linux-modules-6.8.0-147-generic", "6.8.0-147.147"), kernelPending},
			// meta and userspace packages carry no release in the name
			{deb("linux-image-virtual", "6.8.0-147.147"), kernelNone},
			{deb("linux-libc-dev", "6.8.0-147.147"), kernelNone},
			{deb("linux-firmware", "20240318.git3b128b60-0ubuntu2.20"), kernelNone},
			{deb("linux-base", "4.5ubuntu9+24.04.1"), kernelNone},
		}, true)
	})

	t.Run("newer headers without an image need no reboot", func(t *testing.T) {
		checkKernelFlags(t, ManagerDpkg, "6.8.0-147-generic", []kernelCase{
			{deb("linux-image-6.8.0-147-generic", "6.8.0-147.147"), kernelActive},
			{deb("linux-headers-6.8.0-149", "6.8.0-149.149"), kernelPending},
			{deb("linux-hwe-6.17-tools-6.17.0-38", "6.17.0-38.38.1~24.04.1"), kernelPending},
		}, false)
	})

	t.Run("hwe kernel booted over the ga one", func(t *testing.T) {
		checkKernelFlags(t, ManagerDpkg, "6.17.0-38-generic", []kernelCase{
			{deb("linux-image-6.17.0-38-generic", "6.17.0-38.38.1~24.04.1"), kernelActive},
			{deb("linux-image-6.8.0-147-generic", "6.8.0-147.147"), kernelOld},
			{deb("linux-image-generic-hwe-24.04", "6.17.0-38.38.1~24.04.1"), kernelNone},
		}, false)
	})

	t.Run("debian", func(t *testing.T) {
		checkKernelFlags(t, ManagerDpkg, "6.1.0-28-cloud-amd64", []kernelCase{
			{deb("linux-image-6.1.0-28-cloud-amd64", "6.1.119-1"), kernelActive},
			{deb("linux-headers-6.1.0-28-common", "6.1.119-1"), kernelActive},
			{deb("linux-image-6.1.0-26-cloud-amd64", "6.1.112-1"), kernelOld},
			{deb("linux-image-cloud-amd64", "6.1.119-1"), kernelNone},
			{deb("linux-kbuild-6.1", "6.1.119-1"), kernelNone},
		}, false)
	})

	t.Run("debian 13 with a newer kernel waiting for reboot", func(t *testing.T) {
		checkKernelFlags(t, ManagerDpkg, "6.12.115+deb13.1-amd64", []kernelCase{
			{deb("linux-image-6.12.115+deb13.1-amd64", "6.12.115-2"), kernelActive},
			{deb("linux-headers-6.12.115+deb13.1-common", "6.12.115-2"), kernelActive},
			{deb("linux-image-6.12.48+deb13-amd64", "6.12.48-1"), kernelOld},
			{deb("linux-image-6.12.120+deb13.1-amd64", "6.12.120-1"), kernelPending},
			{deb("linux-image-amd64", "6.12.120-1"), kernelNone},
		}, true)
	})

	t.Run("bookworm with a backports kernel booted", func(t *testing.T) {
		checkKernelFlags(t, ManagerDpkg, "6.11.10+bpo-amd64", []kernelCase{
			{deb("linux-image-6.11.10+bpo-amd64", "6.11.10-1~bpo12+1"), kernelActive},
			{deb("linux-image-6.1.0-28-amd64", "6.1.119-1"), kernelOld},
		}, false)
	})

	t.Run("unparseable running release flags nothing", func(t *testing.T) {
		// a self-built kernel (make bindeb-pkg) carries no ABI
		checkKernelFlags(t, ManagerDpkg, "6.9.0", []kernelCase{
			{deb("linux-image-6.9.0", "6.9.0-1"), kernelNone},
			{deb("linux-image-6.8.0-58-generic", "6.8.0-58.60"), kernelNone},
		}, false)
	})
}

func TestMarkKernelPackagesRpm(t *testing.T) {
	t.Run("el9 with a newer kernel waiting for reboot", func(t *testing.T) {
		checkKernelFlags(t, ManagerRpm, "5.14.0-503.14.1.el9_5.x86_64", []kernelCase{
			{rpmPkg("kernel", "5.14.0", "503.14.1.el9_5"), kernelActive},
			{rpmPkg("kernel-core", "5.14.0", "503.14.1.el9_5"), kernelActive},
			{rpmPkg("kernel-modules", "5.14.0", "503.14.1.el9_5"), kernelActive},
			{rpmPkg("kernel-core", "5.14.0", "427.13.1.el9_4"), kernelOld},
			{rpmPkg("kernel-modules", "5.14.0", "427.13.1.el9_4"), kernelOld},
			{rpmPkg("kernel-core", "5.14.0", "503.16.1.el9_5"), kernelPending},
			// single-version userspace packages are not per-kernel
			{rpmPkg("kernel-headers", "5.14.0", "503.16.1.el9_5"), kernelNone},
			{rpmPkg("kernel-tools", "5.14.0", "503.16.1.el9_5"), kernelNone},
			{rpmPkg("openssl", "3.2.2", "6.el9_5"), kernelNone},
		}, true)
	})

	t.Run("el8.10 GA kernel left by installonly is old, not pending", func(t *testing.T) {
		checkKernelFlags(t, ManagerRpm, "4.18.0-553.5.1.el8_10.x86_64", []kernelCase{
			{rpmPkg("kernel-core", "4.18.0", "553.5.1.el8_10"), kernelActive},
			{rpmPkg("kernel-core", "4.18.0", "553.el8_10"), kernelOld},
			{rpmPkg("kernel-modules", "4.18.0", "553.el8_10"), kernelOld},
		}, false)
	})

	t.Run("el7 GA kernel is old, z-stream update is pending", func(t *testing.T) {
		checkKernelFlags(t, ManagerRpm, "3.10.0-1160.2.1.el7.x86_64", []kernelCase{
			{rpmPkg("kernel", "3.10.0", "1160.2.1.el7"), kernelActive},
			{rpmPkg("kernel", "3.10.0", "1160.el7"), kernelOld},
			{rpmPkg("kernel", "3.10.0", "1160.6.1.el7"), kernelPending},
		}, true)
	})

	t.Run("only devel is newer: no reboot", func(t *testing.T) {
		checkKernelFlags(t, ManagerRpm, "5.14.0-503.14.1.el9_5.x86_64", []kernelCase{
			{rpmPkg("kernel-core", "5.14.0", "503.14.1.el9_5"), kernelActive},
			{rpmPkg("kernel-devel", "5.14.0", "503.16.1.el9_5"), kernelPending},
		}, false)
	})
}

func TestMarkKernelPackagesApk(t *testing.T) {
	t.Run("booted kernel is current", func(t *testing.T) {
		checkKernelFlags(t, ManagerApk, "6.6.58-0-lts", []kernelCase{
			{Package{Name: "linux-lts", Version: "6.6.58-r0"}, kernelActive},
			{Package{Name: "linux-virt", Version: "6.6.58-r0"}, kernelNone},
			{Package{Name: "linux-firmware-none", Version: "20241017-r0"}, kernelNone},
		}, false)
	})

	t.Run("upgraded in place, not rebooted", func(t *testing.T) {
		checkKernelFlags(t, ManagerApk, "6.6.58-0-lts", []kernelCase{
			{Package{Name: "linux-lts", Version: "6.6.60-r0"}, kernelPending},
		}, true)
	})

	t.Run("pkgrel bump only", func(t *testing.T) {
		checkKernelFlags(t, ManagerApk, "6.6.58-0-lts", []kernelCase{
			{Package{Name: "linux-lts", Version: "6.6.58-r1"}, kernelPending},
		}, true)
	})
}

func TestMarkKernelPackagesNoRelease(t *testing.T) {
	checkKernelFlags(t, ManagerDpkg, "", []kernelCase{
		{deb("linux-image-6.8.0-58-generic", "6.8.0-58.60"), kernelNone},
	}, false)
	checkKernelFlags(t, "freebsdPkg", "14.1-RELEASE", []kernelCase{
		{Package{Name: "linux-image-6.8.0-58-generic", Version: "6.8.0-58.60"}, kernelNone},
	}, false)
}

func TestVersionRuns(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"6.8.0-147", []int{6, 8, 0, 147}},
		{"5.14.0-503.14.1.el9_5", []int{5, 14, 0, 503, 14, 1, -1, 9, 5}},
		{"4.18.0-553.el8_10", []int{4, 18, 0, 553, -1, 8, 10}},
		{"5.15.0-208.159.3.el9uek", []int{5, 15, 0, 208, 159, 3, -1, 9, -1}},
		{"6.12.115+deb13.1", []int{6, 12, 115, -1, 13, 1}},
		{"", nil},
	}
	for _, tc := range cases {
		if got := versionRuns(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("versionRuns(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	// a digit run that overflows int must still sort after any real number
	if compareKernel("6.8.0-99999999999999999999999", "6.8.0-147") != kernelPending {
		t.Error("overflowing digit run must sort last")
	}
}
