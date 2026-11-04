package packages

import (
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// kernelState says how an installed kernel package relates to the running
// kernel (`uname -r`).
type kernelState int

const (
	kernelNone    kernelState = iota // not a per-release kernel package: meta, firmware, userspace
	kernelActive                     // belongs to the running kernel
	kernelOld                        // an older release than the running one
	kernelPending                    // a newer release, boots on the next reboot
)

// markKernelPackages tags per-release kernel packages relative to the running
// kernel and reports whether a newer kernel image is installed but not booted.
//
// Vulners' own agent drops kernel packages that don't match `uname -r` for the
// same reason: CVEs in unloaded kernels are not live. The receiver skips
// IsOldKernel packages in the audit and in CVE counts. Newer kernels stay
// unflagged — they are what runs after the reboot, so they are worth
// auditing. Meta packages (linux-image-virtual, linux-generic) carry no
// release and stay unflagged too.
func markKernelPackages(manager string, pkgs []Package, kernelRelease string) (rebootRequired bool) {
	if kernelRelease == "" {
		return false
	}
	for i := range pkgs {
		p := &pkgs[i]
		state, image := classifyKernel(manager, kernelRelease, p)
		switch state {
		case kernelActive:
			p.IsActiveKernel = true
		case kernelOld:
			p.IsOldKernel = true
		case kernelPending:
			rebootRequired = rebootRequired || image
		case kernelNone:
		}
	}
	return rebootRequired
}

// classifyKernel places one package against the running kernel release. A
// running release that can't be parsed or an unknown manager flags nothing.
// The bool reports whether the package is a bootable kernel image: only a
// newer image (not newer headers alone) means a reboot is pending.
func classifyKernel(manager, kernelRelease string, p *Package) (kernelState, bool) {
	switch manager {
	case ManagerDpkg:
		if !strings.HasPrefix(p.Name, "linux-") {
			return kernelNone, false
		}
		abi, running := dpkgKernelABI(p.Name), dpkgKernelABI(kernelRelease)
		if abi == "" || running == "" {
			return kernelNone, false
		}
		return compareKernel(abi, running), strings.HasPrefix(p.Name, "linux-image-")
	case ManagerRpm:
		image, ok := rpmKernelPackages[p.Name]
		if !ok {
			return kernelNone, false
		}
		release := p.Version + "-" + p.Release
		running := strings.TrimSuffix(kernelRelease, "."+p.Arch)
		return compareKernel(release, running), image
	case ManagerApk:
		// uname -r on Alpine is "<version>-<pkgrel>-<flavor>", e.g. 6.6.58-0-lts;
		// the kernel package is linux-<flavor> with version "<version>-r<pkgrel>".
		// The "r" is dropped so it doesn't count as a letter run.
		i := strings.LastIndexByte(kernelRelease, '-')
		if i < 0 || p.Name != "linux-"+kernelRelease[i+1:] {
			return kernelNone, false
		}
		return compareKernel(strings.Replace(p.Version, "-r", "-", 1), kernelRelease[:i]), true
	}
	return kernelNone, false
}

// dpkgABIRe matches the ABI part of an Ubuntu/Debian kernel release, in a
// package name and in uname alike: "<upstream>-<abi>" as 6.8.0-147 in
// linux-image-6.8.0-147-generic or 6.1.0-28 in linux-headers-6.1.0-28-common,
// and "<upstream>+<tag>" as 6.12.115+deb13.1 in linux-image-6.12.115+deb13.1-amd64
// (Debian 13), 6.11.10+bpo (backports), 6.6.51+rpt (Raspberry Pi OS).
var dpkgABIRe = regexp.MustCompile(`(?:^|-)(\d+\.\d+(?:\.\d+)?(?:-\d+|\+[0-9a-z.]+))(?:-|$)`)

// dpkgKernelABI returns the kernel ABI embedded in a package name or uname
// release, or "" when there is none (meta packages, linux-libc-dev).
func dpkgKernelABI(s string) string {
	m := dpkgABIRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// rpmKernelPackages are the install-only kernel packages: one copy per
// installed kernel, side by side. The value says whether the package ships a
// bootable vmlinuz. kernel-headers and kernel-tools are single-version
// userspace packages and deliberately absent.
var rpmKernelPackages = map[string]bool{
	"kernel": true, "kernel-core": true, "kernel-uek": true, "kernel-uek-core": true,
	"kernel-modules": false, "kernel-modules-core": false, "kernel-modules-extra": false,
	"kernel-uek-modules": false, "kernel-uek-modules-extra": false,
	"kernel-devel": false, "kernel-uek-devel": false,
}

// compareKernel places a package release against the running one.
func compareKernel(release, running string) kernelState {
	switch slices.Compare(versionRuns(release), versionRuns(running)) {
	case 0:
		return kernelActive
	case -1:
		return kernelOld
	default:
		return kernelPending
	}
}

// versionRunRe matches the digit and letter runs of a version; anything else
// only separates them.
var versionRunRe = regexp.MustCompile(`\d+|[A-Za-z]+`)

// versionRuns turns a version into comparable runs: "6.8.0-147" →
// [6 8 0 147], "4.18.0-553.5.1.el8_10" → [4 18 0 553 5 1 -1 8 10]. A letter
// run counts as -1, below any number, as in rpm's rpmvercmp: otherwise the
// EL 8.10 GA kernel 553.el8_10 → [.. 553 8 10] would sort after its update
// 553.5.1.el8_10. Releases of one kernel line share the letter runs (the dist
// tag), so their text doesn't matter; the full dpkg/rpm collation rules are
// not needed here.
func versionRuns(s string) []int {
	var out []int
	for _, run := range versionRunRe.FindAllString(s, -1) {
		if run[0] < '0' || run[0] > '9' {
			out = append(out, -1) // a letter run
			continue
		}
		n, err := strconv.Atoi(run)
		if err != nil {
			n = math.MaxInt // a digit run too long for int sorts last
		}
		out = append(out, n)
	}
	return out
}
