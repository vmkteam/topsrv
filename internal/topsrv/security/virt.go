package security

import (
	"errors"
	"io/fs"
	"slices"
	"strconv"
	"strings"
)

// Values of envData.Virt: the names systemd-detect-virt prints.
const (
	virtNone      = "none"
	virtKVM       = "kvm"
	virtQEMU      = "qemu"
	virtAmazon    = "amazon"
	virtGoogle    = "google"
	virtVMware    = "vmware"
	virtOracle    = "oracle"
	virtXen       = "xen"
	virtBochs     = "bochs"
	virtParallels = "parallels"
	virtBhyve     = "bhyve"
	virtMicrosoft = "microsoft"
	virtApple     = "apple"
	virtOther     = "vm-other"
)

// dmiFiles in systemd's order: product_name before sys_vendor tells KVM from
// QEMU, product_version catches Hyper-V.
var dmiFiles = []string{
	"/sys/class/dmi/id/product_name",
	"/sys/class/dmi/id/sys_vendor",
	"/sys/class/dmi/id/board_vendor",
	"/sys/class/dmi/id/bios_vendor",
	"/sys/class/dmi/id/product_version",
}

// dmiVendors are prefixes of the DMI strings, from dmi_vendor_table of
// systemd's virt.c.
var dmiVendors = []struct{ prefix, virt string }{
	{"KVM", virtKVM},
	{"OpenStack", virtKVM},
	{"KubeVirt", virtKVM},
	{"Alibaba Cloud ECS", virtKVM},
	{"Amazon EC2", virtAmazon},
	{"QEMU", virtQEMU},
	{"VMware", virtVMware},
	{"VMW", virtVMware},
	{"innotek GmbH", virtOracle},
	{"VirtualBox", virtOracle},
	{"Oracle Corporation", virtOracle},
	{"Xen", virtXen},
	{"Bochs", virtBochs},
	{"Parallels", virtParallels},
	{"BHYVE", virtBhyve},
	{"Hyper-V", virtMicrosoft},
	{"Apple Virtualization", virtApple},
	{"Google Compute Engine", virtGoogle},
}

// Paths read for the hypervisor.
const (
	cpuinfoPath     = "/proc/cpuinfo"
	clocksourcePath = "/sys/devices/system/clocksource/clocksource0/available_clocksource"
	smbiosBIOSPath  = "/sys/firmware/dmi/entries/0-0/raw" // root only
)

// cpuinfoHead is enough for the first processor of /proc/cpuinfo.
const cpuinfoHead = 16 << 10

// xenFeatDom0 is XENFEAT_dom0 of xen/include/public/features.h: the
// hardware domain.
const xenFeatDom0 = 11

// detectVirt names the hypervisor the agent runs under, following detect_vm()
// of systemd's virt.c. CPUID is not read, the kernel already shows it: the
// hypervisor flag of /proc/cpuinfo is its bit, and the paravirtual clock the
// guest registered (kvm-clock, hyperv_clocksource_*) stands in for the
// vendor signature. A Xen dom0 is the host and gives "none". The DMI strings
// themselves are never sent.
func detectVirt(sc *scanCtx, gaps *gapList) string {
	x86, guest, cpuErr := readCPUFlags(sc)
	gaps.optional(cpuinfoPath, cpuErr)

	dmi := detectDMI(sc, gaps)
	// Their guests show the KVM or Hyper-V interface too. A GCE machine is told
	// from a bare-metal one by the hypervisor, which only x86 shows.
	if slices.Contains([]string{virtOracle, virtXen, virtAmazon, virtParallels}, dmi) || dmi == virtGoogle && !x86 {
		return dmi
	}
	if xen, dom0 := xenDomain(sc); dom0 {
		return virtNone
	} else if xen {
		return virtXen
	}

	var hyperv, other bool
	if guest {
		switch paravirtClock(sc, gaps) {
		case virtKVM:
			if dmi == virtGoogle {
				return virtGoogle
			}
			return virtKVM
		case virtMicrosoft:
			hyperv = true // QEMU offers Hyper-V enlightenments too: DMI goes first
		default:
			other = true
		}
	}
	switch dmi {
	case virtNone, virtGoogle: // GCE without a hypervisor is bare metal
	case virtOther:
		other = true
	default:
		return dmi
	}
	switch dt := deviceTreeVirt(sc); dt {
	case virtNone:
	case virtOther:
		other = true
	default:
		return dt
	}

	switch {
	case hyperv:
		return virtMicrosoft
	case other:
		return virtOther
	case cpuErr != nil && !errors.Is(cpuErr, fs.ErrNotExist):
		return valueUnknown // no hypervisor flag to rule a VM out
	}
	return virtNone
}

// readCPUFlags reads the first processor of /proc/cpuinfo: x86 lists its CPU
// flags, and "hypervisor" among them is the CPUID bit every x86 hypervisor
// sets. Other architectures have no such flag.
func readCPUFlags(sc *scanCtx) (x86, hypervisor bool, err error) {
	b, err := sc.readHead(cpuinfoPath, cpuinfoHead)
	if err != nil {
		return false, false, err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			break // the end of the first processor
		}
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == "flags" {
			return true, slices.Contains(strings.Fields(v), "hypervisor"), nil
		}
	}
	return false, false, nil
}

// detectDMI matches the DMI strings against dmiVendors. An "Amazon EC2"
// machine may be bare metal: the VM bit of the SMBIOS tells, or, without
// root, a ".metal" product name. A set VM bit with no known vendor is a VM
// of some kind.
func detectDMI(sc *scanCtx, gaps *gapList) string {
	virt, product := dmiVendor(sc, gaps)
	if virt != virtAmazon && virt != virtNone {
		return virt
	}
	vmBit := smbiosVMBit(sc)
	switch {
	case virt == virtAmazon && vmBit != nil:
		if !*vmBit {
			return virtNone
		}
	case virt == virtAmazon && isMetal(product):
		return virtNone
	case virt == virtNone && vmBit != nil && *vmBit:
		return virtOther
	}
	return virt
}

// dmiVendor returns the first match of dmiVendors over dmiFiles, and the
// product name.
func dmiVendor(sc *scanCtx, gaps *gapList) (virt, product string) {
	virt = virtNone
	for i, path := range dmiFiles {
		b, err := sc.read(path, smallFileLimit)
		if err != nil {
			gaps.optional(path, err)
			continue
		}
		s := strings.TrimSpace(string(b))
		if i == 0 {
			product = s
		}
		if virt != virtNone {
			continue
		}
		for _, v := range dmiVendors {
			if strings.HasPrefix(s, v.prefix) {
				virt = v.virt
				break
			}
		}
	}
	return virt, product
}

// smbiosVMBit is bit 4 of BIOS Characteristics Extension Byte 2 of the SMBIOS
// BIOS table (DSP0134 2.1.2.2): the firmware says it is a VM. nil when the
// table is unreadable (it is root only) or too short. An unset bit does not
// prove bare metal: QEMU with SeaBIOS leaves it unset.
func smbiosVMBit(sc *scanCtx) *bool {
	b, err := sc.read(smbiosBIOSPath, smallFileLimit)
	if err != nil || len(b) < 20 || b[1] < 20 {
		return nil
	}
	set := b[19]&(1<<4) != 0
	return &set
}

// isMetal: an EC2 bare-metal product name, "c5.metal" or "m7i.metal-24xl".
func isMetal(product string) bool {
	_, rest, ok := strings.Cut(product, ".metal")
	return ok && (rest == "" || rest[0] == '-')
}

// xenDomain: /proc/xen or /sys/hypervisor/type says Xen; dom0 is the
// hardware domain, by the features bitmap or /proc/xen/capabilities.
func xenDomain(sc *scanCtx) (xen, dom0 bool) {
	hv, _ := sc.read("/sys/hypervisor/type", smallFileLimit)
	if !sc.exists("/proc/xen") && strings.TrimSpace(string(hv)) != "xen" {
		return false, false
	}
	if b, err := sc.read("/sys/hypervisor/properties/features", smallFileLimit); err == nil {
		if f, err := strconv.ParseUint(strings.TrimSpace(string(b)), 16, 64); err == nil {
			return true, f&(1<<xenFeatDom0) != 0
		}
	}
	caps, _ := sc.read("/proc/xen/capabilities", smallFileLimit)
	return true, slices.Contains(strings.Split(strings.TrimSpace(string(caps)), ","), "control_d")
}

// paravirtClock names the hypervisor by the clock source its guest
// registered: kvm-clock for KVM, hyperv_clocksource_* for Hyper-V (and
// QEMU with Hyper-V enlightenments). "" when there is none.
func paravirtClock(sc *scanCtx, gaps *gapList) string {
	b, err := sc.read(clocksourcePath, smallFileLimit)
	gaps.optional(clocksourcePath, err)
	for cs := range strings.FieldsSeq(string(b)) {
		switch {
		case cs == "kvm-clock":
			return virtKVM
		case strings.HasPrefix(cs, "hyperv_clocksource"):
			return virtMicrosoft
		}
	}
	return ""
}

// deviceTreeVirt reads the device tree of arm, powerpc and riscv guests: the
// hypervisor node, a QEMU fw-cfg node, or the generic dummy-virt board.
func deviceTreeVirt(sc *scanCtx) string {
	if b, err := sc.read("/proc/device-tree/hypervisor/compatible", smallFileLimit); err == nil {
		switch hv := firstString(b); {
		case hv == "linux,kvm":
			return virtKVM
		case strings.Contains(hv, "xen"):
			return virtXen
		case strings.Contains(hv, "vmware"):
			return virtVMware
		}
		return virtOther
	}
	entries, err := sc.readDir("/proc/device-tree")
	if err != nil {
		return virtNone
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "fw-cfg") {
			return virtQEMU
		}
	}
	if b, err := sc.read("/proc/device-tree/compatible", smallFileLimit); err == nil && firstString(b) == "linux,dummy-virt" {
		return virtOther
	}
	return virtNone
}

// firstString is the first of the NUL-separated strings of a device tree
// property.
func firstString(b []byte) string {
	s, _, _ := strings.Cut(string(b), "\x00")
	return strings.TrimSpace(s)
}
