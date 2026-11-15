package security

import "strings"

// EFI global variable GUID: SecureBoot and SetupMode live under it.
const efiGlobalVar = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

// secureBoot: EFI false means a legacy BIOS boot, where Secure Boot cannot
// be on. Enabled and SetupMode are null when efivarfs is not readable (a
// container, no root).
type secureBoot struct {
	EFI       bool  `json:"efi"`
	Enabled   *bool `json:"enabled"`
	SetupMode *bool `json:"setupMode"` // keys not enrolled: Secure Boot enforces nothing
}

// kexecState: a loaded kexec image boots without firmware and Secure Boot.
type kexecState struct {
	Loaded      bool `json:"loaded"`
	CrashLoaded bool `json:"crashLoaded"` // a crash kernel (kdump) is normal
}

// smtState: with SMT on, the mitigated_smt_vulnerable class stays open.
type smtState struct {
	Control string `json:"control"` // on|off|forceoff|notsupported|notimplemented
	Active  bool   `json:"active"`
}

// readBootFacts reads the boot and platform facts. Each is optional: a
// kernel or firmware without the feature has no file, which is not a gap.
func readBootFacts(sc *scanCtx, d *kernelData, gaps *gapList) {
	d.SecureBoot = readSecureBoot(sc, gaps)

	if b, err := sc.read("/sys/module/module/parameters/sig_enforce", smallFileLimit); err == nil {
		v := strings.TrimSpace(string(b)) == "Y"
		d.ModuleSigEnforce = &v
	} else {
		gaps.optional("/sys/module/module/parameters/sig_enforce", err)
	}

	loaded, err1 := sc.read("/sys/kernel/kexec_loaded", smallFileLimit)
	crash, err2 := sc.read("/sys/kernel/kexec_crash_loaded", smallFileLimit)
	gaps.optional("/sys/kernel/kexec_loaded", err1)
	if err1 == nil && err2 == nil {
		d.Kexec = &kexecState{Loaded: isOne(loaded), CrashLoaded: isOne(crash)}
	}

	control, err1 := sc.read("/sys/devices/system/cpu/smt/control", smallFileLimit)
	active, err2 := sc.read("/sys/devices/system/cpu/smt/active", smallFileLimit)
	gaps.optional("/sys/devices/system/cpu/smt/control", err1)
	if err1 == nil && err2 == nil {
		d.SMT = &smtState{Control: strings.TrimSpace(string(control)), Active: isOne(active)}
	}

	if b, err := sc.read("/sys/devices/system/cpu/cpu0/microcode/version", smallFileLimit); err == nil {
		d.Microcode = strings.TrimSpace(string(b)) // x86 only
	} else {
		gaps.optional("/sys/devices/system/cpu/cpu0/microcode/version", err)
	}
}

// readSecureBoot reads the SecureBoot and SetupMode EFI variables: 4 bytes
// of attributes, then the value byte. Reading efivarfs calls into the
// firmware, so it happens once a pass.
func readSecureBoot(sc *scanCtx, gaps *gapList) *secureBoot {
	sb := &secureBoot{EFI: sc.exists("/sys/firmware/efi")}
	if !sb.EFI {
		return sb
	}
	sb.Enabled = readEFIFlag(sc, "SecureBoot", gaps)
	sb.SetupMode = readEFIFlag(sc, "SetupMode", gaps)
	return sb
}

func readEFIFlag(sc *scanCtx, name string, gaps *gapList) *bool {
	path := "/sys/firmware/efi/efivars/" + name + "-" + efiGlobalVar
	b, err := sc.read(path, smallFileLimit)
	if err != nil {
		gaps.optional(path, err) // efivarfs not mounted: unknown, not off
		return nil
	}
	if len(b) < 5 {
		gaps.add(path, errParse)
		return nil
	}
	v := b[4] == 1
	return &v
}

func isOne(b []byte) bool { return strings.TrimSpace(string(b)) == "1" }
