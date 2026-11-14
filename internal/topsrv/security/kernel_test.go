package security

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func kernelFixture() map[string]string {
	return map[string]string{
		"proc/sys/kernel/tainted": "12289\n",
		"proc/modules": "zfs 6639616 6 - Live 0x0000000000000000 (PO)\n" +
			"vboxdrv 696320 0 - Loading 0x0000000000000000 (OE+)\n" +
			"nvidia_uvm 1564672 0 - Live 0x0000000000000000 (POE)\n" +
			"ext4 1036288 1 - Live 0x0000000000000000\n",
		"sys/module/zfs/initstate":                                 "live\n",
		"sys/module/nvidia_uvm/initstate":                          "live\n",
		"sys/module/ext4/initstate":                                "live\n",
		"sys/module/diamorphine/initstate":                         "live\n",
		"sys/module/kernel/parameters/":                            "",
		"sys/devices/system/cpu/vulnerabilities/meltdown":          "Not affected\n",
		"sys/devices/system/cpu/vulnerabilities/spectre_v2":        "Mitigation: Retpolines; IBPB: conditional; STIBP: conditional; RSB filling\n",
		"sys/devices/system/cpu/vulnerabilities/l1tf":              "Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable\n",
		"sys/devices/system/cpu/vulnerabilities/mds":               "Vulnerable: Clear CPU buffers attempted, no microcode; SMT vulnerable\n",
		"sys/devices/system/cpu/vulnerabilities/itlb_multihit":     "KVM: Mitigation: VMX disabled\n",
		"sys/devices/system/cpu/vulnerabilities/spec_store_bypass": "Vulnerable\n",
		"sys/devices/system/cpu/vulnerabilities/gds":               "Unknown: Dependent on hypervisor status\n",
		"sys/kernel/security/lsm":                                  "lockdown,capability,landlock,yama,apparmor,ima,evm",
		"sys/kernel/security/lockdown":                             "none [integrity] confidentiality\n",
		"sys/module/apparmor/parameters/enabled":                   "Y\n",
		"sys/kernel/security/apparmor/profiles": "/usr/bin/man (enforce)\n" +
			"lsb_release (enforce)\n" +
			"/usr/sbin/cupsd (complain)\n" +
			":lxd-c1_<var-snap-lxd-common-lxd>:///usr/sbin/sshd (enforce)\n",
		"sys/kernel/livepatch/lp_6_8_0_90/enabled":    "1\n",
		"sys/kernel/livepatch/lp_6_8_0_90/transition": "0\n",
		"proc/cmdline": "BOOT_IMAGE=/vmlinuz-6.8.0-90-generic root=UUID=0000 ro " +
			"mitigations=auto,nosmt apparmor=1 security=apparmor iscsi_password=SENTINELSECRET quiet " +
			"nosmt nokaslr audit=1 -- nopti single\n",
		"sys/firmware/efi/efivars/SecureBoot-" + efiGlobalVar: "\x06\x00\x00\x00\x01",
		"sys/firmware/efi/efivars/SetupMode-" + efiGlobalVar:  "\x06\x00\x00\x00\x00",
		"sys/module/module/parameters/sig_enforce":            "Y\n",
		"sys/kernel/kexec_loaded":                             "0\n",
		"sys/kernel/kexec_crash_loaded":                       "1\n",
		"sys/devices/system/cpu/smt/control":                  "on\n",
		"sys/devices/system/cpu/smt/active":                   "1\n",
		"sys/devices/system/cpu/cpu0/microcode/version":       "0xf0\n",
	}
}

func TestKernel(t *testing.T) {
	sc := fixture(t, kernelFixture())

	sec := collectKernel(t.Context(), sc)

	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	d := sec.Data.(kernelData)

	assert.Equal(t, &taint{Value: 12289, Flags: []string{"P", "O", "E"}}, d.Taint)
	assert.Equal(t, []module{{"zfs", "PO", ""}, {"vboxdrv", "OE", "Loading"}, {"nvidia_uvm", "POE", ""}, {"ext4", "", ""}}, d.Modules)
	assert.Equal(t, []string{"diamorphine"}, d.HiddenModules, "in /sys/module with initstate but not in /proc/modules")
	assert.Equal(t, map[string]cpuVuln{
		"meltdown":          {"Not affected", vulnNotAffected},
		"spectre_v2":        {"Mitigation: Retpolines; IBPB: conditional; STIBP: conditional; RSB filling", vulnMitigated},
		"l1tf":              {"Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable", vulnMitigatedSMT},
		"mds":               {"Vulnerable: Clear CPU buffers attempted, no microcode; SMT vulnerable", vulnVulnerable},
		"itlb_multihit":     {"KVM: Mitigation: VMX disabled", vulnMitigated},
		"spec_store_bypass": {"Vulnerable", vulnVulnerable},
		"gds":               {"Unknown: Dependent on hypervisor status", vulnUnknown},
	}, d.CPUVulnerabilities)
	assert.Equal(t, lsm{
		Active:   []string{"lockdown", "capability", "landlock", "yama", "apparmor", "ima", "evm"},
		Lockdown: "integrity",
		AppArmor: &appArmor{Enabled: true, Profiles: map[string]int{"enforce": 2, "complain": 1}, ChildNamespaceProfiles: 1},
		SELinux:  "disabled",
	}, d.LSM)
	assert.Equal(t, []livepatch{{Name: "lp_6_8_0_90", Enabled: true}}, d.Livepatch)
	assert.Equal(t, map[string]string{
		"mitigations": "auto,nosmt", "apparmor": "1", "security": "apparmor", "audit": "1",
		"nosmt": "", "nokaslr": "",
	}, d.Cmdline, "whitelisted keys and flags, nothing after --")
	yes, no := true, false
	assert.Equal(t, &secureBoot{EFI: true, Enabled: &yes, SetupMode: &no}, d.SecureBoot)
	assert.Equal(t, &yes, d.ModuleSigEnforce)
	assert.Equal(t, &kexecState{CrashLoaded: true}, d.Kexec)
	assert.Equal(t, &smtState{Control: "on", Active: true}, d.SMT)
	assert.Equal(t, "0xf0", d.Microcode)
	assert.NotContains(t, toJSON(t, sec), "SENTINEL", "cmdline only yields whitelisted tokens")
}

func TestKernelSELinux(t *testing.T) {
	for want, enforce := range map[string]string{"enforcing": "1\n", "permissive": "0\n"} {
		sc := fixture(t, merge(kernelFixture(), map[string]string{"sys/fs/selinux/enforce": enforce}))

		sec := collectKernel(t.Context(), sc)

		d := sec.Data.(kernelData)
		assert.Equal(t, want, d.LSM.SELinux)
	}
}

func TestKernelGaps(t *testing.T) {
	t.Run("missing required sources are gaps, optional ones are not", func(t *testing.T) {
		sc := fixture(t, map[string]string{"proc/sys/kernel/tainted": "0\n", "proc/modules": ""})

		sec := collectKernel(t.Context(), sc)

		assert.Equal(t, StatusPartial, sec.Status)
		assert.ElementsMatch(t, []Gap{
			{Path: "/sys/module", Reason: ReasonNotFound},
			{Path: "/sys/devices/system/cpu/vulnerabilities", Reason: ReasonNotFound},
			{Path: "/sys/kernel/security/lsm", Reason: ReasonNotFound},
			{Path: "/proc/cmdline", Reason: ReasonNotFound},
		}, sec.Gaps)
		d := sec.Data.(kernelData)
		assert.Nil(t, d.LSM.AppArmor, "no apparmor module: not a gap")
		assert.Empty(t, d.Livepatch)
	})

	t.Run("unreadable file is permission_denied", func(t *testing.T) {
		sc := fixture(t, kernelFixture())
		unreadable(t, sc, "sys/kernel/security/apparmor/profiles")

		sec := collectKernel(t.Context(), sc)

		assert.Equal(t, StatusPartial, sec.Status)
		assert.Equal(t, []Gap{{Path: "/sys/kernel/security/apparmor/profiles", Reason: ReasonPermissionDenied}}, sec.Gaps)
		d := sec.Data.(kernelData)
		assert.Nil(t, d.LSM.AppArmor.Profiles, "unreadable, not zero profiles")
	})

	t.Run("in a container: AppArmor on, no securityfs", func(t *testing.T) {
		files := kernelFixture()
		for _, p := range []string{"sys/kernel/security/lsm", "sys/kernel/security/lockdown", "sys/kernel/security/apparmor/profiles"} {
			delete(files, p)
		}
		sc := fixture(t, files)

		sec := collectKernel(t.Context(), sc)

		d := sec.Data.(kernelData)
		assert.Nil(t, d.LSM.Active, "unknown, not empty")
		assert.Contains(t, toJSON(t, sec), `"active":null`)
		assert.True(t, d.LSM.AppArmor.Enabled)
		assert.Nil(t, d.LSM.AppArmor.Profiles)
		assert.Contains(t, toJSON(t, sec), `"profiles":null`)
		assert.Equal(t, valueUnknown, d.LSM.SELinux, "no selinuxfs proves nothing without the LSM list")
		assert.ElementsMatch(t, []Gap{
			{Path: "/sys/kernel/security/lsm", Reason: ReasonNotFound},
			{Path: "/sys/kernel/security/apparmor/profiles", Reason: ReasonNotFound},
		}, sec.Gaps)
	})

	t.Run("SELinux in the LSM list but no selinuxfs", func(t *testing.T) {
		sc := fixture(t, merge(kernelFixture(), map[string]string{"sys/kernel/security/lsm": "capability,selinux"}))

		sec := collectKernel(t.Context(), sc)

		d := sec.Data.(kernelData)
		assert.Equal(t, valueUnknown, d.LSM.SELinux)
		assert.Contains(t, sec.Gaps, Gap{Path: "/sys/fs/selinux/enforce", Reason: ReasonNotFound})
	})

	t.Run("unreadable /proc/modules skips the hidden module check", func(t *testing.T) {
		sc := fixture(t, kernelFixture())
		unreadable(t, sc, "proc/modules")

		sec := collectKernel(t.Context(), sc)

		d := sec.Data.(kernelData)
		assert.Nil(t, d.HiddenModules, "not checked, rather than every module hidden")
		assert.Contains(t, toJSON(t, sec), `"hiddenModules":null`)
		assert.Equal(t, []Gap{{Path: "/proc/modules", Reason: ReasonPermissionDenied}}, sec.Gaps)
	})

	t.Run("garbage in tainted is a parse error", func(t *testing.T) {
		sc := fixture(t, merge(kernelFixture(), map[string]string{"proc/sys/kernel/tainted": "SENTINELLINE\n"}))

		sec := collectKernel(t.Context(), sc)

		assert.Equal(t, []Gap{{Path: "/proc/sys/kernel/tainted", Reason: ReasonParseError}}, sec.Gaps)
		assert.NotContains(t, toJSON(t, sec), "SENTINEL")
	})
}

func TestTaintFlags(t *testing.T) {
	flags := func(v uint64) []string { return bitNames(v, taintLetters, "bit") }
	assert.Empty(t, flags(0))
	assert.Equal(t, []string{"P", "F", "S", "R", "M", "B", "U", "D", "A", "W", "C", "I", "O", "E", "L", "K", "X", "T", "N", "J"}, flags(1<<20-1))
	assert.Equal(t, []string{"W", "bit20"}, flags(1<<9|1<<20))
}

func TestVulnClass(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{"meltdown", "Not affected", vulnNotAffected},
		{"itlb_multihit", "Processor vulnerable", vulnVulnerable},
		{"itlb_multihit", "KVM: Vulnerable", vulnVulnerable},
		{"itlb_multihit", "KVM: Mitigation: Split huge pages", vulnMitigated},
		{"spectre_v2", "Vulnerable: eIBRS with unprivileged eBPF", vulnVulnerable},
		{"spectre_v1", "Mitigation: __user pointer sanitization", vulnMitigated},
		{"spectre_v2", "Mitigation: CSV2, but not BHB", vulnVulnerable}, // arm64: Spectre-BHB is open
		{"mds", "Mitigation: Clear CPU buffers; SMT vulnerable", vulnMitigatedSMT},
		{"mds", "Vulnerable: Clear CPU buffers attempted, no microcode; SMT vulnerable", vulnVulnerable},
		{"l1tf", "Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable", vulnMitigatedSMT},
		{"l1tf", "Mitigation: PTE Inversion; VMX: vulnerable", vulnVulnerable},
		{"spectre_v2", "Mitigation: Retpolines; IBPB: conditional; STIBP: disabled; RSB filling - vulnerable module loaded", vulnVulnerable},
		{"spectre_v2", "Mitigation: Enhanced / Automatic IBRS; IBPB: conditional; RSB filling; BHI: Vulnerable", vulnVulnerable},
		{"spectre_v2", "Mitigation: Enhanced / Automatic IBRS; IBPB: conditional; BHI: BHI_DIS_S", vulnMitigated},
		{"spec_rstack_overflow", "Mitigation: safe RET, no microcode", vulnVulnerable}, // LTS wording of the current "Vulnerable: Safe RET, no microcode"
		{"spec_rstack_overflow", "Mitigation: microcode", vulnVulnerable},
		{"spec_rstack_overflow", "Mitigation: Safe RET", vulnMitigated},
		{"gather_data_sampling", "Mitigation: AVX disabled, no microcode", vulnMitigated}, // a real mitigation
		{"gather_data_sampling", "Unknown: Dependent on hypervisor status", vulnUnknown},
		{"mds", "Unknown (XEN PV detected, hypervisor mitigation required)", vulnUnknown},
		{"x", "", vulnUnknown},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, vulnClass(tc.name, tc.raw), "%s: %s", tc.name, tc.raw)
	}
}

func TestTimeSyncReader(t *testing.T) {
	read := timeSyncReader()
	if runtime.GOOS != "linux" {
		assert.Nil(t, read)
		return
	}
	ts, err := read()
	require.NoError(t, err, "read-only adjtimex needs no privileges")
	assert.GreaterOrEqual(t, ts.MaxErrorUs, int64(0))
}

func TestKernelBootFactsAbsent(t *testing.T) {
	sc := fixture(t, map[string]string{"proc/sys/kernel/tainted": "0\n", "proc/modules": "", "proc/cmdline": "ro\n"})

	sec := collectKernel(t.Context(), sc)

	d := sec.Data.(kernelData)
	assert.Equal(t, &secureBoot{}, d.SecureBoot, "legacy BIOS: no EFI, Secure Boot impossible")
	assert.Nil(t, d.ModuleSigEnforce)
	assert.Nil(t, d.Kexec)
	assert.Nil(t, d.SMT)
	assert.NotContains(t, sec.Gaps, Gap{Path: "/sys/kernel/kexec_loaded", Reason: ReasonNotFound}, "features the kernel lacks are not gaps")

	t.Run("EFI without readable efivars: unknown, not off", func(t *testing.T) {
		sc := fixture(t, map[string]string{"sys/firmware/efi/": ""})

		sb := readSecureBoot(sc, &gapList{})

		assert.True(t, sb.EFI)
		assert.Nil(t, sb.Enabled)
		assert.Contains(t, toJSON(t, sb), `"enabled":null`)
	})
}
