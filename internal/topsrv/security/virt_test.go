package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cpuinfoMetal = "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu vme de pse tsc msr pae\n\n"
	cpuinfoGuest = "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu vme de pse tsc hypervisor lahf_lm\n\n"
	cpuinfoArm   = "processor\t: 0\nBogoMIPS\t: 50.00\nFeatures\t: fp asimd evtstrm aes\n\n"
	kvmClock     = "kvm-clock tsc acpi_pm \n"
	tscClock     = "tsc acpi_pm \n"
)

// smbiosBIOS is an SMBIOS BIOS table with the VM bit of Extension Byte 2
// set or not.
func smbiosBIOS(vm bool) string {
	b := make([]byte, 24)
	b[1] = 24
	if vm {
		b[19] = 1 << 4
	}
	return string(b)
}

func dmi(product, vendor string) map[string]string {
	return map[string]string{
		"sys/class/dmi/id/product_name": product + "\n",
		"sys/class/dmi/id/sys_vendor":   vendor + "\n",
	}
}

func cpu(cpuinfo, clocksource string) map[string]string {
	files := map[string]string{"proc/cpuinfo": cpuinfo}
	if clocksource != "" {
		files["sys/devices/system/clocksource/clocksource0/available_clocksource"] = clocksource
	}
	return files
}

func TestDetectVirt(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"bare metal", merge(cpu(cpuinfoMetal, tscClock), dmi("System Product Name", "ASUS")), virtNone},
		{"KVM with the QEMU DMI", merge(cpu(cpuinfoGuest, kvmClock), dmi("Standard PC (Q35 + ICH9, 2009)", "QEMU")), virtKVM},
		{"KVM with the cloud's own DMI", merge(cpu(cpuinfoGuest, kvmClock), dmi("Cloud Server", "Example Cloud")), virtKVM},
		{"QEMU without KVM", merge(cpu(cpuinfoGuest, tscClock), dmi("Standard PC (i440FX + PIIX, 1996)", "QEMU")), virtQEMU},
		{"QEMU with Hyper-V enlightenments: DMI decides", merge(cpu(cpuinfoGuest, "hyperv_clocksource_tsc_page tsc\n"), dmi("Standard PC (Q35 + ICH9, 2009)", "QEMU")), virtQEMU},
		{"VMware", merge(cpu(cpuinfoGuest, tscClock), dmi("VMware Virtual Platform", "VMware, Inc.")), virtVMware},
		{"Hyper-V", merge(cpu(cpuinfoGuest, "hyperv_clocksource_tsc_page acpi_pm\n"), dmi("Virtual Machine", "Microsoft Corporation")), virtMicrosoft},
		{"VirtualBox with the KVM interface", merge(cpu(cpuinfoGuest, kvmClock), dmi("VirtualBox", "innotek GmbH")), virtOracle},
		{
			"EC2 Nitro: KVM underneath, the SMBIOS VM bit set",
			merge(cpu(cpuinfoGuest, kvmClock), dmi("m6i.large", "Amazon EC2"), map[string]string{"sys/firmware/dmi/entries/0-0/raw": smbiosBIOS(true)}),
			virtAmazon,
		},
		{
			"EC2 metal by the SMBIOS VM bit",
			merge(cpu(cpuinfoMetal, tscClock), dmi("i3.metal", "Amazon EC2"), map[string]string{"sys/firmware/dmi/entries/0-0/raw": smbiosBIOS(false)}),
			virtNone,
		},
		{"EC2 metal without root: by the product name", merge(cpu(cpuinfoMetal, tscClock), dmi("m7i.metal-24xl", "Amazon EC2")), virtNone},
		{"EC2 without root and no .metal: a VM", merge(cpu(cpuinfoGuest, kvmClock), dmi("t3.micro", "Amazon EC2")), virtAmazon},
		{"GCE VM", merge(cpu(cpuinfoGuest, kvmClock), dmi("Google Compute Engine", "Google")), virtGoogle},
		{"GCE bare metal: no hypervisor on x86", merge(cpu(cpuinfoMetal, tscClock), dmi("Google Compute Engine", "Google")), virtNone},
		{"GCE on arm64: no flag to tell, a VM", merge(cpu(cpuinfoArm, ""), dmi("Google Compute Engine", "Google")), virtGoogle},
		{"Xen PV domU", merge(cpu(cpuinfoGuest, "xen tsc\n"), map[string]string{"proc/xen/capabilities": "", "sys/hypervisor/type": "xen\n"}), virtXen},
		{"Xen dom0 is the host", merge(cpu(cpuinfoGuest, "xen tsc\n"), map[string]string{"proc/xen/capabilities": "control_d\n"}), virtNone},
		{"Xen dom0 by the features bitmap", merge(cpu(cpuinfoGuest, "xen\n"), map[string]string{"sys/hypervisor/type": "xen\n", "sys/hypervisor/properties/features": "00000801\n"}), virtNone},
		{"Xen domU by the features bitmap", merge(cpu(cpuinfoGuest, "xen\n"), map[string]string{"sys/hypervisor/type": "xen\n", "sys/hypervisor/properties/features": "00000001\n"}), virtXen},
		{"Xen HVM by DMI", merge(cpu(cpuinfoGuest, "xen tsc\n"), dmi("HVM domU", "Xen")), virtXen},
		{"unknown hypervisor", merge(cpu(cpuinfoGuest, tscClock), dmi("vServer", "Example Hosting")), virtOther},
		{"arm64 KVM by the device tree", merge(cpu(cpuinfoArm, ""), map[string]string{"proc/device-tree/hypervisor/compatible": "linux,kvm\x00"}), virtKVM},
		{"arm64 Xen by the device tree", merge(cpu(cpuinfoArm, ""), map[string]string{"proc/device-tree/hypervisor/compatible": "xen,xen-4.17\x00xen,xen\x00"}), virtXen},
		{"arm64 QEMU by its fw-cfg node", merge(cpu(cpuinfoArm, ""), map[string]string{"proc/device-tree/fw-cfg@9020000/": ""}), virtQEMU},
		{"arm64 generic virt board", merge(cpu(cpuinfoArm, ""), map[string]string{"proc/device-tree/compatible": "linux,dummy-virt\x00"}), virtOther},
		{
			"arm64 VM by the SMBIOS VM bit",
			merge(cpu(cpuinfoArm, ""), dmi("vServer", "Example Hosting"), map[string]string{"sys/firmware/dmi/entries/0-0/raw": smbiosBIOS(true)}),
			virtOther,
		},
		{"arm64 bare metal", merge(cpu(cpuinfoArm, ""), dmi("Mt.Collins", "Ampere(R)")), virtNone},
		{"no sources at all", nil, virtNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gaps gapList

			got := detectVirt(fixture(t, tc.files), &gaps)

			assert.Equal(t, tc.want, got)
			assert.Empty(t, gaps)
		})
	}
}

func TestDetectVirtUnreadable(t *testing.T) {
	t.Run("unreadable cpuinfo and no other signal: unknown, not none", func(t *testing.T) {
		sc := fixture(t, merge(cpu(cpuinfoGuest, tscClock), dmi("System Product Name", "ASUS")))
		unreadable(t, sc, "proc/cpuinfo")
		var gaps gapList

		got := detectVirt(sc, &gaps)

		assert.Equal(t, valueUnknown, got)
		assert.Equal(t, gapList{{Path: cpuinfoPath, Reason: ReasonPermissionDenied}}, gaps)
	})

	t.Run("unreadable cpuinfo, DMI names the hypervisor", func(t *testing.T) {
		sc := fixture(t, merge(cpu(cpuinfoGuest, tscClock), dmi("VMware Virtual Platform", "VMware, Inc.")))
		unreadable(t, sc, "proc/cpuinfo")
		var gaps gapList

		assert.Equal(t, virtVMware, detectVirt(sc, &gaps))
	})

	t.Run("an unreadable DMI file is a gap, the other DMI files still count", func(t *testing.T) {
		sc := fixture(t, merge(cpu(cpuinfoGuest, tscClock), map[string]string{
			"sys/class/dmi/id/product_name/": "", // a directory: refused as not a regular file
			"sys/class/dmi/id/sys_vendor":    "VMware, Inc.\n",
		}))
		var gaps gapList

		got := detectVirt(sc, &gaps)

		assert.Equal(t, virtVMware, got)
		assert.Equal(t, gapList{{Path: "/sys/class/dmi/id/product_name", Reason: ReasonNotRegular}}, gaps)
	})
}

func TestIsMetal(t *testing.T) {
	assert.True(t, isMetal("c5.metal"))
	assert.True(t, isMetal("m7i.metal-24xl"))
	assert.False(t, isMetal("m6i.large"))
	assert.False(t, isMetal("c5.metalx"))
	assert.False(t, isMetal(""))
}

func TestCPUFlagsFirstProcessorOnly(t *testing.T) {
	sc := fixture(t, cpu("processor\t: 0\nflags\t\t: fpu\n\nprocessor\t: 1\nflags\t\t: fpu hypervisor\n", ""))

	x86, guest, err := readCPUFlags(sc)

	require.NoError(t, err)
	assert.True(t, x86)
	assert.False(t, guest)
}
