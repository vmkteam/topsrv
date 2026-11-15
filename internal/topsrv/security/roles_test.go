package security

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRouteV4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth1\t00000000\t016433C6\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"*\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n" + // blackhole default
		"eth0\t00000000\t020200C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n" + // a second default via eth0
		"eth2\t00000000\t00000000\t0201\t0\t0\t0\t00000000\t0\t0\t0\n"
	testRouteV6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000002 00000400 00000001 00000000 00000003     eth0\n" + // ECMP
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n" +
		"20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000002 00000000 00000001     eth0\n"
)

func rolesFixture() map[string]string {
	return map[string]string{
		"proc/self":                            "-> 100",
		"proc/1/exe":                           "-> /usr/lib/systemd/systemd",
		"proc/1/ns/net":                        "-> net:[4026531840]",
		"proc/107/exe":                         "-> /usr/bin/kubelet", // kind: kubelet in a container's netns
		"proc/107/ns/net":                      "-> net:[4026532900]",
		"proc/108/exe":                         "-> /usr/sbin/keepalived",
		"proc/108/ns/net":                      "-> net:[4026531840]",
		"sys/class/net/gre1/uevent":            "INTERFACE=gre1\n",
		"sys/class/net/gre1/type":              "778\n",
		"sys/class/net/vmbr0/uevent":           "DEVTYPE=bridge\nINTERFACE=vmbr0\n",
		"dev/kvm":                              "",
		"sys/module/wireguard/":                "",
		"proc/2/cmdline":                       "",
		"proc/100/exe":                         "-> /usr/bin/dockerd",
		"proc/101/exe":                         "-> /usr/bin/containerd (deleted)",
		"proc/102/cmdline":                     "/usr/local/bin/k3s\x00server\x00--token\x00SENTINELSECRET\x00",
		"proc/103/exe":                         "-> /usr/bin/qemu-system-x86_64",
		"proc/104/exe":                         "-> /usr/sbin/sshd",
		"proc/105/exe":                         "-> /usr/bin/dockerd",
		"proc/106/cmdline":                     "tailscaled\x00--state=/var/lib/tailscale/tailscaled.state\x00",
		"proc/net/route":                       testRouteV4,
		"proc/net/ipv6_route":                  testRouteV6,
		"sys/class/net/lo/uevent":              "INTERFACE=lo\nIFINDEX=1\n",
		"sys/class/net/eth0/uevent":            "INTERFACE=eth0\nIFINDEX=2\n",
		"sys/class/net/docker0/uevent":         "DEVTYPE=bridge\nINTERFACE=docker0\n",
		"sys/class/net/br-0a1b2c3d4e5f/uevent": "DEVTYPE=bridge\nINTERFACE=br-0a1b2c3d4e5f\n",
		"sys/class/net/wg0/uevent":             "DEVTYPE=wireguard\nINTERFACE=wg0\n",
		"sys/class/net/tailscale0/uevent":      "INTERFACE=tailscale0\n",
		"sys/class/net/tailscale0/tun_flags":   "0x1001\n",
		"sys/class/net/veth1a2b3c/uevent":      "INTERFACE=veth1a2b3c\n",
	}
}

func TestRoleSignals(t *testing.T) {
	sc := fixture(t, rolesFixture())

	sec := collectRoleSignals(t.Context(), sc)

	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	d := sec.Data.(roleData)
	assert.Equal(t, []string{"containerd", "dockerd", "k3s", "keepalived", "qemu-system-x86_64", "tailscaled"}, d.Processes,
		"by exe, argv[0] when exe is unreadable; deduplicated and sorted; kubelet in another netns is not the host's")
	assert.Equal(t, ifaceSignals{
		Total:     8,
		DevTypes:  map[string]int{"bridge": 3, "wireguard": 1},
		LinkTypes: map[string]int{"gre": 1},
		Tun:       1,
		Names:     []string{"br-0a1b2c3d4e5f", "docker0", "vmbr0"},
	}, d.Interfaces)
	assert.Equal(t, defaultRoutes{V4: 2, V6: 1, Interfaces: []string{"eth0", "eth1"}}, d.DefaultRoutes,
		"interfaces, not routes: ECMP, rejecting and blackhole routes and lo do not add uplinks")
	assert.Equal(t, []string{"/dev/kvm", "/sys/module/wireguard"}, d.Markers)
	assert.NotContains(t, toJSON(t, sec), "SENTINEL")
}

func TestRoleSignalsNameLimit(t *testing.T) {
	files := map[string]string{"proc/net/route": "", "proc/net/ipv6_route": ""}
	for i := range maxRoleIfaceNames + 3 {
		files[fmt.Sprintf("sys/class/net/br-%012d/uevent", i)] = "DEVTYPE=bridge\n"
	}
	sc := fixture(t, files)

	sec := collectRoleSignals(t.Context(), sc)

	d := sec.Data.(roleData)
	assert.Len(t, d.Interfaces.Names, maxRoleIfaceNames)
	assert.True(t, d.Interfaces.NamesTruncated)
	assert.Equal(t, maxRoleIfaceNames+3, d.Interfaces.DevTypes["bridge"], "counts are not capped")
}

func TestRoleSignalsGaps(t *testing.T) {
	sec := collectRoleSignals(t.Context(), fixture(t, nil))

	assert.Equal(t, StatusUnknown, sec.Status)
	assert.Equal(t, ReasonNotFound, sec.Reason)
}

func TestRoleSignalsHidepid(t *testing.T) {
	sc := fixture(t, rolesFixture())
	unreadable(t, sc, "proc/106/cmdline") // hidepid: another user's process

	sec := collectRoleSignals(t.Context(), sc)

	assert.Equal(t, StatusPartial, sec.Status, "an incomplete process list is not ok")
	assert.Equal(t, []Gap{{Path: "/proc", Reason: ReasonPermissionDenied}}, sec.Gaps)
	d := sec.Data.(roleData)
	assert.NotContains(t, d.Processes, "tailscaled")
	assert.Contains(t, d.Processes, "dockerd", "what was readable is kept")
}

func TestRoleSignalsHidepid2(t *testing.T) {
	files := rolesFixture()
	delete(files, "proc/1/exe")
	delete(files, "proc/1/ns/net")
	sc := fixture(t, files) // hidepid=2: other users' processes, PID 1 included, are not listed

	sec := collectRoleSignals(t.Context(), sc)

	assert.Equal(t, StatusPartial, sec.Status)
	assert.Equal(t, []Gap{{Path: "/proc", Reason: ReasonPermissionDenied}}, sec.Gaps)
}
