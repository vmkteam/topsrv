package security

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sysctlFixture() map[string]string {
	return map[string]string{
		"proc/sys/kernel/kptr_restrict":                "1\n",
		"proc/sys/kernel/yama/ptrace_scope":            "1\n",
		"proc/sys/kernel/randomize_va_space":           "2\n",
		"proc/sys/kernel/core_pattern":                 "|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -- %E\n",
		"proc/sys/fs/protected_symlinks":               "1\n",
		"proc/sys/net/ipv4/ip_forward":                 "1\n",
		"proc/sys/net/bridge/bridge-nf-call-iptables":  "1\n",
		"proc/sys/net/ipv6/conf/all/forwarding":        "0\n",
		"proc/sys/net/ipv4/conf/all/rp_filter":         "0\n",
		"proc/sys/net/ipv4/conf/all/accept_redirects":  "0\n",
		"proc/sys/net/ipv4/conf/default/rp_filter":     "2\n",
		"proc/sys/net/ipv4/conf/eth0/rp_filter":        "1\n",
		"proc/sys/net/ipv4/conf/eth0/accept_redirects": "1\n",
		"proc/sys/net/ipv4/conf/eth0.100/rp_filter":    "2\n",
		"proc/sys/net/ipv4/conf/veth1a2b3c/rp_filter":  "0\n",
		"proc/sys/net/ipv6/conf/all/accept_redirects":  "1\n",
		"proc/sys/net/ipv6/conf/eth0/accept_redirects": "0\n",
	}
}

func TestSysctl(t *testing.T) {
	sc := fixture(t, sysctlFixture())

	sec := collectSysctl(t.Context(), sc)

	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	d := sec.Data.(sysctlData)
	assert.Equal(t, map[string]string{
		"kernel.kptr_restrict":               "1",
		"kernel.yama.ptrace_scope":           "1",
		"kernel.randomize_va_space":          "2",
		"kernel.core_pattern":                "|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -- %E",
		"fs.protected_symlinks":              "1",
		"net.ipv4.ip_forward":                "1",
		"net.bridge.bridge-nf-call-iptables": "1",
		"net.ipv6.conf.all.forwarding":       "0",
	}, d.Values, "keys the kernel does not have are absent, not empty")
	assert.Equal(t, map[string]map[string]string{
		"all":      {"rp_filter": "0", "accept_redirects": "0"},
		"default":  {"rp_filter": "2"},
		"eth0":     {"rp_filter": "1", "accept_redirects": "1"},
		"eth0.100": {"rp_filter": "2"},
	}, d.IPv4Conf, "container-side veth interfaces are skipped")
	assert.Equal(t, map[string]map[string]string{
		"all":  {"accept_redirects": "1"},
		"eth0": {"accept_redirects": "0"},
	}, d.IPv6Conf)
	assert.False(t, d.ConfTruncated)
}

func TestSysctlConfLimit(t *testing.T) {
	files := map[string]string{"proc/sys/net/ipv4/conf/all/rp_filter": "1\n"}
	for i := range maxConfInterfaces + 6 {
		files[fmt.Sprintf("proc/sys/net/ipv4/conf/dummy%02d/rp_filter", i)] = "1\n"
	}
	sc := fixture(t, files)

	sec := collectSysctl(t.Context(), sc)

	d := sec.Data.(sysctlData)
	assert.Len(t, d.IPv4Conf, maxConfInterfaces+1, "all + the first maxConfInterfaces")
	assert.Contains(t, d.IPv4Conf, "all")
	assert.True(t, d.ConfTruncated)
}

func TestSysctlUnreadable(t *testing.T) {
	sc := fixture(t, sysctlFixture())
	unreadable(t, sc, "proc/sys/kernel/kptr_restrict")

	sec := collectSysctl(t.Context(), sc)

	assert.Equal(t, StatusPartial, sec.Status)
	assert.Equal(t, []Gap{{Path: "/proc/sys/kernel/kptr_restrict", Reason: ReasonPermissionDenied}}, sec.Gaps)
}

func TestSysctlNoProcSys(t *testing.T) {
	sec := collectSysctl(t.Context(), fixture(t, nil))

	assert.Equal(t, StatusUnknown, sec.Status, "nothing readable is not an empty pass")
	assert.Equal(t, ReasonNotFound, sec.Reason)
}
