package security

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"
)

// maxConfInterfaces caps per-interface net.*.conf entries: a k8s node has
// hundreds of pod interfaces.
const maxConfInterfaces = 64

// sysctlKeys are reported raw; norms depend on the host role and are the
// backend's job.
var sysctlKeys = []string{
	// KSPP recommended settings
	"kernel.kptr_restrict", "kernel.dmesg_restrict", "kernel.unprivileged_bpf_disabled",
	"kernel.yama.ptrace_scope", "kernel.kexec_load_disabled", "kernel.randomize_va_space",
	"kernel.modules_disabled", "kernel.perf_event_paranoid", "kernel.warn_limit", "kernel.oops_limit",
	"net.core.bpf_jit_harden", "dev.tty.ldisc_autoload", "dev.tty.legacy_tiocsti",
	"fs.protected_symlinks", "fs.protected_hardlinks", "fs.protected_fifos", "fs.protected_regular",
	"fs.suid_dumpable", "vm.unprivileged_userfaultfd", "vm.mmap_min_addr",
	"vm.mmap_rnd_bits", "vm.mmap_rnd_compat_bits",
	// other hardening (kernel-hardening-checker, CIS)
	"kernel.io_uring_disabled", "vm.memfd_noexec", "kernel.sysrq",
	// user namespaces
	"user.max_user_namespaces", "kernel.unprivileged_userns_clone",
	"kernel.apparmor_restrict_unprivileged_userns", "kernel.apparmor_restrict_unprivileged_unconfined",
	// paths the kernel executes: a pipe or helper at an unusual path is
	// suspicious, and kernel.hotplug is a container escape
	"kernel.core_pattern", "kernel.modprobe", "kernel.hotplug",
	// network (CIS); per-interface keys are in ipv4ConfKeys and ipv6ConfKeys
	"net.ipv4.ip_forward", "net.ipv4.tcp_syncookies", "net.ipv6.conf.all.forwarding",
	"net.ipv4.icmp_echo_ignore_broadcasts", "net.ipv4.icmp_ignore_bogus_error_responses",
	"net.ipv4.ip_unprivileged_port_start", // 0: anyone binds :22 and :443
	"net.bridge.bridge-nf-call-iptables", "net.bridge.bridge-nf-call-ip6tables",
}

// Per-interface keys, "all" alone is not enough: the effective rp_filter is
// max(all, iface); IPv4 accept_redirects is all AND iface on a forwarding
// interface, OR otherwise; IPv6 accept_redirects and accept_ra are read from
// the interface only and switched off by its forwarding. Hence forwarding
// per interface.
var (
	ipv4ConfKeys = []string{
		"rp_filter", "accept_redirects", "secure_redirects", "send_redirects", "accept_source_route",
		"log_martians", "forwarding", "route_localnet",
	}
	ipv6ConfKeys = []string{"accept_redirects", "accept_ra", "accept_source_route", "forwarding", "disable_ipv6"}
)

// containerIfacePrefixes: the host ends of container and pod interfaces,
// never reported.
var containerIfacePrefixes = []string{"veth", "cali", "lxc"}

// guestIfacePrefixes: per-VM and per-container interfaces (Proxmox firewall
// bridges, tap and vnet devices). Reported, but after the rest, so the cap
// never pushes out the uplinks and bridges of the host.
var guestIfacePrefixes = []string{"fwbr", "fwln", "fwpr", "tap", "vnet", "vif"}

// sysctlData holds raw values. A key the kernel does not have is absent; one
// it has but the agent could not read is null, with a gap that says why.
type sysctlData struct {
	Values        map[string]*string            `json:"values"`
	IPv4Conf      map[string]map[string]*string `json:"ipv4Conf"`
	IPv6Conf      map[string]map[string]*string `json:"ipv6Conf"`
	ConfTruncated bool                          `json:"confTruncated,omitempty"`
}

func collectSysctl(_ context.Context, sc *scanCtx) Section {
	if _, err := sc.stat("/proc/sys"); err != nil {
		return unknown(reasonOf(err))
	}
	var gaps gapList
	d := sysctlData{Values: map[string]*string{}}
	for _, key := range sysctlKeys {
		if v, ok := readSysctl(sc, "/proc/sys/"+strings.ReplaceAll(key, ".", "/"), &gaps); ok {
			d.Values[key] = v
		}
	}
	var trunc4, trunc6 bool
	d.IPv4Conf, trunc4 = readConf(sc, "/proc/sys/net/ipv4/conf/", ipv4ConfKeys, &gaps)
	d.IPv6Conf, trunc6 = readConf(sc, "/proc/sys/net/ipv6/conf/", ipv6ConfKeys, &gaps)
	d.ConfTruncated = trunc4 || trunc6
	return collected(gaps, d)
}

// readSysctl reads one value. present is false for a key the kernel does
// not have; a key it has that could not be read is present with a nil value
// and a gap.
func readSysctl(sc *scanCtx, path string, gaps *gapList) (v *string, present bool) {
	b, err := sc.read(path, smallFileLimit)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false
	case err != nil:
		gaps.add(path, err)
		return nil, true
	}
	s := strings.TrimRight(string(b), "\n")
	return &s, true
}

// readConf reads keys for "all", "default" and up to maxConfInterfaces
// interfaces: physical ones first, guest ones last, by name within a group.
func readConf(sc *scanCtx, dir string, keys []string, gaps *gapList) (map[string]map[string]*string, bool) {
	entries, err := sc.readDir(dir)
	if err != nil {
		gaps.optional(dir, err) // no IPv6
		return nil, false
	}
	var ifaces []string
	for _, e := range entries {
		name := e.Name()
		if name != "all" && name != "default" && !hasAnyPrefix(name, containerIfacePrefixes) {
			ifaces = append(ifaces, name)
		}
	}
	rank := func(name string) int {
		switch {
		case sc.exists("/sys/class/net/" + name + "/device"):
			return 0
		case hasAnyPrefix(name, guestIfacePrefixes):
			return 2
		}
		return 1
	}
	slices.SortStableFunc(ifaces, func(a, b string) int { return rank(a) - rank(b) }) // ReadDir sorted by name
	truncated := len(ifaces) > maxConfInterfaces
	names := slices.Concat([]string{"all", "default"}, ifaces[:min(len(ifaces), maxConfInterfaces)])

	out := map[string]map[string]*string{}
	for _, name := range names {
		vals := map[string]*string{}
		for _, k := range keys {
			if v, ok := readSysctl(sc, dir+name+"/"+k, gaps); ok {
				vals[k] = v
			}
		}
		if len(vals) > 0 {
			out[name] = vals
		}
	}
	return out, truncated
}

func hasAnyPrefix(s string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(s, p) })
}
