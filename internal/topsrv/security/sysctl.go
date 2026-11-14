package security

import (
	"context"
	"slices"
	"strings"
)

// maxConfInterfaces caps per-interface net.*.conf entries: a k8s node has
// hundreds of pod interfaces.
const maxConfInterfaces = 64

// sysctlKeys are reported raw; norms depend on the host role and are the
// backend's job.
var sysctlKeys = []string{
	// KSPP
	"kernel.kptr_restrict", "kernel.dmesg_restrict", "kernel.unprivileged_bpf_disabled",
	"kernel.yama.ptrace_scope", "kernel.kexec_load_disabled", "kernel.randomize_va_space",
	"kernel.modules_disabled", "kernel.perf_event_paranoid", "kernel.io_uring_disabled",
	"net.core.bpf_jit_harden", "dev.tty.ldisc_autoload",
	"fs.protected_symlinks", "fs.protected_hardlinks", "fs.protected_fifos", "fs.protected_regular",
	"fs.suid_dumpable", "vm.unprivileged_userfaultfd", "vm.memfd_noexec",
	// user namespaces
	"user.max_user_namespaces", "kernel.unprivileged_userns_clone", "kernel.apparmor_restrict_unprivileged_userns",
	// core dumps: a pipe to an unusual path is suspicious
	"kernel.core_pattern",
	// network
	"net.ipv4.ip_forward", "net.ipv4.tcp_syncookies", "net.ipv6.conf.all.forwarding",
	"net.bridge.bridge-nf-call-iptables",
}

// Per-interface keys: the effective rp_filter is max(all, iface), and
// accept_redirects has its own rule, so "all" alone is not enough.
var (
	ipv4ConfKeys = []string{"rp_filter", "accept_redirects", "send_redirects", "accept_source_route", "log_martians"}
	ipv6ConfKeys = []string{"accept_redirects", "accept_source_route"}
)

// containerIfacePrefixes: the host ends of container and pod interfaces.
var containerIfacePrefixes = []string{"veth", "cali", "lxc"}

type sysctlData struct {
	Values        map[string]string            `json:"values"`
	IPv4Conf      map[string]map[string]string `json:"ipv4Conf"`
	IPv6Conf      map[string]map[string]string `json:"ipv6Conf"`
	ConfTruncated bool                         `json:"confTruncated,omitempty"`
}

func collectSysctl(_ context.Context, sc *scanCtx) Section {
	if _, err := sc.stat("/proc/sys"); err != nil {
		return unknown(reasonOf(err))
	}
	var gaps gapList
	d := sysctlData{Values: map[string]string{}}
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

// readSysctl reads one value; a key the kernel does not have is skipped.
func readSysctl(sc *scanCtx, path string, gaps *gapList) (string, bool) {
	b, err := sc.read(path, smallFileLimit)
	if err != nil {
		gaps.optional(path, err)
		return "", false
	}
	return strings.TrimRight(string(b), "\n"), true
}

// readConf reads keys for "all", "default" and up to maxConfInterfaces
// interfaces, skipping the host ends of container interfaces.
func readConf(sc *scanCtx, dir string, keys []string, gaps *gapList) (map[string]map[string]string, bool) {
	entries, err := sc.readDir(dir)
	if err != nil {
		gaps.optional(dir, err) // no IPv6
		return nil, false
	}
	out := map[string]map[string]string{}
	ifaces, truncated := 0, false
	for _, e := range entries {
		name := e.Name()
		if slices.ContainsFunc(containerIfacePrefixes, func(p string) bool { return strings.HasPrefix(name, p) }) {
			continue
		}
		if name != "all" && name != "default" {
			if ifaces == maxConfInterfaces {
				truncated = true
				continue
			}
			ifaces++
		}
		vals := map[string]string{}
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
