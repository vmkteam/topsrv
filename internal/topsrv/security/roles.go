package security

import (
	"context"
	"slices"
	"strconv"
	"strings"
)

const (
	maxRoleIfaceNames = 32      // a docker host has a br-* per network
	maxRouteIfaces    = 16      // interfaces listed with a default route
	routesLimit       = 4 << 20 // /proc/net/route of a router with a full table
	argv0Limit        = 4096
)

// Route flags, linux/route.h.
const (
	rtfUp     = 0x0001
	rtfReject = 0x0200
)

// roleProcesses are matched by exe, or argv[0]: comm is cut to 15 chars.
var roleProcesses = []string{
	// containers
	"dockerd", "containerd", "crio", "conmon",
	// kubernetes
	"kubelet", "kubelite", "k3s", "rke2", "k0s", "kube-proxy", "kube-apiserver", "etcd",
	// orchestration
	"nomad",
	// cluster networking
	"cilium-agent", "calico-node", "flanneld", "kube-router", "antrea-agent", "ovs-vswitchd",
	// virtualization
	"libvirtd", "virtqemud", "lxd", "incus", "incusd", "firecracker", "cloud-hypervisor", "pvedaemon",
	// VPN
	"tailscaled", "openvpn", "wireguard-go", "charon", "pluto", "zerotier-one", "nebula", "netbird",
	// routing and failover
	"bird", "zebra", "bgpd", "keepalived",
	// image builds: standalone BuildKit, not the buildx builder container
	"buildkitd",
}

// ciRunners, with drone-runner-*, run CI jobs: GitLab, GitHub Actions
// (Runner.Listener), Azure Pipelines (Agent.Listener), Woodpecker, Gitea,
// Forgejo, Buildkite. A runner in a container of the host's user namespace
// (rootful Docker, a Kubernetes pod) runs its jobs on this kernel, mostly
// through the Docker socket, so it counts in any network namespace; one in
// an unprivileged LXC, LXD or Proxmox container, with a user namespace of
// its own, is that container's.
var ciRunners = []string{"gitlab-runner", "Runner.Listener", "Agent.Listener", "woodpecker-agent", "act_runner", "forgejo-runner", "buildkite-agent"}

// Interfaces reported by name; the backend derives role tags.
var (
	roleIfaceNames = []string{
		"docker0", "podman0", "cni-podman0", "cni0", "cilium_host", "flannel.1", "vxlan.calico", "tunl0",
		"kube-ipvs0", "lxdbr0", "incusbr0", "nomad",
	}
	roleIfacePrefixes = []string{"br-", "virbr", "vmbr"}
)

// tunnelLinkTypes are ARPHRD types of tunnels, /sys/class/net/*/type: they
// set no DEVTYPE, so devTypes misses them.
var tunnelLinkTypes = map[string]string{"768": "ipip", "769": "ip6tnl", "776": "sit", "778": "gre", "823": "ip6gre"}

// roleMarkers are probed with lstat only: reading or connecting would wake
// a socket-activated daemon.
var roleMarkers = []string{
	"/dev/kvm",
	"/etc/kubernetes/manifests/kube-apiserver.yaml", // a control plane node
	"/var/lib/kubelet/config.yaml",
	"/var/lib/rancher/k3s", "/var/lib/rancher/rke2", "/var/snap/microk8s", "/var/lib/k0s",
	"/etc/cni/net.d",
	"/var/lib/containers/storage", // podman without running containers
	"/sys/module/wireguard",       // kernel WireGuard has no process
	"/proc/net/ip_vs",             // IPVS: kube-proxy in ipvs mode, keepalived LVS
}

// roleData carries signals for role tags (docker-host, k8s-node, nomad-node,
// ci-runner, vpn-gw, hypervisor, multi-uplink) that the backend derives.
type roleData struct {
	Processes     []string      `json:"processes"`
	Interfaces    ifaceSignals  `json:"interfaces"`
	DefaultRoutes defaultRoutes `json:"defaultRoutes"`
	Markers       []string      `json:"markers"`
}

type ifaceSignals struct {
	Total          int            `json:"total"` // without lo
	DevTypes       map[string]int `json:"devTypes"`
	LinkTypes      map[string]int `json:"linkTypes"` // tunnels without a DEVTYPE: gre, ipip, sit, ip6tnl, ip6gre
	Tun            int            `json:"tun"`       // tun/tap: wireguard-go, tailscale, openvpn
	Names          []string       `json:"names"`
	NamesTruncated bool           `json:"namesTruncated,omitempty"`
}

// defaultRoutes counts interfaces with a default route, not routes: ECMP and
// several router advertisements give one interface many routes. IPv4 shows
// the main table only; IPv6 shows every table, so a VPN with its own table
// (wg-quick 51820, tailscale 52) appears too — hence the interface list.
type defaultRoutes struct {
	V4         int      `json:"v4"`
	V6         int      `json:"v6"`
	Interfaces []string `json:"interfaces"`
}

func collectRoleSignals(_ context.Context, sc *scanCtx) Section {
	var (
		d                          roleData
		gaps                       gapList
		procErr, ifErr, v4Err, err error
		v4, v6                     []string
	)
	d.Processes, procErr = roleProcessesRunning(sc)
	gaps.add("/proc", procErr)
	d.Interfaces, ifErr = interfaceSignals(sc)
	gaps.add("/sys/class/net", ifErr)
	v4, v4Err = defaultRouteIfaces(sc, "/proc/net/route", defaultIfaceV4)
	gaps.add("/proc/net/route", v4Err)
	v6, err = defaultRouteIfaces(sc, "/proc/net/ipv6_route", defaultIfaceV6)
	gaps.optional("/proc/net/ipv6_route", err) // no IPv6
	d.DefaultRoutes = defaultRoutes{V4: len(v4), V6: len(v6), Interfaces: union(v4, v6, maxRouteIfaces)}
	d.Markers = presentMarkers(sc)

	if d.Processes == nil && ifErr != nil && v4Err != nil {
		return unknown(reasonOf(procErr)) // nothing readable
	}
	return collected(gaps, d)
}

// roleProcessesRunning lists the role processes found, sorted; incomplete
// with fs.ErrPermission under hidepid (see processes). A process in a network
// namespace other than PID 1's (a VPN client or kubelet in a container) is
// not a role of the host; a CI runner is not a network role, see ciRunners.
func roleProcessesRunning(sc *scanCtx) ([]string, error) {
	procs, err := sc.processes()
	if procs == nil && err != nil {
		return nil, err
	}
	hostNet, _ := sc.readlink("/proc/1/ns/net")
	hostUser, _ := sc.readlink("/proc/1/ns/user")
	found := map[string]bool{}
	for _, p := range procs {
		switch {
		case isRoleProcess(p.name) && sameNamespace(sc, p.pid, "net", hostNet):
		case isCIRunner(p.name) && (sameNamespace(sc, p.pid, "user", hostUser) || sameNamespace(sc, p.pid, "net", hostNet)):
		default:
			continue
		}
		found[p.name] = true
	}
	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	slices.Sort(out)
	return out, err
}

func isRoleProcess(name string) bool {
	return slices.Contains(roleProcesses, name) || strings.HasPrefix(name, "qemu-system-")
}

func isCIRunner(name string) bool {
	return slices.Contains(ciRunners, name) || strings.HasPrefix(name, "drone-runner-")
}

func interfaceSignals(sc *scanCtx) (ifaceSignals, error) {
	s := ifaceSignals{DevTypes: map[string]int{}, LinkTypes: map[string]int{}, Names: []string{}}
	entries, err := sc.readDir("/sys/class/net")
	if err != nil {
		return s, err
	}
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		s.Total++
		dir := "/sys/class/net/" + name
		if uevent, err := sc.read(dir+"/uevent", smallFileLimit); err == nil {
			for line := range strings.SplitSeq(string(uevent), "\n") {
				if t, ok := strings.CutPrefix(line, "DEVTYPE="); ok {
					s.DevTypes[t]++
				}
			}
		}
		if typ, err := sc.read(dir+"/type", smallFileLimit); err == nil {
			if tunnel, ok := tunnelLinkTypes[strings.TrimSpace(string(typ))]; ok {
				s.LinkTypes[tunnel]++
			}
		}
		if sc.exists(dir + "/tun_flags") {
			s.Tun++
		}
		if !slices.Contains(roleIfaceNames, name) && !hasAnyPrefix(name, roleIfacePrefixes) {
			continue
		}
		if len(s.Names) == maxRoleIfaceNames {
			s.NamesTruncated = true
			continue
		}
		s.Names = append(s.Names, name)
	}
	return s, nil
}

// defaultRouteIfaces returns the interfaces with a usable default route,
// sorted and deduplicated.
func defaultRouteIfaces(sc *scanCtx, path string, defaultIface func([]string) (string, bool)) ([]string, error) {
	b, err := sc.read(path, routesLimit)
	if err != nil {
		return nil, err
	}
	var out []string
	for line := range strings.SplitSeq(string(b), "\n") {
		if iface, ok := defaultIface(strings.Fields(line)); ok && !slices.Contains(out, iface) {
			out = append(out, iface)
		}
	}
	slices.Sort(out)
	return out, nil
}

// defaultIfaceV4: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
// A blackhole default has no interface ("*").
func defaultIfaceV4(f []string) (string, bool) {
	ok := len(f) >= 8 && f[0] != "*" && f[1] == "00000000" && f[7] == "00000000" && routeUsable(f[3])
	if !ok {
		return "", false
	}
	return f[0], true
}

// defaultIfaceV6: dest destlen src srclen nexthop metric refcnt use flags iface.
func defaultIfaceV6(f []string) (string, bool) {
	ok := len(f) >= 10 && f[1] == "00" && f[9] != "lo" && strings.Trim(f[0], "0") == "" && routeUsable(f[8])
	if !ok {
		return "", false
	}
	return f[9], true
}

func routeUsable(hexFlags string) bool {
	flags, err := strconv.ParseUint(hexFlags, 16, 32)
	return err == nil && flags&rtfUp != 0 && flags&rtfReject == 0
}

// union merges two sorted lists without duplicates, at most limit entries.
func union(a, b []string, limit int) []string {
	out := slices.Concat(a, b)
	slices.Sort(out)
	out = slices.Compact(out)
	return out[:min(len(out), limit)]
}

// presentMarkers lists the role marker paths that exist, plus Xen dom0, told
// apart from a domU by the capabilities file.
func presentMarkers(sc *scanCtx) []string {
	out := []string{}
	for _, p := range roleMarkers {
		if sc.exists(p) {
			out = append(out, p)
		}
	}
	if caps, err := sc.read("/proc/xen/capabilities", smallFileLimit); err == nil && strings.Contains(string(caps), "control_d") {
		out = append(out, "/proc/xen/capabilities:control_d")
	}
	return out
}
