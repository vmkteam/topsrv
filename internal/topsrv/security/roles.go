package security

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	maxRoleIfaceNames = 32      // a docker host has a br-* per network
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
	"dockerd", "containerd", "kubelet", "k3s", "crio", "conmon", "libvirtd", "virtqemud",
	"lxd", "incus", "incusd", "tailscaled", "openvpn", "cilium-agent", "calico-node",
}

// roleIfaceNames are reported by name; the backend derives role tags.
var (
	roleIfaceNames    = []string{"docker0", "cni0", "cilium_host"}
	roleIfacePrefixes = []string{"br-", "virbr"}
)

// roleData carries signals for role tags (docker-host, k8s-node, vpn-gw,
// hypervisor, multi-uplink) that the backend derives.
type roleData struct {
	Processes     []string      `json:"processes"`
	Interfaces    ifaceSignals  `json:"interfaces"`
	DefaultRoutes defaultRoutes `json:"defaultRoutes"`
}

type ifaceSignals struct {
	Total          int            `json:"total"` // without lo
	DevTypes       map[string]int `json:"devTypes"`
	Tun            int            `json:"tun"` // tun/tap: wireguard-go, tailscale, openvpn
	Names          []string       `json:"names"`
	NamesTruncated bool           `json:"namesTruncated,omitempty"`
}

// defaultRoutes counts default routes of the main table.
type defaultRoutes struct {
	V4 int `json:"v4"`
	V6 int `json:"v6"`
}

func collectRoleSignals(_ context.Context, sc *scanCtx) Section {
	var (
		d                          roleData
		gaps                       gapList
		procErr, ifErr, v4Err, err error
	)
	d.Processes, procErr = roleProcessesRunning(sc)
	gaps.add("/proc", procErr)
	d.Interfaces, ifErr = interfaceSignals(sc)
	gaps.add("/sys/class/net", ifErr)
	d.DefaultRoutes.V4, v4Err = countDefaultRoutes(sc, "/proc/net/route", isDefaultV4)
	gaps.add("/proc/net/route", v4Err)
	d.DefaultRoutes.V6, err = countDefaultRoutes(sc, "/proc/net/ipv6_route", isDefaultV6)
	gaps.optional("/proc/net/ipv6_route", err) // no IPv6

	if d.Processes == nil && ifErr != nil && v4Err != nil {
		return unknown(reasonOf(procErr)) // nothing readable
	}
	return collected(gaps, d)
}

// roleProcessesRunning lists the role processes found, sorted. Processes come
// and go during the walk, so a vanished one is skipped; a command line the
// agent may not read (/proc mounted with hidepid) makes the list incomplete,
// reported as fs.ErrPermission with what was found. Of the command line only
// argv[0] is read: the rest may hold secrets.
func roleProcessesRunning(sc *scanCtx) ([]string, error) {
	entries, err := sc.readDir("/proc")
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	var denied error
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		name, err := processName(sc, e.Name())
		if errors.Is(err, fs.ErrPermission) {
			denied = err
		}
		if isRoleProcess(name) {
			found[name] = true
		}
	}
	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	slices.Sort(out)
	return out, denied
}

func processName(sc *scanCtx, pid string) (string, error) {
	if exe, err := sc.readlink("/proc/" + pid + "/exe"); err == nil {
		return filepath.Base(strings.TrimSuffix(exe, " (deleted)")), nil
	}
	head, err := sc.readHead("/proc/"+pid+"/cmdline", argv0Limit)
	if err != nil {
		return "", err
	}
	argv0, _, _ := strings.Cut(string(head), "\x00")
	argv0, _, _ = strings.Cut(argv0, " ") // a rewritten title: "k3s server"
	return filepath.Base(argv0), nil
}

func isRoleProcess(name string) bool {
	return slices.Contains(roleProcesses, name) || strings.HasPrefix(name, "qemu-system-")
}

func interfaceSignals(sc *scanCtx) (ifaceSignals, error) {
	s := ifaceSignals{DevTypes: map[string]int{}, Names: []string{}}
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
		if sc.exists(dir + "/tun_flags") {
			s.Tun++
		}
		if !slices.Contains(roleIfaceNames, name) &&
			!slices.ContainsFunc(roleIfacePrefixes, func(p string) bool { return strings.HasPrefix(name, p) }) {
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

func countDefaultRoutes(sc *scanCtx, path string, isDefault func([]string) bool) (int, error) {
	b, err := sc.read(path, routesLimit)
	if err != nil {
		return 0, err
	}
	n := 0
	for line := range strings.SplitSeq(string(b), "\n") {
		if isDefault(strings.Fields(line)) {
			n++
		}
	}
	return n, nil
}

// isDefaultV4: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
func isDefaultV4(f []string) bool {
	return len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" && routeUsable(f[3])
}

// isDefaultV6: dest destlen src srclen nexthop metric refcnt use flags iface.
func isDefaultV6(f []string) bool {
	return len(f) >= 10 && f[1] == "00" && f[9] != "lo" &&
		strings.Trim(f[0], "0") == "" && routeUsable(f[8])
}

func routeUsable(hexFlags string) bool {
	flags, err := strconv.ParseUint(hexFlags, 16, 32)
	return err == nil && flags&rtfUp != 0 && flags&rtfReject == 0
}
