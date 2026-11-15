package security

import (
	"bytes"
	"strconv"
	"strings"
)

// Inodes of the initial pid and user namespaces, fixed since Linux 3.8.
const (
	hostPidNs  = "pid:[4026531836]"
	hostUserNs = "user:[4026531837]"
)

// smallFileLimit caps the one-line files of /proc, /sys and /run.
const smallFileLimit = 64 << 10

// Values of envData.Libc.
const (
	libcGlibc = "glibc"
	libcMusl  = "musl"
)

// Values of envData.Init.
const (
	initSystemd = "systemd"
	initOpenRC  = "openrc"
	initOther   = "other"
)

// Values of envData.ContainerKind.
const (
	containerNone    = "none"
	containerDocker  = "docker"
	containerPodman  = "podman"
	containerK8s     = "k8s"
	containerLXC     = "lxc"
	containerNspawn  = "nspawn"
	containerOpenVZ  = "openvz"
	containerUnknown = valueUnknown
)

// envData says where the agent runs. Without it every other section may give
// a false pass: in a container /etc belongs to the container.
type envData struct {
	PidNsHost      bool `json:"pidNsHost"`
	RootIsHostRoot bool `json:"rootIsHostRoot"`
	// NetNsHost: the agent shares the net namespace of PID 1 — in an app
	// container that is the container's own PID 1, not the host's.
	NetNsHost bool `json:"netNsHost"`
	// UserNsHost: the initial user namespace. Outside it (unprivileged LXC,
	// rootless podman) uid 0 and a full capEff are not root of the host.
	UserNsHost    bool   `json:"userNsHost"`
	ContainerKind string `json:"containerKind"`
	// Virt is the hypervisor, as systemd-detect-virt names it, or "none" on
	// bare metal. Kernel-wide, so in a container too.
	Virt string `json:"virt"`
	Libc string `json:"libc"`
	Init string `json:"init"`
}

// appContainer: docker, podman or k8s without the host root in view, or an
// unidentified container (another pid namespace, no marker: a pod without a
// service account token, nerdctl). Host sections report
// unknown/container_env there. A system container (lxc, nspawn, openvz) is a
// machine of its own and is collected.
func (e envData) appContainer() bool {
	switch e.ContainerKind {
	case containerDocker, containerPodman, containerK8s:
		return !e.RootIsHostRoot
	case containerUnknown:
		return !e.PidNsHost
	}
	return false
}

// collectEnvironment checks the pid namespace first: in the initial one the
// agent is on the host unless its root differs from PID 1's. Outside it the
// container markers are read in the order of systemd's virt.c.
func collectEnvironment(sc *scanCtx) (Section, envData) {
	env := envData{ContainerKind: containerUnknown}
	pidNs, err := sc.readlink("/proc/self/ns/pid")
	if err != nil {
		return unknown(reasonOf(err)), env
	}
	env.PidNsHost = pidNs == hostPidNs

	var gaps gapList
	if env.PidNsHost {
		// With the host pid namespace a different root than PID 1's means a
		// container started with --pid=host. Without CAP_SYS_PTRACE that is
		// unknowable: no marker leaves the kind unknown, not "none".
		same, sameErr := sc.sameFile("/", "/proc/1/root")
		gaps.add("/proc/1/root", sameErr)
		env.RootIsHostRoot = same
	}
	env.ContainerKind = containerNone
	if !env.RootIsHostRoot {
		env.ContainerKind = detectContainer(sc)
	}

	userNs, err := sc.readlink("/proc/self/ns/user")
	gaps.add("/proc/self/ns/user", err)
	env.UserNsHost = userNs == hostUserNs

	selfNet, err1 := sc.readlink("/proc/self/ns/net")
	initNet, err2 := sc.readlink("/proc/1/ns/net")
	gaps.add("/proc/self/ns/net", err1)
	if err1 == nil {
		gaps.add("/proc/1/ns/net", err2)
	}
	env.NetNsHost = err1 == nil && err2 == nil && selfNet == initNet

	env.Virt = detectVirt(sc, &gaps)
	env.Libc = detectLibc(sc)
	env.Init = detectInit(sc)
	return collected(gaps, env), env
}

// detectContainer reads the container markers in the order of systemd's
// virt.c, the most reliable first; /.dockerenv comes last, it may be left in
// an image by mistake. A manager name it does not know ("oci" in UBI images)
// does not end the search.
func detectContainer(sc *scanCtx) string {
	if sc.exists("/proc/vz") && !sc.exists("/proc/bc") {
		return containerOpenVZ // a container, not the OpenVZ host
	}
	for _, p := range []string{"/run/host/container-manager", "/run/systemd/container"} {
		if b, err := sc.read(p, smallFileLimit); err == nil {
			if kind := containerOfManager(sc, strings.TrimSpace(string(b))); kind != containerUnknown {
				return kind
			}
		}
	}
	if v, ok := initEnv(sc, "container"); ok {
		if kind := containerOfManager(sc, v); kind != containerUnknown {
			return kind
		}
	}
	switch {
	case sc.exists("/run/.containerenv"):
		return containerPodman
	case isK8s(sc):
		return containerK8s
	case sc.exists("/.dockerenv"):
		return containerDocker
	}
	return containerUnknown
}

func containerOfManager(sc *scanCtx, name string) string {
	switch name {
	case "lxc", "lxc-libvirt":
		return containerLXC
	case "systemd-nspawn":
		return containerNspawn
	}
	if isK8s(sc) {
		return containerK8s
	}
	switch name {
	case "docker":
		return containerDocker
	case "podman":
		return containerPodman
	}
	return containerUnknown
}

// isK8s: the service account mount every pod gets unless it opts out.
func isK8s(sc *scanCtx) bool {
	return sc.exists("/var/run/secrets/kubernetes.io/serviceaccount") ||
		sc.exists("/run/secrets/kubernetes.io/serviceaccount")
}

// initEnv returns one variable from the environment of PID 1. Only the
// requested key is kept: the environment may hold secrets.
func initEnv(sc *scanCtx, key string) (string, bool) {
	b, err := sc.read("/proc/1/environ", smallFileLimit)
	if err != nil {
		return "", false
	}
	for kv := range bytes.SplitSeq(b, []byte{0}) {
		if k, v, ok := bytes.Cut(kv, []byte{'='}); ok && string(k) == key {
			return string(v), true
		}
	}
	return "", false
}

// detectLibc goes by the dynamic loaders present. Both is common: the musl
// package on Debian, gcompat on Alpine — the distribution decides then.
func detectLibc(sc *scanCtx) string {
	musl := sc.glob("/lib/ld-musl-*")
	glibc := sc.glob("/lib*/ld-linux*.so.*") || sc.glob("/usr/lib*/ld-linux*.so.*")
	switch {
	case musl && glibc:
		if osID(sc) == "alpine" {
			return libcMusl
		}
		return libcGlibc
	case musl:
		return libcMusl
	case glibc:
		return libcGlibc
	}
	return valueUnknown
}

// osID is ID from /etc/os-release.
func osID(sc *scanCtx) string {
	b, _ := sc.read("/etc/os-release", smallFileLimit)
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "ID="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func detectInit(sc *scanCtx) string {
	comm, _ := sc.read("/proc/1/comm", smallFileLimit)
	switch strings.TrimSpace(string(comm)) {
	case initSystemd:
		return initSystemd
	case "openrc-init":
		return initOpenRC
	}
	switch {
	case sc.exists("/run/systemd/system"):
		return initSystemd
	case sc.exists("/run/openrc"):
		return initOpenRC
	}
	return initOther
}

// readAgent reads the uid and effective capabilities of the agent from
// /proc/self/status.
func readAgent(sc *scanCtx) (Agent, error) {
	b, err := sc.read("/proc/self/status", smallFileLimit)
	if err != nil {
		return Agent{}, err
	}
	a := Agent{UID: -1}
	for line := range strings.SplitSeq(string(b), "\n") {
		k, v, _ := strings.Cut(line, ":")
		f := strings.Fields(v)
		switch {
		case k == "Uid" && len(f) >= 2:
			a.UID, err = strconv.Atoi(f[1])
		case k == "CapEff" && len(f) == 1:
			var mask uint64
			mask, err = strconv.ParseUint(f[0], 16, 64)
			a.CapEff = bitNames(mask, capabilities, "CAP_")
		}
		if err != nil {
			return Agent{}, errParse
		}
	}
	return a, nil
}

// bitNames names the set bits of mask from names; bits past the table come
// out as <prefix><bit>.
func bitNames(mask uint64, names []string, prefix string) []string {
	out := []string{}
	for bit := range 64 {
		if mask&(1<<bit) == 0 {
			continue
		}
		if bit < len(names) {
			out = append(out, names[bit])
		} else {
			out = append(out, prefix+strconv.Itoa(bit))
		}
	}
	return out
}

// capabilities by bit number, from linux/capability.h.
var capabilities = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
	"CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK",
	"CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
	"CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
	"CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}
