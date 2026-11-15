package security

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/dockerapi"
)

// Limits of the docker section.
const (
	dockerEngine         = "docker"
	dockerSocketUnit     = "docker.socket"
	dockerCmdlineMax     = 64 << 10
	dockerConfigLimit    = 1 << 20
	dockerAPIBudget      = 5 * time.Second // the whole conversation with dockerd
	maxPublished         = 1000            // port ranges merged first
	maxFlaggedContainers = 200
	maxExposed           = 16
)

// Forms of what dockerd answers and of daemon.json values: anything else is
// sent as "invalid".
var (
	dockerVersionRe   = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~_-]{0,63}$`)
	dockerWordRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9+_.-]{0,31}$`)
	dockerNameRe      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$`) // container names dockerd takes
	dockerBackendRe   = regexp.MustCompile(`^(iptables|nftables)$`)
	dockerProtocolsRe = regexp.MustCompile(`^(tcp|udp|sctp)$`)
	dockerGatewayRe   = regexp.MustCompile(`^(nat|nat-unprotected|routed|isolated)$`)
	dockerSwarmRe     = regexp.MustCompile(`^(inactive|pending|active|error|locked)$`)
)

// dockerSocketMounts are host paths whose bind mount gives a container the
// Docker socket: the socket itself or a directory holding it.
var dockerSocketMounts = []string{"/", "/run", "/var/run", "/run/docker.sock", "/var/run/docker.sock"}

// dockerData is the docker section: the rootful dockerd of the host.
type dockerData struct {
	Engine string `json:"engine"`
	// DaemonRunning: dockerd runs. false — only docker.socket listens: the
	// first connection starts the daemon; the API is not read.
	DaemonRunning bool `json:"daemonRunning"`
	// DaemonStartedAt: dockerd reads daemon.json at start (and on SIGHUP for
	// a few keys); a file newer than this may not be in force.
	DaemonStartedAt *time.Time `json:"daemonStartedAt"`
	// From the API; null when it did not answer (see gaps).
	Version             *string          `json:"version"`
	APIVersion          *string          `json:"apiVersion"`
	FirewallBackend     *string          `json:"firewallBackend"` // API 1.49+; null before: iptables
	SecurityOptions     []string         `json:"securityOptions"`
	SeccompProfile      *string          `json:"seccompProfile"` // builtin, unconfined, custom; null without seccomp
	ContainersRunning   *int             `json:"containersRunning"`
	Swarm               *dockerSwarm     `json:"swarm"`
	AuthorizationPlugin *bool            `json:"authorizationPlugin"`
	APIExposed          []dockerExposure `json:"apiExposed"`

	Config dockerConfig `json:"config"`
	Hosts  []dockerHost `json:"hosts"`
	// Socket is the unix socket of the API; null when there is none.
	Socket *fileMeta `json:"socket"`
	// Published are the ports of running containers bound on the host;
	// null when the API did not answer.
	Published          []dockerPort `json:"published"`
	PublishedTruncated bool         `json:"publishedTruncated,omitempty"`
	// Containers are the running containers with host networking or the
	// Docker socket mounted; null when the API did not answer.
	Containers          []dockerContainer `json:"containers"`
	ContainersTruncated bool              `json:"containersTruncated,omitempty"`
}

// dockerConfig is what flags and daemon.json set; a null field is set by
// neither, the default of the engine version applies.
type dockerConfig struct {
	File               *dockerConfigFile `json:"file"` // null without daemon.json
	UserlandProxy      *bool             `json:"userlandProxy"`
	IPTables           *bool             `json:"iptables"`
	IP6Tables          *bool             `json:"ip6tables"`
	FirewallBackend    *string           `json:"firewallBackend"`
	AllowDirectRouting *bool             `json:"allowDirectRouting"`
	ICC                *bool             `json:"icc"`
	NoNewPrivileges    *bool             `json:"noNewPrivileges"`
	LiveRestore        *bool             `json:"liveRestore"`
	TLS                *bool             `json:"tls"`
	TLSVerify          *bool             `json:"tlsVerify"`
	DefaultBindIP      *string           `json:"defaultBindIp"`
	UsernsRemap        bool              `json:"usernsRemap"`
	// default-network-opts of the bridge driver: networks created without
	// options of their own, compose networks among them.
	BridgeHostBindingIP   *string `json:"bridgeHostBindingIp"`
	BridgeGatewayModeIPv4 *string `json:"bridgeGatewayModeIpv4"`
	BridgeGatewayModeIPv6 *string `json:"bridgeGatewayModeIpv6"`
}

type dockerConfigFile struct {
	fileMeta
	MTime time.Time `json:"mtime"`
	// Valid: dockerd takes the file — JSON, and the keys read of the type
	// it expects. A dockerd that runs read it at start: an invalid file
	// stops the next start.
	Valid bool `json:"valid"`
}

type dockerHost struct {
	Proto  string `json:"proto"` // unix, tcp, fd, npipe; "invalid" for an address dockerd refuses
	Addr   string `json:"addr"`
	Source string `json:"source"`
}

type dockerPort struct {
	Container   string `json:"container"`
	IP          string `json:"ip"` // "" when dockerd sends none
	PublicPort  int    `json:"publicPort"`
	PrivatePort int    `json:"privatePort"`
	Type        string `json:"type"`
	// The last ports of a range (-p 49152-65535:49152-65535), which the API
	// lists one by one; absent for a single port.
	PublicPortEnd  int `json:"publicPortEnd,omitempty"`
	PrivatePortEnd int `json:"privatePortEnd,omitempty"`
}

type dockerSwarm struct {
	State   string `json:"state"`
	Manager bool   `json:"manager"`
}

type dockerExposure struct {
	Addr  string `json:"addr"`
	NoTLS bool   `json:"noTls"` // without encryption; else TLS without client verification
}

type dockerContainer struct {
	Name         string `json:"name"`
	HostNetwork  bool   `json:"hostNetwork"`
	DockerSocket bool   `json:"dockerSocket"` // the socket, or a directory holding it, bind-mounted
}

func collectDocker(ctx context.Context, sc *scanCtx) Section {
	var gaps gapList
	p, ownMnt, err := dockerDaemon(sc)
	switch {
	case p == nil && err != nil:
		gaps.add("/proc", err)
		return absent(gaps) // absence is not known
	case p == nil:
		return dockerSocketOnly(sc)
	}
	droot := "" // dockerd's root: a dockerd in its own mount namespace (the snap) sees its paths there
	if ownMnt {
		droot = "/proc/" + p.pid + "/root"
	}
	d := dockerData{Engine: dockerEngine, DaemonRunning: true, DaemonStartedAt: processStart(sc, p.pid)}
	head, err := sc.readHead("/proc/"+p.pid+"/cmdline", dockerCmdlineMax)
	gaps.add("/proc/"+p.pid+"/cmdline", err)
	flags := dockerapi.ParseArgs(strings.Split(strings.TrimRight(string(head), "\x00"), "\x00"))

	configFile := path.Join("/", cmp.Or(flags.ConfigFile, dockerapi.DefaultConfigFile)) // relative to dockerd's cwd, /
	file, fileSettings := readDockerConfig(sc, droot, configFile, &gaps)
	d.Config = dockerConfigOf(dockerapi.Merge(flags, fileSettings), file)
	hosts := dockerapi.ResolveHosts(flags, fileSettings, unitValues(sc, dockerSocketUnit, "ListenStream"))
	d.Hosts = dockerHostsOf(hosts)
	socket, ok := dockerapi.Socket(hosts)
	if !ok {
		return collected(gaps, d) // TCP only, or an abstract socket: not talked to
	}
	sroot := droot
	if socket.Systemd {
		sroot = "" // systemd made it, in the host's mount namespace
	}
	if d.Socket = dockerSocketMeta(sc, sroot, socket.Addr, &gaps); d.Socket == nil {
		return collected(gaps, d)
	}
	gaps.add(socket.Addr, dockerErr(d.readAPI(ctx, sc.newDockerClient(sc.root+sroot+socket.Addr), socket.Addr)))
	return collected(gaps, d)
}

// dockerSocketOnly is the section without a dockerd: na, unless
// docker.socket is enabled — then systemd holds the sockets, and the first
// connection starts a root daemon. They are listed and stat'ed, never
// connected to; daemon.json is what that start will read.
func dockerSocketOnly(sc *scanCtx) Section {
	if !unitEnabled(sc, dockerSocketUnit, "sockets.target") {
		return Section{Status: StatusNA}
	}
	var gaps gapList
	d := dockerData{Engine: dockerEngine}
	file, fileSettings := readDockerConfig(sc, "", dockerapi.DefaultConfigFile, &gaps)
	d.Config = dockerConfigOf(fileSettings, file)
	hosts := dockerapi.SocketUnitHosts(unitValues(sc, dockerSocketUnit, "ListenStream"))
	d.Hosts = dockerHostsOf(hosts)
	if socket, ok := dockerapi.Socket(hosts); ok {
		d.Socket = dockerSocketMeta(sc, "", socket.Addr, &gaps)
	}
	return collected(gaps, d)
}

// dockerDaemon finds the rootful dockerd of the host: trusted (root, a
// binary only root can change) and in the network namespace of PID 1,
// where its ports and firewall rules are. ownMnt: it runs in a mount
// namespace of its own (the snap). A dockerd in a container
// (docker-in-docker) or a rootless one is not this section's.
func dockerDaemon(sc *scanCtx) (*process, bool, error) {
	procs, err := sc.processes()
	hostMnt, _ := sc.readlink("/proc/1/ns/mnt")
	hostNet, _ := sc.readlink("/proc/1/ns/net")
	for _, p := range procs {
		if p.name != "dockerd" {
			continue
		}
		if p.exe == "" { // found by argv[0]: without CAP_SYS_PTRACE its binary cannot be checked
			err = fs.ErrPermission
			continue
		}
		if trustedProcess(sc, p) && sameNamespace(sc, p.pid, "net", hostNet) {
			return &p, !sameNamespace(sc, p.pid, "mnt", hostMnt), nil
		}
	}
	return nil, false, err
}

// readDockerConfig reads daemon.json under droot, dockerd's root; nil
// without the file. Paths are reported as dockerd sees them.
func readDockerConfig(sc *scanCtx, droot, path string, gaps *gapList) (*dockerConfigFile, dockerapi.Settings) {
	b, err := sc.read(droot+path, dockerConfigLimit)
	if err != nil {
		gaps.optional(path, err)
		return nil, dockerapi.Settings{}
	}
	s, err := dockerapi.ParseConfig(b)
	file := &dockerConfigFile{Valid: err == nil}
	if fi, err := sc.stat(droot + path); err == nil {
		file.fileMeta, file.MTime = metaOf(path, fi), fi.ModTime().UTC()
	} else {
		file.Path = path
	}
	return file, s
}

// dockerSocketMeta stats the socket under root without following it, and
// without connecting: nil, with a gap, when it is missing or not a socket.
func dockerSocketMeta(sc *scanCtx, root, socket string, gaps *gapList) *fileMeta {
	fi, err := sc.lstat(root + socket)
	if err == nil && fi.Mode()&fs.ModeSocket == 0 {
		err = errNotRegular
	}
	if err != nil {
		gaps.add(socket, err)
		return nil
	}
	m := metaOf(socket, fi)
	return &m
}

func dockerConfigOf(s dockerapi.Settings, file *dockerConfigFile) dockerConfig {
	return dockerConfig{
		File:                  file,
		UserlandProxy:         s.UserlandProxy,
		IPTables:              s.IPTables,
		IP6Tables:             s.IP6Tables,
		FirewallBackend:       checked(s.FirewallBackend, dockerBackendRe.MatchString),
		AllowDirectRouting:    s.AllowDirectRouting,
		ICC:                   s.ICC,
		NoNewPrivileges:       s.NoNewPrivileges,
		LiveRestore:           s.LiveRestore,
		TLS:                   s.TLS,
		TLSVerify:             s.TLSVerify,
		DefaultBindIP:         checked(s.DefaultBindIP, isIPAddr),
		UsernsRemap:           s.UsernsRemap != nil && *s.UsernsRemap != "",
		BridgeHostBindingIP:   checked(s.BridgeHostBindingIPv4, isIPAddr),
		BridgeGatewayModeIPv4: checked(s.BridgeGatewayModeIPv4, dockerGatewayRe.MatchString),
		BridgeGatewayModeIPv6: checked(s.BridgeGatewayModeIPv6, dockerGatewayRe.MatchString),
	}
}

func isIPAddr(v string) bool { return net.ParseIP(v) != nil }

// dockerHostsOf is the wire form of the hosts: an address dockerd refuses
// is "invalid", never sent as written.
func dockerHostsOf(hosts []dockerapi.ResolvedHost) []dockerHost {
	out := make([]dockerHost, 0, len(hosts))
	for _, h := range hosts {
		if h.Err != nil {
			out = append(out, dockerHost{Proto: valueInvalid, Source: h.Source})
			continue
		}
		out = append(out, dockerHost{Proto: h.Proto, Addr: h.Addr, Source: h.Source})
	}
	return out
}

// errSkipped: entries of /containers/json of a shape the agent does not
// read; the ports listed are not all of them.
var errSkipped = fmt.Errorf("docker: containers skipped: %w", errParse)

// readAPI reads the version, the posture and the published ports from
// dockerd, within dockerAPIBudget. The error is of the request that
// failed; what came before it is kept. socket is the path containers may
// mount.
func (d *dockerData) readAPI(ctx context.Context, c *dockerapi.Client, socket string) error {
	ctx, cancel := context.WithTimeout(ctx, dockerAPIBudget)
	defer cancel()
	api, err := c.Ping(ctx)
	if err != nil {
		return err
	}
	d.APIVersion = checked(nonEmpty(api), dockerVersionRe.MatchString)
	info, err := c.Info(ctx)
	if err != nil {
		return err
	}
	d.setInfo(info)
	list, skipped, err := c.Containers(ctx)
	if err != nil {
		return err
	}
	d.Published, d.PublishedTruncated = publishedPorts(list)
	d.Containers, d.ContainersTruncated = flaggedContainers(list, socket)
	if skipped > 0 {
		return errSkipped
	}
	return nil
}

func (d *dockerData) setInfo(info dockerapi.Info) {
	d.Version = checked(nonEmpty(info.ServerVersion), dockerVersionRe.MatchString)
	d.FirewallBackend = checked(nonEmpty(info.FirewallBackend), dockerWordRe.MatchString)
	d.SecurityOptions = make([]string, 0, len(info.SecurityOptions))
	for _, o := range info.SecurityOptions {
		if !dockerWordRe.MatchString(o) {
			o = valueInvalid
		}
		d.SecurityOptions = append(d.SecurityOptions, o)
	}
	d.SeccompProfile = seccompProfile(info)
	d.ContainersRunning = info.ContainersRunning
	if info.SwarmState != "" {
		state := info.SwarmState
		if !dockerSwarmRe.MatchString(state) {
			state = valueInvalid
		}
		d.Swarm = &dockerSwarm{State: state, Manager: info.SwarmManager}
	}
	authz := info.AuthorizationPlugins > 0
	d.AuthorizationPlugin = &authz
	d.APIExposed = []dockerExposure{}
	for _, e := range info.Exposed[:min(len(info.Exposed), maxExposed)] {
		addr := e.Addr
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = valueInvalid
		}
		d.APIExposed = append(d.APIExposed, dockerExposure{Addr: addr, NoTLS: e.NoTLS})
	}
}

// seccompProfile is the daemon's seccomp profile by kind, never its path:
// builtin ("default" before Docker 20.10), unconfined, custom.
func seccompProfile(info dockerapi.Info) *string {
	if !slices.Contains(info.SecurityOptions, "seccomp") {
		return nil
	}
	kind := "custom"
	switch info.SeccompProfile {
	case seccompBuiltin, seccompBuiltinOld:
		kind = seccompBuiltin
	case "unconfined":
		kind = "unconfined"
	}
	return &kind
}

// Names of dockerd's own seccomp profile in SecurityOptions.
const (
	seccompBuiltin    = "builtin"
	seccompBuiltinOld = "default" // before Docker 20.10
)

// newDockerClient is dockerapi.New, or the test's.
func (sc *scanCtx) newDockerClient(path string) *dockerapi.Client {
	if sc.dockerClient != nil {
		return sc.dockerClient(path)
	}
	return dockerapi.New(path)
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// dockerErr maps an API failure to the error reasonOf reads.
func dockerErr(err error) error {
	if err == nil {
		return nil
	}
	var (
		se *dockerapi.StatusError
		ne net.Error
	)
	switch {
	case errors.Is(err, dockerapi.ErrTooLarge):
		return errTooLarge
	case errors.As(err, &se) && (se.Code == 401 || se.Code == 403): // an authorization plugin
		return fs.ErrPermission
	case errors.As(err, &ne) && ne.Timeout():
		return context.DeadlineExceeded
	}
	return err
}

// publishedPorts lists the ports bound on the host, consecutive ports
// merged into ranges, sorted, at most maxPublished: one large range must
// not push the other containers out.
func publishedPorts(list []dockerapi.Container) ([]dockerPort, bool) {
	var ports []dockerPort
	for _, c := range list {
		name := containerName(c)
		for _, p := range c.Ports {
			if p.PublicPort < 1 || p.PublicPort > 65535 {
				continue // exposed, not published
			}
			if !dockerProtocolsRe.MatchString(p.Type) {
				p.Type = valueInvalid
			}
			ports = append(ports, dockerPort{Container: name, IP: portIP(p.IP), PublicPort: p.PublicPort,
				PrivatePort: p.PrivatePort, Type: p.Type})
		}
	}
	slices.SortFunc(ports, func(a, b dockerPort) int {
		return cmp.Or(cmp.Compare(a.Container, b.Container), cmp.Compare(a.Type, b.Type), cmp.Compare(a.IP, b.IP),
			cmp.Compare(a.PublicPort, b.PublicPort))
	})
	out := []dockerPort{}
	for _, p := range ports {
		if n := len(out); n > 0 && extendsRange(out[n-1], p) {
			out[n-1].PublicPortEnd, out[n-1].PrivatePortEnd = p.PublicPort, p.PrivatePort
			continue
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b dockerPort) int {
		return cmp.Or(cmp.Compare(a.Container, b.Container), cmp.Compare(a.PublicPort, b.PublicPort),
			cmp.Compare(a.Type, b.Type), cmp.Compare(a.IP, b.IP))
	})
	if len(out) > maxPublished {
		return out[:maxPublished], true
	}
	return out, false
}

// extendsRange: p is the next port of the range, or single port, r.
func extendsRange(r, p dockerPort) bool {
	return r.Container == p.Container && r.IP == p.IP && r.Type == p.Type &&
		cmp.Or(r.PublicPortEnd, r.PublicPort)+1 == p.PublicPort && cmp.Or(r.PrivatePortEnd, r.PrivatePort)+1 == p.PrivatePort
}

// flaggedContainers are the containers with host networking or the Docker
// socket bind-mounted, from the list (no request per container), sorted.
func flaggedContainers(list []dockerapi.Container, socket string) ([]dockerContainer, bool) {
	out := []dockerContainer{}
	for _, c := range list {
		f := dockerContainer{Name: containerName(c), HostNetwork: c.HostConfig.NetworkMode == "host"}
		for _, m := range c.Mounts {
			src := path.Clean(m.Source)
			f.DockerSocket = f.DockerSocket || m.Type == "bind" && (src == socket || slices.Contains(dockerSocketMounts, src))
		}
		if f.HostNetwork || f.DockerSocket {
			out = append(out, f)
		}
	}
	slices.SortFunc(out, func(a, b dockerContainer) int { return cmp.Compare(a.Name, b.Name) })
	if len(out) > maxFlaggedContainers {
		return out[:maxFlaggedContainers], true
	}
	return out, false
}

// containerName is the first name without "/", or "invalid".
func containerName(c dockerapi.Container) string {
	name := ""
	if len(c.Names) > 0 {
		name = strings.TrimPrefix(c.Names[0], "/")
	}
	if !dockerNameRe.MatchString(name) {
		return valueInvalid
	}
	return name
}

// portIP is the address a port is bound to, canonical, or "invalid".
func portIP(ip string) string {
	if ip == "" {
		return ""
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return valueInvalid
	}
	return a.String()
}
