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
	dockerEngine      = "docker"
	dockerSocketUnit  = "docker.socket"
	dockerCmdlineMax  = 64 << 10
	dockerConfigLimit = 1 << 20
	dockerAPIBudget   = 5 * time.Second // the whole conversation with dockerd
	maxPublished      = 1000            // port ranges merged first
	maxContainers     = 1000
	maxExposed        = 16
	maxCILabels       = 32 // per container
	maxImageName      = 255
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

	imageRepoRe = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?/)?` +
		`[a-z0-9]+([._-]+[a-z0-9]+)*(/[a-z0-9]+([._-]+[a-z0-9]+)*)*$`) // [registry[:port]/]path, lowercase
	ciLabelKeyRe      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$`)
	githubRunnerKeyRe = regexp.MustCompile(`^[0-9a-f]{6}$`)
)

// ciLabelPrefixes are the label namespaces (and Woodpecker's two keys) CI
// runners put on the containers they start: GitLab Runner, Woodpecker,
// Drone, Buildkite's docker plugins, Jenkins' docker-plugin. act_runner and Forgejo's runner
// label none: their containers are known by name.
var ciLabelPrefixes = []string{"com.gitlab.gitlab-runner.", "environment.runner.gitlab.com/", "wp_uuid", "wp_step", "io.drone",
	"com.buildkite.", "com.nirima.jenkins.plugins.docker."}

// gitlabRunnerType is the one CI label whose value is sent: the role of a
// GitLab Runner container (build, predefined, service, wait, …). The
// values of the others carry branches, project URLs, part of the runner
// token.
const gitlabRunnerType = "com.gitlab.gitlab-runner.type"

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
	Socket *dockerSocket `json:"socket"`
	// Published are the ports of running containers bound on the host;
	// null when the API did not answer.
	Published          []dockerPort `json:"published"`
	PublishedTruncated bool         `json:"publishedTruncated,omitempty"`
	// Containers are the running containers that publish a port, use host
	// networking or have the Docker socket mounted; null when the API did
	// not answer.
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

// dockerSocket is the API's unix socket. Members of its group are root in
// all but name, and the group need not be called docker: dockerd's --group,
// SocketGroup= of docker.socket, dockerroot on old RHEL.
type dockerSocket struct {
	fileMeta
	// Group of the socket's gid, from the accounts section; null when
	// /etc/group was not read (accounts disabled or failed).
	Group *gidGroup `json:"group"`
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
	Name         string            `json:"name"`
	Image        string            `json:"image,omitempty"`
	CILabels     map[string]string `json:"ciLabels,omitempty"`
	HostNetwork  bool              `json:"hostNetwork"`
	DockerSocket bool              `json:"dockerSocket"` // the socket, or a directory holding it, bind-mounted
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
// A gid is the same in every mount namespace: the group is the host's.
func dockerSocketMeta(sc *scanCtx, root, socket string, gaps *gapList) *dockerSocket {
	fi, err := sc.lstat(root + socket)
	if err == nil && fi.Mode()&fs.ModeSocket == 0 {
		err = errNotRegular
	}
	if err != nil {
		gaps.add(socket, err)
		return nil
	}
	s := &dockerSocket{fileMeta: metaOf(socket, fi)}
	_, res, _ := sc.dep(SectionAccounts)
	if acc, ok := res.(*accountsResult); ok {
		s.Group = acc.groupOf(s.GID)
	}
	return s
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
	d.Containers, d.ContainersTruncated = listedContainers(list, socket)
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
			if !published(p) {
				continue
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

// published: the port is bound on the host, not only exposed.
func published(p dockerapi.Port) bool { return p.PublicPort >= 1 && p.PublicPort <= 65535 }

// listedContainers are the containers that publish a port, use host
// networking or have the Docker socket bind-mounted, from the list (no
// request per container): those with host networking or the socket first,
// so the limit cuts the others, then by name.
func listedContainers(list []dockerapi.Container, socket string) ([]dockerContainer, bool) {
	out := []dockerContainer{}
	for _, c := range list {
		f := dockerContainer{Name: containerName(c), HostNetwork: c.HostConfig.NetworkMode == "host"}
		for _, m := range c.Mounts {
			src := path.Clean(m.Source)
			f.DockerSocket = f.DockerSocket || m.Type == "bind" && (src == socket || slices.Contains(dockerSocketMounts, src))
		}
		if f.HostNetwork || f.DockerSocket || slices.ContainsFunc(c.Ports, published) {
			f.Image, f.CILabels = containerImage(c.Image, c.ImageID), ciLabels(c.Labels)
			out = append(out, f)
		}
	}
	slices.SortFunc(out, func(a, b dockerContainer) int {
		return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(a.Name, b.Name))
	})
	if len(out) > maxContainers {
		return out[:maxContainers], true
	}
	return out, false
}

// rank orders containers with host networking or the socket before the rest.
func rank(c dockerContainer) int {
	if c.HostNetwork || c.DockerSocket {
		return 0
	}
	return 1
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

// containerImage is the repository of the image a container runs: the
// tag and digest dropped, and Docker Hub's docker.io/ and library/ — dockerd
// lists the reference as the container was created with, podman the full
// name (docker.io/library/nginx:latest for nginx). "" for an image ID,
// full or as short as typed — a prefix of imageID: dockerd lists the ID
// once the tag is moved or removed, and GitLab Runner starts jobs by ID.
// "invalid" for anything else.
func containerImage(ref, imageID string) string {
	id := strings.TrimPrefix(imageID, "sha256:")
	if ref == "" || strings.HasPrefix(ref, "sha256:") || id != "" && strings.HasPrefix(id, ref) {
		return ""
	}
	name, _, _ := strings.Cut(ref, "@")
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		name = name[:i]
	}
	if rest, ok := strings.CutPrefix(name, "docker.io/"); ok {
		name = rest
	} else if rest, ok := strings.CutPrefix(name, "index.docker.io/"); ok {
		name = rest
	}
	if rest, ok := strings.CutPrefix(name, "library/"); ok && !strings.Contains(rest, "/") {
		name = rest
	}
	if len(name) > maxImageName || !imageRepoRe.MatchString(name) {
		return valueInvalid
	}
	return name
}

// ciLabels are the CI runner labels of a container, at most maxCILabels:
// gitlabRunnerType first — GitLab Runner puts its prefix on the user's
// container_labels too, which must not push the role out — then in key
// order. Keys of ciLabelPrefixes, and the bare six-hex key GitHub's runner
// labels its containers with. Values are "", but for gitlabRunnerType.
// nil without any.
func ciLabels(labels map[string]string) map[string]string {
	var keys []string
	for k, v := range labels {
		github := len(k) == 6 && v == "" && githubRunnerKeyRe.MatchString(k)
		if (github || hasAnyPrefix(k, ciLabelPrefixes)) && ciLabelKeyRe.MatchString(k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	slices.SortFunc(keys, func(a, b string) int {
		switch {
		case a == gitlabRunnerType:
			return -1
		case b == gitlabRunnerType:
			return 1
		}
		return cmp.Compare(a, b)
	})
	out := make(map[string]string, min(len(keys), maxCILabels))
	for _, k := range keys[:min(len(keys), maxCILabels)] {
		out[k] = ""
		if k == gitlabRunnerType {
			out[k] = checkedBy(labels[k], dockerWordRe.MatchString)
		}
	}
	return out
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
