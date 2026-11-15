package security

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
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
	maxPublished      = 1000
	dockerStockSocket = "/run/docker.sock" // ListenStream of the docker.socket Docker ships
)

// Sources of dockerHost.
const (
	hostFromCmdline    = "cmdline"
	hostFromConfig     = "config"
	hostFromSocketUnit = "socketUnit"
	hostFromDefault    = "default"
)

// Forms of what dockerd answers and of daemon.json values: anything else is
// sent as "invalid".
var (
	dockerVersionRe   = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~_-]{0,63}$`)
	dockerWordRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9+_.-]{0,31}$`)
	dockerNameRe      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$`) // container names dockerd takes
	dockerBackendRe   = regexp.MustCompile(`^(iptables|nftables)$`)
	dockerProtocolsRe = regexp.MustCompile(`^(tcp|udp|sctp)$`)
)

// dockerData is the docker section: the rootful dockerd of the host.
type dockerData struct {
	Engine string `json:"engine"`
	// DaemonStartedAt: dockerd reads daemon.json at start (and on SIGHUP for
	// a few keys); a file newer than this may not be in force.
	DaemonStartedAt *time.Time `json:"daemonStartedAt"`
	// From the API; null when it did not answer (see gaps).
	Version           *string  `json:"version"`
	APIVersion        *string  `json:"apiVersion"`
	FirewallBackend   *string  `json:"firewallBackend"` // API 1.49+; null before: iptables
	SecurityOptions   []string `json:"securityOptions"`
	ContainersRunning *int     `json:"containersRunning"`

	Config dockerConfig `json:"config"`
	Hosts  []dockerHost `json:"hosts"`
	// Socket is the unix socket the API was read from; null when there is
	// none to read.
	Socket *fileMeta `json:"socket"`
	// Published are the ports of running containers bound on the host;
	// null when the API did not answer.
	Published          []dockerPort `json:"published"`
	PublishedTruncated bool         `json:"publishedTruncated,omitempty"`
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
}

func collectDocker(ctx context.Context, sc *scanCtx) Section {
	var gaps gapList
	p, err := dockerDaemon(sc)
	if p == nil {
		gaps.add("/proc", err)
		return absent(gaps) // no dockerd: the socket is not touched, it may be socket-activated
	}
	d := dockerData{Engine: dockerEngine, DaemonStartedAt: processStart(sc, p.pid)}
	head, err := sc.readHead("/proc/"+p.pid+"/cmdline", dockerCmdlineMax)
	gaps.add("/proc/"+p.pid+"/cmdline", err)
	flags := dockerapi.ParseArgs(strings.Split(strings.TrimRight(string(head), "\x00"), "\x00"))

	file, fileSettings := readDockerConfig(sc, cmp.Or(flags.ConfigFile, dockerapi.DefaultConfigFile), &gaps)
	settings := dockerapi.Merge(flags, fileSettings)
	d.Config = dockerConfigOf(settings, file)
	hosts, socket := dockerHosts(sc, flags, fileSettings, settings)
	d.Hosts = hosts
	if socket == "" {
		return collected(gaps, d) // TCP only, or an abstract socket: not talked to
	}
	fi, err := sc.lstat(socket)
	switch {
	case err != nil:
		gaps.add(socket, err)
		return collected(gaps, d)
	case fi.Mode()&fs.ModeSocket == 0:
		gaps.add(socket, errNotRegular)
		return collected(gaps, d)
	}
	m := metaOf(socket, fi)
	d.Socket = &m
	d.readAPI(ctx, sc, socket, &gaps)
	return collected(gaps, d)
}

// dockerDaemon finds the rootful dockerd of the host: trusted (root, a
// binary only root can change) and in the mount and network namespaces of
// PID 1. A dockerd in a container (docker-in-docker) or a rootless one
// does not publish ports on the host's firewall and is not this section's.
func dockerDaemon(sc *scanCtx) (*process, error) {
	procs, err := sc.processes()
	hostMnt, _ := sc.readlink("/proc/1/ns/mnt")
	hostNet, _ := sc.readlink("/proc/1/ns/net")
	for _, p := range procs {
		if p.name != "dockerd" || !trustedProcess(sc, p) {
			continue
		}
		if sameNamespace(sc, p.pid, "mnt", hostMnt) && sameNamespace(sc, p.pid, "net", hostNet) {
			return &p, nil
		}
	}
	return nil, err
}

// sameNamespace: the process is in the namespace of PID 1, or that cannot
// be told.
func sameNamespace(sc *scanCtx, pid, kind, host string) bool {
	ns, err := sc.readlink("/proc/" + pid + "/ns/" + kind)
	return err != nil || host == "" || ns == host
}

// readDockerConfig reads daemon.json: nil without the file.
func readDockerConfig(sc *scanCtx, path string, gaps *gapList) (*dockerConfigFile, dockerapi.Settings) {
	b, err := sc.read(path, dockerConfigLimit)
	if err != nil {
		gaps.optional(path, err)
		return nil, dockerapi.Settings{}
	}
	s, err := dockerapi.ParseConfig(b)
	file := &dockerConfigFile{Valid: err == nil}
	if fi, err := sc.stat(path); err == nil {
		file.fileMeta, file.MTime = metaOf(path, fi), fi.ModTime().UTC()
	} else {
		file.Path = path
	}
	return file, s
}

func dockerConfigOf(s dockerapi.Settings, file *dockerConfigFile) dockerConfig {
	return dockerConfig{
		File:               file,
		UserlandProxy:      s.UserlandProxy,
		IPTables:           s.IPTables,
		IP6Tables:          s.IP6Tables,
		FirewallBackend:    checked(s.FirewallBackend, dockerBackendRe.MatchString),
		AllowDirectRouting: s.AllowDirectRouting,
		ICC:                s.ICC,
		NoNewPrivileges:    s.NoNewPrivileges,
		LiveRestore:        s.LiveRestore,
		TLS:                s.TLS,
		TLSVerify:          s.TLSVerify,
		DefaultBindIP:      checked(s.DefaultBindIP, isIPAddr),
		UsernsRemap:        s.UsernsRemap != nil && *s.UsernsRemap != "",
	}
}

func isIPAddr(v string) bool { return net.ParseIP(v) != nil }

// dockerHosts are the addresses dockerd listens on, as dockerd picks them:
// -H, else hosts of daemon.json, else the default; fd:// takes the sockets
// of docker.socket. socket is the first unix socket, the one to talk to.
func dockerHosts(sc *scanCtx, flags, file, s dockerapi.Settings) (hosts []dockerHost, socket string) {
	raw, source := flags.Hosts, hostFromCmdline
	if raw == nil {
		raw, source = file.Hosts, hostFromConfig
	}
	var parsed []dockerapi.Host
	if raw == nil {
		parsed, source = dockerapi.DefaultHosts(isTrue(s.TLS) || isTrue(s.TLSVerify)), hostFromDefault
	}
	hosts = []dockerHost{}
	add := func(h dockerapi.Host, src string) {
		hosts = append(hosts, dockerHost{Proto: h.Proto, Addr: h.Addr, Source: src})
		if socket == "" && h.Proto == dockerapi.ProtoUnix && strings.HasPrefix(h.Addr, "/") {
			socket = h.Addr
		}
	}
	for _, r := range raw {
		h, err := dockerapi.ParseHost(r)
		if err != nil {
			hosts = append(hosts, dockerHost{Proto: valueInvalid, Source: source})
			continue
		}
		parsed = append(parsed, h)
	}
	for _, h := range parsed {
		add(h, source)
		if h.Proto != dockerapi.ProtoFD {
			continue
		}
		listens := socketUnitListens(sc)
		for _, l := range listens {
			add(l, hostFromSocketUnit)
		}
		if len(listens) == 0 { // no docker.socket found: its stock path
			add(dockerapi.Host{Proto: dockerapi.ProtoUnix, Addr: dockerStockSocket}, hostFromDefault)
		}
	}
	return hosts, socket
}

func isTrue(b *bool) bool { return b != nil && *b }

// socketUnitListens are the ListenStream= of docker.socket with its
// drop-ins; an empty ListenStream= resets the list, as systemd does.
func socketUnitListens(sc *scanCtx) []dockerapi.Host {
	var out []dockerapi.Host
	for _, line := range unitLines(sc, dockerSocketUnit) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(k) != "ListenStream" {
			continue
		}
		if v = strings.TrimSpace(v); v == "" {
			out = nil
			continue
		}
		if h, err := dockerapi.ListenStreamHost(v); err == nil {
			out = append(out, h)
		}
	}
	return out
}

// readAPI reads the version, the firewall backend and the published ports
// from dockerd, within dockerAPIBudget. A failed request is a gap on the
// socket; what came before it is kept.
func (d *dockerData) readAPI(ctx context.Context, sc *scanCtx, socket string, gaps *gapList) {
	ctx, cancel := context.WithTimeout(ctx, dockerAPIBudget)
	defer cancel()
	c := sc.newDockerClient(sc.root + socket)
	api, err := c.Ping(ctx)
	if err != nil {
		gaps.add(socket, dockerErr(err))
		return
	}
	d.APIVersion = checked(nonEmpty(api), dockerVersionRe.MatchString)
	info, err := c.Info(ctx)
	if err != nil {
		gaps.add(socket, dockerErr(err))
		return
	}
	d.Version = checked(nonEmpty(info.ServerVersion), dockerVersionRe.MatchString)
	d.FirewallBackend = checked(nonEmpty(info.FirewallBackend), dockerWordRe.MatchString)
	d.SecurityOptions = make([]string, 0, len(info.SecurityOptions))
	for _, o := range info.SecurityOptions {
		d.SecurityOptions = append(d.SecurityOptions, *checked(&o, dockerWordRe.MatchString))
	}
	d.ContainersRunning = info.ContainersRunning
	list, _, err := c.Containers(ctx)
	if err != nil {
		gaps.add(socket, dockerErr(err))
		return
	}
	d.Published, d.PublishedTruncated = publishedPorts(list)
}

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

// publishedPorts lists the ports bound on the host, sorted, at most
// maxPublished.
func publishedPorts(list []dockerapi.Container) ([]dockerPort, bool) {
	out := []dockerPort{}
	for _, c := range list {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		if !dockerNameRe.MatchString(name) {
			name = valueInvalid
		}
		for _, p := range c.Ports {
			if p.PublicPort < 1 || p.PublicPort > 65535 {
				continue // exposed, not published
			}
			out = append(out, dockerPort{Container: name, IP: portIP(p.IP), PublicPort: p.PublicPort,
				PrivatePort: p.PrivatePort, Type: *checked(&p.Type, dockerProtocolsRe.MatchString)})
		}
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
