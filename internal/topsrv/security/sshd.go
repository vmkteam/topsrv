package security

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/security/sshdconf"
)

// sshdFileLimit is sshd's own limit of a configuration file.
const sshdFileLimit = 1 << 20

// procStatLimit caps /proc/stat: a line per CPU.
const procStatLimit = 1 << 20

// sshdEffectiveKeys are the keywords sent: what posture rules need.
var sshdEffectiveKeys = []string{
	"PermitRootLogin", "PasswordAuthentication", "KbdInteractiveAuthentication", "PermitEmptyPasswords",
	"PubkeyAuthentication", "AuthenticationMethods", "UsePAM", "MaxAuthTries", "LoginGraceTime",
	"Port", "ListenAddress", "AddressFamily", "AllowUsers", "DenyUsers", "AllowGroups", "DenyGroups",
	"AuthorizedKeysFile", "AuthorizedKeysCommand", "AuthorizedKeysCommandUser", "TrustedUserCAKeys",
	"StrictModes", "PermitUserEnvironment", "HostbasedAuthentication", "IgnoreRhosts",
	"GSSAPIAuthentication", "X11Forwarding", "AllowTcpForwarding", "AllowAgentForwarding", "PermitTunnel",
	"GatewayPorts", "Ciphers", "MACs", "KexAlgorithms", "HostKeyAlgorithms", "PubkeyAcceptedAlgorithms",
	"LogLevel", "ClientAliveInterval", "ClientAliveCountMax", "MaxSessions", "MaxStartups", "Banner",
	// CIS and STIG checks beyond the above
	"DisableForwarding", "PermitTTY", "PermitUserRC", "AllowStreamLocalForwarding", "X11UseLocalhost",
	"Compression", "KerberosAuthentication", "IgnoreUserKnownHosts", "PrintLastLog", "UseDNS",
	"RequiredRSASize", "ForceCommand",
}

// sshdListKeys are sent as arrays, the rest as strings.
var sshdListKeys = []string{
	"Port", "ListenAddress", "AllowUsers", "DenyUsers", "AllowGroups", "DenyGroups",
	"AuthorizedKeysFile", "AuthenticationMethods",
}

// sshdPresenceKeys are sent as true/false: a command line or a path, of
// which only whether it is set matters ("none" is unset).
var sshdPresenceKeys = []string{"AuthorizedKeysCommand", "TrustedUserCAKeys", "Banner", "ForceCommand"}

// defaultHostKeys are the host keys sshd loads without a HostKey line
// (fill_default_server_options), those that exist.
var defaultHostKeys = []string{"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key"}

// sshdUnits are the service units sshd runs as, Debian and RHEL names.
var sshdUnits = []string{"ssh.service", "sshd.service"}

// sshdBinaries may hold the PAM code: sshd-session since OpenSSH 9.8,
// sshd-auth since 10.0.
var sshdBinaries = []string{
	"/usr/sbin/sshd",
	"/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session", "/usr/lib/ssh/sshd-session",
	"/usr/lib/openssh/sshd-auth", "/usr/libexec/openssh/sshd-auth", "/usr/lib/ssh/sshd-auth",
}

// sshdData is the sshd section. Defaults are not filled in: a keyword not
// set is "unset", the backend knows the default of the installed version.
type sshdData struct {
	ConfigFile      string               `json:"configFile"`
	ConfigValid     bool                 `json:"configValid"`
	Effective       map[string]sshdValue `json:"effective"`
	MatchBlocks     []sshdMatch          `json:"matchBlocks"`
	Files           []sshdFile           `json:"files"`
	UnknownKeywords []lineRef            `json:"unknownKeywords"`
	ParseErrors     []lineRef            `json:"parseErrors"`
	Listener        sshdListener         `json:"listener"`
	SocketActivated bool                 `json:"socketActivated"`
	// PAMCompiled: the sshd binaries link libpam. Without it UsePAM does
	// nothing and a "*" password is not a lock. null when unreadable.
	PAMCompiled *bool `json:"pamCompiled"`
	// HostKeys are the private host key files, by HostKey or the defaults:
	// owner and mode only.
	HostKeys []fileMeta `json:"hostKeys"`
}

// sshdValue is a keyword's value — a string, an array for list keywords,
// true/false for presence keywords, null when unset — and its source:
// "file:line", "cmdline" or "unset".
type sshdValue struct {
	Value  any    `json:"value"`
	Source string `json:"source"`
}

type sshdMatch struct {
	Criteria []string `json:"criteria"`
	Source   string   `json:"source"`
	// Evaluable: only User and Group criteria, which the backend can match
	// with accounts; Address and Host depend on the connection.
	Evaluable bool                 `json:"evaluable"`
	Keys      map[string]sshdValue `json:"keys"`
	// EqualsSyntax: written criterion=pattern (criteria come split into
	// pairs either way), which only OpenSSH 10.0+ accepts: older sshd exits.
	EqualsSyntax bool `json:"equalsSyntax,omitempty"`
}

type sshdFile struct {
	fileMeta
	SHA256 string    `json:"sha256"`
	MTime  time.Time `json:"mtime"`
}

type sshdListener struct {
	Found bool `json:"found"`
	// FlagsFromCmdline: -f, -o and -p came from the running listener, not
	// from the unit file.
	FlagsFromCmdline bool `json:"flagsFromCmdline"`
	// StartedAt: sshd reads its configuration at start and on SIGHUP, so a
	// file newer than this may not be in force.
	StartedAt *time.Time `json:"startedAt"`
}

// sshdResult is what authorizedKeys builds on.
type sshdResult struct {
	authorizedKeysFiles []string            // global, with the default when unset
	userKeysFiles       map[string][]string // AuthorizedKeysFile of "Match User x" blocks, by user
	strictModes         bool
	keysCommand         bool
	trustedCA           bool
}

// defaultAuthorizedKeysFiles is AuthorizedKeysFile when unset.
var defaultAuthorizedKeysFiles = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}

func collectSSHD(_ context.Context, sc *scanCtx) (Section, any) {
	var gaps gapList
	flags, listener := sshdFlags(sc, &gaps)
	socket := sshdSocketActivated(sc)
	if !listener.Found && !socket && !sc.exists(flags.ConfigFile) && !sc.exists("/usr/sbin/sshd") {
		return Section{Status: StatusNA}, nil
	}

	hashes := map[string]string{}
	files := sshdconf.Files{
		ReadFile: func(p string) ([]byte, error) {
			b, err := sc.read(p, sshdFileLimit)
			if err == nil {
				sum := sha256.Sum256(b)
				hashes[p] = hex.EncodeToString(sum[:])
			}
			return b, err
		},
		ReadDir: sc.readDirNames,
	}
	cfg := sshdconf.Parse(flags, files)
	for _, re := range cfg.ReadErrors {
		if re.Path == flags.ConfigFile {
			return unknown(reasonOf(re.Err)), nil
		}
		gaps.add(re.Path, re.Err)
	}

	d := sshdData{
		ConfigFile:      flags.ConfigFile,
		ConfigValid:     cfg.Valid(),
		Effective:       sshdValues(cfg.Global, true),
		MatchBlocks:     sshdMatches(cfg.MatchBlocks),
		UnknownKeywords: lineRefs(cfg.Unknown),
		ParseErrors:     lineRefs(cfg.Errors),
		Listener:        listener,
		SocketActivated: socket,
		PAMCompiled:     sshdPAMCompiled(sc),
		HostKeys:        filesMeta(sc, sshdHostKeys(cfg)),
	}
	for _, p := range cfg.Files {
		if m, err := sshdFileMeta(sc, p, hashes[p]); err == nil {
			d.Files = append(d.Files, m)
		}
	}
	return collected(gaps, d), sshdResultOf(cfg)
}

// sshdHostKeys are the HostKey files of the configuration, or the defaults.
func sshdHostKeys(cfg *sshdconf.Config) []string {
	if v, ok := cfg.Global["HostKey"]; ok {
		return v.Values
	}
	return defaultHostKeys
}

// sshdFlags finds the -f, -o and -p in force: from the running listener in
// the host mount namespace, or else from the service unit.
func sshdFlags(sc *scanCtx, gaps *gapList) (sshdconf.Flags, sshdListener) {
	procs, err := sc.processes()
	gaps.add("/proc", err)
	hostMnt, _ := sc.readlink("/proc/1/ns/mnt")
	for _, p := range procs {
		if p.name != "sshd" || !trustedListener(sc, p) {
			continue
		}
		if mnt, err := sc.readlink("/proc/" + p.pid + "/ns/mnt"); err == nil && hostMnt != "" && mnt != hostMnt {
			continue // sshd in a container reads its own /etc/ssh
		}
		head, err := sc.readHead("/proc/"+p.pid+"/cmdline", argv0Limit)
		if err != nil {
			continue
		}
		args, ok := sshdconf.ListenerArgs(head)
		if !ok {
			continue
		}
		l := sshdListener{Found: true, FlagsFromCmdline: true, StartedAt: processStart(sc, p.pid)}
		return sshdconf.ParseFlags(args), l
	}
	return sshdconf.ParseFlags(sshdUnitArgs(sc)), sshdListener{}
}

// trustedListener: a process named sshd that runs as root from a binary
// only root can change. Any user can start ~/bin/sshd -f ~/evil, whose -f
// and Include would otherwise make the agent read files of its choosing.
func trustedListener(sc *scanCtx, p process) bool {
	proc, err := sc.stat("/proc/" + p.pid)
	if err != nil {
		return false
	}
	if uid, _ := fileOwner(proc); uid != sc.trustedUID || p.exe == "" {
		return false
	}
	exe, err := sc.stat(p.exe)
	if err != nil {
		return false
	}
	uid, _ := fileOwner(exe)
	return uid == sc.trustedUID && exe.Mode().Perm()&0o022 == 0
}

// sshdUnitArgs reads the sshd arguments from the service unit (with its
// drop-ins and EnvironmentFile), or from OpenRC's conf.d on Alpine.
func sshdUnitArgs(sc *scanCtx) []string {
	for _, unit := range sshdUnits {
		lines := unitLines(sc, unit)
		if lines == nil {
			continue
		}
		var exec string
		env := map[string]string{}
		for _, l := range lines {
			switch k, v, _ := strings.Cut(l, "="); strings.TrimSpace(k) {
			case "ExecStart":
				exec = strings.TrimLeft(strings.TrimSpace(v), "-@+!:") // "ExecStart=" alone resets
			case "EnvironmentFile":
				for f := range strings.FieldsSeq(v) {
					readEnvFile(sc, strings.TrimPrefix(f, "-"), env)
				}
			}
		}
		if f := strings.Fields(expandEnv(exec, env)); len(f) > 0 {
			return f[1:]
		}
	}
	env := map[string]string{}
	readEnvFile(sc, "/etc/conf.d/sshd", env)
	args := strings.Fields(env["SSHD_OPTS"])
	if cfg := env["SSHD_CONFIG"]; cfg != "" {
		args = append(args, "-f", cfg)
	}
	return args
}

// readEnvFile adds the KEY=value lines of an environment file to env.
func readEnvFile(sc *scanCtx, file string, env map[string]string) {
	b, err := sc.read(file, smallFileLimit)
	if err != nil {
		return
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		env[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
}

// expandEnv replaces $VAR and ${VAR} as systemd does in ExecStart.
func expandEnv(s string, env map[string]string) string {
	return os.Expand(s, func(k string) string { return env[k] })
}

// sshdSocketActivated: ssh.socket is enabled (Ubuntu 24.04): the service
// starts on the first connection, and there may be no listener until then.
func sshdSocketActivated(sc *scanCtx) bool {
	return sc.exists("/etc/systemd/system/sockets.target.wants/ssh.socket") ||
		sc.exists("/etc/systemd/system/sockets.target.wants/sshd.socket")
}

// processStart is when a process started: field 22 of /proc/PID/stat, in
// clock ticks since boot (USER_HZ, 100 on Linux), plus btime of /proc/stat.
func processStart(sc *scanCtx, pid string) *time.Time {
	stat, err := sc.read("/proc/"+pid+"/stat", smallFileLimit)
	if err != nil {
		return nil
	}
	_, after, ok := bytes.CutLast(stat, []byte(")")) // comm may hold spaces and parentheses
	f := strings.Fields(string(after))
	if !ok || len(f) < 20 {
		return nil
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil {
		return nil
	}
	b, err := sc.read("/proc/stat", procStatLimit)
	if err != nil {
		return nil
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			btime, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return nil
			}
			t := time.Unix(btime+ticks/100, 0).UTC()
			return &t
		}
	}
	return nil
}

// sshdPAMCompiled looks for libpam among the libraries the sshd binaries
// import (ELF DT_NEEDED): Alpine ships openssh-server without PAM, the -pam
// variant with it. Only the dynamic section is read, not the binary.
func sshdPAMCompiled(sc *scanCtx) *bool {
	var read, unreadable bool
	for _, bin := range sshdBinaries {
		libs, err := importedLibraries(sc, bin)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			unreadable = true // PAM may be just there: not "no"
			continue
		}
		read = true
		if slices.ContainsFunc(libs, func(l string) bool { return strings.HasPrefix(l, "libpam.so") }) {
			found := true
			return &found
		}
	}
	if !read || unreadable {
		return nil
	}
	found := false
	return &found
}

// importedLibraries reads DT_NEEDED of an ELF binary, opened as any other
// file: regular only, no FIFO or device.
func importedLibraries(sc *scanCtx, bin string) ([]string, error) {
	if err := sc.local(bin); err != nil {
		return nil, err
	}
	f, err := openFile(sc.root+bin, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	e, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}
	return e.ImportedLibraries()
}

func sshdFileMeta(sc *scanCtx, p, sum string) (sshdFile, error) {
	fi, err := sc.stat(p)
	if err != nil {
		return sshdFile{}, err
	}
	return sshdFile{fileMeta: metaOf(p, fi), SHA256: sum, MTime: fi.ModTime().UTC()}, nil
}

// sshdValues converts parsed values to the wire form; with all, every key of
// sshdEffectiveKeys is present, "unset" when not set.
func sshdValues(vals map[string]sshdconf.Value, all bool) map[string]sshdValue {
	out := map[string]sshdValue{}
	for _, k := range sshdEffectiveKeys {
		v, ok := vals[k]
		switch {
		case !ok && all:
			out[k] = sshdValue{Value: nil, Source: "unset"}
		case !ok:
		case slices.Contains(sshdPresenceKeys, k):
			out[k] = sshdValue{Value: !strings.EqualFold(v.Values[0], "none"), Source: v.Source}
		case slices.Contains(sshdListKeys, k):
			out[k] = sshdValue{Value: v.Values, Source: v.Source}
		default:
			out[k] = sshdValue{Value: v.Values[0], Source: v.Source}
		}
	}
	return out
}

func sshdMatches(blocks []*sshdconf.MatchBlock) []sshdMatch {
	out := make([]sshdMatch, 0, len(blocks))
	for _, b := range blocks {
		evaluable := len(b.Criteria)%2 == 0
		for i := 0; i < len(b.Criteria); i += 2 {
			if c := strings.ToLower(b.Criteria[i]); c != "user" && c != "group" {
				evaluable = false
			}
		}
		out = append(out, sshdMatch{Criteria: b.Criteria, Source: b.Source, Evaluable: evaluable, Keys: sshdValues(b.Keys, false),
			EqualsSyntax: b.EqualsSyntax})
	}
	return out
}

// maxLineRefs caps a list of refused or unknown lines: a large file of junk
// would otherwise fill the snapshot past what the receiving side accepts.
const maxLineRefs = 100

func lineRefs(refs []sshdconf.Ref) []lineRef {
	out := make([]lineRef, 0, min(len(refs), maxLineRefs))
	for _, r := range refs[:min(len(refs), maxLineRefs)] {
		out = append(out, lineRef(r))
	}
	return out
}

func sshdResultOf(cfg *sshdconf.Config) *sshdResult {
	r := &sshdResult{authorizedKeysFiles: defaultAuthorizedKeysFiles, strictModes: true, userKeysFiles: map[string][]string{}}
	g := cfg.Global
	if v, ok := g["AuthorizedKeysFile"]; ok {
		r.authorizedKeysFiles = v.Values
	}
	if v, ok := g["StrictModes"]; ok {
		r.strictModes = v.Values[0] != "no"
	}
	r.keysCommand = isSetNotNone(g, "AuthorizedKeysCommand")
	r.trustedCA = isSetNotNone(g, "TrustedUserCAKeys")
	for _, b := range cfg.MatchBlocks {
		v, ok := b.Keys["AuthorizedKeysFile"]
		if !ok || len(b.Criteria) != 2 || !strings.EqualFold(b.Criteria[0], "user") {
			continue
		}
		for u := range strings.SplitSeq(b.Criteria[1], ",") {
			if _, seen := r.userKeysFiles[u]; !seen && !strings.ContainsAny(u, "*?!") {
				r.userKeysFiles[u] = v.Values
			}
		}
	}
	return r
}

func isSetNotNone(vals map[string]sshdconf.Value, k string) bool {
	v, ok := vals[k]
	return ok && !strings.EqualFold(v.Values[0], "none")
}
