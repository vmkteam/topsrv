package security

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strconv"
	"strings"
)

const (
	modulesLimit  = 1 << 20 // /proc/modules: a few hundred lines
	profilesLimit = 8 << 20 // apparmor profiles: thousands on LXD hosts
)

// CPU vulnerability classes.
const (
	vulnVulnerable   = "vulnerable"
	vulnMitigatedSMT = "mitigated_smt_vulnerable"
	vulnMitigated    = "mitigated"
	vulnNotAffected  = "not_affected"
	vulnUnknown      = valueUnknown
)

type kernelData struct {
	Taint              *taint             `json:"taint"`
	Modules            []module           `json:"modules"`
	HiddenModules      []string           `json:"hiddenModules"`
	CPUVulnerabilities map[string]cpuVuln `json:"cpuVulnerabilities"`
	LSM                lsm                `json:"lsm"`
	Livepatch          []livepatch        `json:"livepatch,omitempty"`
	Time               *timeSync          `json:"time,omitempty"`
	Cmdline            map[string]string  `json:"cmdline"`
}

type taint struct {
	Value uint64   `json:"value"`
	Flags []string `json:"flags"`
}

type module struct {
	Name  string `json:"name"`
	Taint string `json:"taint,omitempty"`
}

type cpuVuln struct {
	Raw   string `json:"raw"`
	Class string `json:"class"`
}

// lsm: nil fields and "unknown" mean the source was unreadable, never
// "none".
type lsm struct {
	Active   []string  `json:"active"`
	Lockdown string    `json:"lockdown,omitempty"`
	AppArmor *appArmor `json:"apparmor,omitempty"` // nil: not built into the kernel
	SELinux  string    `json:"selinux"`            // enforcing|permissive|disabled|unknown
}

type appArmor struct {
	Enabled                bool           `json:"enabled"`
	Profiles               map[string]int `json:"profiles"` // mode → count in the root namespace; null when unreadable
	ChildNamespaceProfiles int            `json:"childNamespaceProfiles"`
}

type livepatch struct {
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Transition bool   `json:"transition"` // stuck if it stays set
}

// timeSync is the kernel clock state from adjtimex. A false unsync follows
// any settimeofday (ntpdate, VMware Tools, Hyper-V IC), so the backend has to
// weigh MaxErrorUs, not the flag alone.
type timeSync struct {
	Unsync     bool  `json:"unsync"`
	ClockErr   bool  `json:"clockErr"`
	MaxErrorUs int64 `json:"maxErrorUs"`
	OffsetUs   int64 `json:"offsetUs"`
}

// cmdlineKeys are the only /proc/cmdline tokens reported: the line itself
// may carry passwords (iscsi and the like).
var cmdlineKeys = []string{"mitigations", "lockdown", "apparmor", "selinux", "security", "module.sig_enforce"}

// taintLetters by bit, from Documentation/admin-guide/tainted-kernels.rst.
var taintLetters = strings.Split("PFSRMBUDAWCIOELKXTNJ", "")

func collectKernel(_ context.Context, sc *scanCtx) Section {
	var (
		d    kernelData
		gaps gapList
		err  error
	)
	d.Taint, err = readTaint(sc)
	gaps.add("/proc/sys/kernel/tainted", err)

	d.Modules, err = readModules(sc)
	gaps.optional("/proc/modules", err) // absent without CONFIG_MODULES
	if err == nil {
		// Without the loaded list every module would look hidden.
		d.HiddenModules, err = hiddenModules(sc, d.Modules)
		gaps.add("/sys/module", err)
	}

	d.CPUVulnerabilities, err = readVulnerabilities(sc)
	gaps.add("/sys/devices/system/cpu/vulnerabilities", err)

	d.LSM = readLSM(sc, &gaps)
	d.Livepatch, err = readLivepatch(sc)
	gaps.optional("/sys/kernel/livepatch", err)

	if sc.timeSync != nil {
		d.Time, err = sc.timeSync()
		gaps.add("adjtimex", err)
	}

	d.Cmdline, err = readCmdline(sc)
	gaps.add("/proc/cmdline", err)
	return collected(gaps, d)
}

func readTaint(sc *scanCtx) (*taint, error) {
	b, err := sc.read("/proc/sys/kernel/tainted", smallFileLimit)
	if err != nil {
		return nil, err
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return nil, errParse
	}
	return &taint{Value: v, Flags: bitNames(v, taintLetters, "bit")}, nil
}

// readModules parses /proc/modules: name size refs deps state addr [(taint)].
func readModules(sc *scanCtx) ([]module, error) {
	b, err := sc.read("/proc/modules", modulesLimit)
	if err != nil {
		return nil, err
	}
	out := []module{}
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		m := module{Name: f[0]}
		if len(f) >= 7 {
			m.Taint = strings.Trim(f[6], "()")
		}
		out = append(out, m)
	}
	return out, nil
}

// hiddenModules lists loadable modules (those with /sys/module/X/initstate)
// missing from /proc/modules — how a rootkit like Diamorphine hides. A
// module loading or unloading between the two reads looks the same, so
// candidates are confirmed by reading both again. nil means not checked.
func hiddenModules(sc *scanCtx, loaded []module) ([]string, error) {
	cand, err := sysModulesNotIn(sc, loaded)
	if err != nil {
		return nil, err
	}
	if len(cand) == 0 {
		return []string{}, nil
	}
	loaded, err = readModules(sc)
	if err != nil {
		return nil, err
	}
	again, err := sysModulesNotIn(sc, loaded)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, m := range cand {
		if slices.Contains(again, m) {
			out = append(out, m)
		}
	}
	return out, nil
}

func sysModulesNotIn(sc *scanCtx, loaded []module) ([]string, error) {
	entries, err := sc.readDir("/sys/module")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if slices.ContainsFunc(loaded, func(m module) bool { return m.Name == name }) {
			continue
		}
		if sc.exists("/sys/module/" + name + "/initstate") {
			out = append(out, name)
		}
	}
	return out, nil
}

func readVulnerabilities(sc *scanCtx) (map[string]cpuVuln, error) {
	const dir = "/sys/devices/system/cpu/vulnerabilities/"
	entries, err := sc.readDir(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]cpuVuln, len(entries))
	for _, e := range entries {
		b, err := sc.read(dir+e.Name(), smallFileLimit)
		if err != nil {
			return nil, err
		}
		raw := strings.TrimSpace(string(b))
		out[e.Name()] = cpuVuln{Raw: raw, Class: vulnClass(raw)}
	}
	return out, nil
}

// vulnClass classifies a vulnerabilities/* line. The raw line is reported as
// well: parsers that keep only the class lose "SMT vulnerable" and the
// "KVM:" lines. A mitigation with a part still open ("...; BHI: Vulnerable")
// is vulnerable.
func vulnClass(raw string) string {
	switch {
	case raw == "Not affected":
		return vulnNotAffected
	case strings.HasPrefix(raw, "Vulnerable"), strings.HasPrefix(raw, "Processor vulnerable"),
		strings.Contains(raw, ": Vulnerable"):
		return vulnVulnerable
	case strings.Contains(raw, "Mitigation"):
		if strings.Contains(raw, "SMT vulnerable") {
			return vulnMitigatedSMT
		}
		return vulnMitigated
	}
	return vulnUnknown
}

func readLSM(sc *scanCtx, gaps *gapList) lsm {
	var l lsm
	if b, err := sc.read("/sys/kernel/security/lsm", smallFileLimit); err == nil {
		l.Active = strings.Split(strings.TrimSpace(string(b)), ",")
	} else {
		gaps.add("/sys/kernel/security/lsm", err) // securityfs not mounted: the LSM set is unknown
	}

	b, err := sc.read("/sys/kernel/security/lockdown", smallFileLimit)
	gaps.optional("/sys/kernel/security/lockdown", err) // since 5.4
	if _, rest, found := strings.Cut(string(b), "["); found {
		l.Lockdown, _, _ = strings.Cut(rest, "]")
	}
	l.AppArmor = readAppArmor(sc, gaps)
	l.SELinux = readSELinux(sc, l.Active, gaps)
	return l
}

// readAppArmor: nil when AppArmor is not built in. With AppArmor enabled
// and the profile list unreadable (securityfs absent in a container,
// EACCES) the counts are null, not zero.
func readAppArmor(sc *scanCtx, gaps *gapList) *appArmor {
	const profilesPath = "/sys/kernel/security/apparmor/profiles"
	b, err := sc.read("/sys/module/apparmor/parameters/enabled", smallFileLimit)
	if err != nil {
		gaps.optional("/sys/module/apparmor/parameters/enabled", err)
		return nil
	}
	a := &appArmor{Enabled: strings.TrimSpace(string(b)) == "Y"}
	if !a.Enabled {
		return a
	}
	profiles, err := sc.read(profilesPath, profilesLimit)
	if err != nil {
		gaps.add(profilesPath, err)
		return a
	}
	a.Profiles = map[string]int{}
	countProfiles(a, profiles)
	return a
}

// readSELinux reports disabled only when the active LSM list is known and
// lacks selinux: a container often has no selinuxfs on an enforcing host.
func readSELinux(sc *scanCtx, active []string, gaps *gapList) string {
	const enforcePath = "/sys/fs/selinux/enforce"
	b, err := sc.read(enforcePath, smallFileLimit)
	switch {
	case err == nil && strings.TrimSpace(string(b)) == "1":
		return "enforcing"
	case err == nil:
		return "permissive"
	case errors.Is(err, fs.ErrNotExist) && active != nil && !slices.Contains(active, "selinux"):
		return "disabled"
	case !errors.Is(err, fs.ErrNotExist) || active != nil:
		gaps.add(enforcePath, err) // selinux is active, or the file is there but unreadable
	}
	return valueUnknown
}

// countProfiles counts profiles by mode. Lines of child namespaces (LXD
// containers) start with ":ns:" and are counted apart; names are not
// reported.
func countProfiles(a *appArmor, profiles []byte) {
	for line := range strings.SplitSeq(string(profiles), "\n") {
		open := strings.LastIndexByte(line, '(')
		if open < 0 || !strings.HasSuffix(line, ")") {
			continue
		}
		if strings.HasPrefix(line, ":") {
			a.ChildNamespaceProfiles++
			continue
		}
		a.Profiles[line[open+1:len(line)-1]]++
	}
}

func readLivepatch(sc *scanCtx) ([]livepatch, error) {
	const dir = "/sys/kernel/livepatch/"
	entries, err := sc.readDir(dir)
	if err != nil {
		return nil, err
	}
	var out []livepatch
	for _, e := range entries {
		lp := livepatch{Name: e.Name()}
		enabled, err1 := sc.read(dir+e.Name()+"/enabled", smallFileLimit)
		transition, err2 := sc.read(dir+e.Name()+"/transition", smallFileLimit)
		if err1 != nil || err2 != nil {
			continue // removed while listing
		}
		lp.Enabled = strings.TrimSpace(string(enabled)) == "1"
		lp.Transition = strings.TrimSpace(string(transition)) == "1"
		out = append(out, lp)
	}
	return out, nil
}

func readCmdline(sc *scanCtx) (map[string]string, error) {
	b, err := sc.read("/proc/cmdline", smallFileLimit)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for tok := range strings.FieldsSeq(string(b)) {
		if k, v, found := strings.Cut(tok, "="); found && slices.Contains(cmdlineKeys, k) {
			out[k] = v
		}
	}
	return out, nil
}
