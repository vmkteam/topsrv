package security

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/nftables"
)

// Limits of the firewall section.
const (
	// firewallBudget: a read takes milliseconds; each reply waits at most
	// 2 s (the socket's receive timeout).
	firewallBudget        = 5 * time.Second
	maxFirewallTables     = 256
	maxFirewallBaseChains = 256
	maxDockerUser         = 16
	modulesBuiltinLimit   = 4 << 20
	netlinkDumpFile       = "nftables.json"
)

// Values of firewallData.FirewallView.
const (
	viewFull    = "full"
	viewPartial = "partial" // an eBPF dataplane filters too, out of sight of nftables
)

// Forms of what the ruleset and the configs hold: anything else is sent as
// "invalid".
var (
	nftNameRe     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./:-]{0,127}$`) // what nft takes unquoted, and iptables chains
	ifaceNameRe   = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,15}$`)
	chainTypeRe   = regexp.MustCompile(`^(filter|nat|route)$`)
	ufwPolicyRe   = regexp.MustCompile(`^(drop|reject|accept)$`)
	ufwLineRe     = regexp.MustCompile(`^\w+="?[\w-]+"?`) // the lines ufw's Python reads
	fwBackendRe   = regexp.MustCompile(`^(nftables|iptables)$`)
	fwZoneRe      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+-]{0,63}$`)
	legacyTableRe = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
)

// ebpfDataplanes filter in eBPF (tc, XDP, cgroup hooks), which the ruleset
// does not show. Role processes, not CI runners: roleProcessesRunning lists
// those in PID 1's network namespace only.
var ebpfDataplanes = []string{"cilium-agent", "calico-node"}

// iptablesTables and iptablesChains are what iptables-nft creates: a table
// of these names with a base chain of these names is its.
var (
	iptablesTables = []string{"filter", "nat", "mangle", "raw", "security"}
	iptablesChains = []string{"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"}
)

// Owners named in more than one place.
const (
	ownerCrowdsec  = "crowdsec"
	ownerKubeProxy = "kube-proxy"
	ownerUFW       = "ufw"
	ownerNetavark  = "netavark"
	ownerLibvirt   = "libvirt"
	ownerFail2ban  = "fail2ban"
	ownerLXD       = "lxd"
)

// ufwYes is how ufw's scripts spell yes.
const ufwYes = "yes"

// Who made a table is guessed by its name, and by the prefixes of its
// chains (iptables-nft tables are shared). A name proves nothing, anyone may
// take it: a hint only.
var (
	// ownerTables are named after their owner.
	ownerTables = []string{"firewalld", ownerKubeProxy, ownerNetavark, ownerCrowdsec, ownerLXD, "incus"}
	// ownerByTable are named otherwise.
	ownerByTable = map[string]string{
		"docker-bridges": dockerEngine, "libvirt_network": ownerLibvirt, "f2b-table": ownerFail2ban, "crowdsec6": ownerCrowdsec,
	}
	ownerByPrefix = []struct{ prefix, owner string }{
		{"ufw-", ownerUFW}, {"ufw6-", ownerUFW}, {"DOCKER", dockerEngine}, {"KUBE-", ownerKubeProxy}, {"cali-", "calico"},
		{"CILIUM_", "cilium"}, {"ts-", "tailscale"}, {"f2b-", ownerFail2ban}, {"LIBVIRT_", ownerLibvirt},
		{"NETAVARK", ownerNetavark}, {"CROWDSEC", ownerCrowdsec},
	}
)

// firewallData is the firewall section: the nftables ruleset in outline,
// and the firewalls that manage it.
type firewallData struct {
	// NFTLoaded: nf_tables is loaded or built in. false — nothing was asked:
	// the first request would load the module.
	NFTLoaded bool `json:"nftLoaded"`
	// The generation of the ruleset is not sent: it moves with every
	// change, the outline below often does not.
	Tables              []fwTable    `json:"tables"`
	TablesTruncated     bool         `json:"tablesTruncated,omitempty"`
	BaseChains          []fwChain    `json:"baseChains"`
	BaseChainsTruncated bool         `json:"baseChainsTruncated,omitempty"`
	DockerUser          []fwChain    `json:"dockerUser"`
	DockerUserTruncated bool         `json:"dockerUserTruncated,omitempty"`
	LegacyTablesPresent bool         `json:"legacyTablesPresent"`
	UFW                 *fwUFW       `json:"ufw"`
	Firewalld           *fwFirewalld `json:"firewalld"`
	// FirewallView: full, or partial when an eBPF dataplane filters too.
	FirewallView string `json:"firewallView"`
}

type fwTable struct {
	Family     string   `json:"family"`
	Name       string   `json:"name"`
	Dormant    bool     `json:"dormant"` // off: its chains see no packets
	OwnerGuess []string `json:"ownerGuess"`
}

// fwChain is a base chain, or a DOCKER-USER chain (no hook).
type fwChain struct {
	Family   string   `json:"family"`
	Table    string   `json:"table"`
	Name     string   `json:"name"`
	Type     string   `json:"type,omitempty"`
	Hook     string   `json:"hook,omitempty"`
	Priority *int32   `json:"priority,omitempty"`
	Policy   string   `json:"policy,omitempty"`
	Devices  []string `json:"devices,omitempty"`
	// RulesCount and Terminal are set for the chains of inbound traffic:
	// filter on input, forward and ingress. Terminal is what happens to a
	// packet at the end of the chain: drop, reject, accept, queue,
	// jump:CHAIN past the depth followed, or unknown.
	RulesCount *int    `json:"rulesCount"`
	Terminal   *string `json:"terminal,omitempty"`
}

type fwUFW struct {
	// ConfigEnabled: ENABLED=yes in /etc/ufw/ufw.conf, ufw loads its rules
	// at boot. Without its chains in the ruleset (RuntimeRulesV4) they were
	// flushed since, often by nftables.service.
	ConfigEnabled        bool    `json:"configEnabled"`
	ServiceEnabled       *bool   `json:"serviceEnabled"` // null without systemd
	DefaultInputPolicy   *string `json:"defaultInputPolicy"`
	DefaultForwardPolicy *string `json:"defaultForwardPolicy"`
	IPv6                 *bool   `json:"ipv6"`
	// RuntimeRulesV4, V6: the rules of ufw-user-input (ufw6-user-input)
	// loaded — the user's ufw rules; null when the chain is not in the
	// ruleset.
	RuntimeRulesV4 *int `json:"runtimeRulesV4"`
	RuntimeRulesV6 *int `json:"runtimeRulesV6"`
}

type fwFirewalld struct {
	ServiceEnabled *bool   `json:"serviceEnabled"` // null without systemd
	Backend        *string `json:"backend"`        // FirewallBackend; null when not set
	DefaultZone    *string `json:"defaultZone"`
	// RuntimeTablePresent: the inet firewalld table is in the ruleset,
	// firewalld runs with the nftables backend.
	RuntimeTablePresent bool `json:"runtimeTablePresent"`
}

// firewallResult is what the gen trigger starts from: whether nf_tables
// was there (built in: there is no /sys/module entry to look at), the
// generation the section read and the namespace it read it in.
type firewallResult struct {
	loaded, builtin bool
	gen             uint32
	netns           string
}

func collectFirewall(_ context.Context, sc *scanCtx) (Section, any) {
	var gaps gapList
	d := firewallData{FirewallView: firewallView(sc, &gaps), LegacyTablesPresent: legacyTablesPresent(sc, &gaps)}
	res := firewallResult{netns: pid1NetNs(sc)}
	res.loaded, res.builtin = nftLoaded(sc, &gaps)
	var rs *nftables.Ruleset
	if res.loaded {
		var err error
		if rs, err = readRuleset(sc.nftDial, res.netns); err != nil {
			return unknown(firewallReason(err)), nil
		}
		res.gen, d.NFTLoaded = rs.Gen, true
		d.setRuleset(rs)
	}
	d.UFW = readUFW(sc, rs, &gaps)
	d.Firewalld = readFirewalld(sc, rs, &gaps)
	return collected(gaps, d), res
}

// nftLoaded: /sys/module/nf_tables, or nf_tables.ko among the modules built
// into the kernel — a built-in module has no /sys/module entry unless it
// has parameters (OrbStack's kernel). When neither can be told, false with
// a gap: asking would load the module.
func nftLoaded(sc *scanCtx, gaps *gapList) (loaded, builtin bool) {
	if sc.exists("/sys/module/nf_tables") {
		return true, false
	}
	rel, err := sc.read("/proc/sys/kernel/osrelease", smallFileLimit)
	if err != nil {
		gaps.add("/proc/sys/kernel/osrelease", err)
		return false, false
	}
	list := "/lib/modules/" + path.Base(strings.TrimSpace(string(rel))) + "/modules.builtin"
	b, err := sc.read(list, modulesBuiltinLimit)
	if errors.Is(err, fs.ErrNotExist) {
		b, err = sc.read("/usr"+list, modulesBuiltinLimit)
	}
	if err != nil {
		gaps.add(list, err)
		return false, false
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if path.Base(strings.TrimSpace(line)) == "nf_tables.ko" {
			return true, true
		}
	}
	return false, false
}

// pid1NetNs is the namespace the ruleset is read in: PID 1's — "" for the
// agent's own when it shares it.
func pid1NetNs(sc *scanCtx) string {
	if sc.env.NetNsHost {
		return ""
	}
	return "/proc/1/ns/net"
}

func readRuleset(dial nftDialer, netns string) (*nftables.Ruleset, error) {
	conn, err := dial(netns)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return nftables.Read(conn, nftables.Inbound)
}

// nftConn is a connection the ruleset is read through: a socket, or a
// recording in tests.
type nftConn interface {
	nftables.Exchanger
	Close() error
}

// nftDialer opens a connection in a network namespace ("" the agent's).
type nftDialer func(netns string) (nftConn, error)

// socketDialer opens a netlink socket: the dialer of the agent.
func socketDialer(netns string) (nftConn, error) {
	c, err := nftables.Dial(netns)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// recordedConn reads through a Recorder, for -security-dump-netlink.
type recordedConn struct {
	*nftables.Recorder
	conn nftConn
}

func (r recordedConn) Close() error { return r.conn.Close() }

// recordingDialer wraps dial so that the replies of the last connection
// land in rec: the section may outlive its budget, hence the atomic.
func recordingDialer(dial nftDialer, rec *atomic.Pointer[nftables.Recorder]) nftDialer {
	return func(netns string) (nftConn, error) {
		conn, err := dial(netns)
		if err != nil {
			return nil, err
		}
		r := &nftables.Recorder{X: conn}
		rec.Store(r)
		return recordedConn{Recorder: r, conn: conn}, nil
	}
}

// writeNetlinkDump saves the replies of the kernel for -security-dump-netlink:
// they hold the full rules of the chains read, addresses and comments, so
// only the owner reads them. The directory must be one only its owner, the
// agent's user, writes, and the file new: a link put in its place by
// someone else would send the rules elsewhere.
func writeNetlinkDump(dir string, rec *nftables.Recorder) error {
	if rec == nil {
		return errors.New("security: nothing to dump: the firewall section did not ask the kernel " +
			"(not collected, nf_tables not loaded, or no netlink here)")
	}
	b, err := rec.JSON()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if uid, _ := fileOwner(fi); !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 || uid != int64(os.Geteuid()) {
		return fmt.Errorf("security: %s is not a directory of this user that only it writes", dir)
	}
	f, err := os.OpenFile(filepath.Join(dir, netlinkDumpFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // O_EXCL: no link followed, no file reused
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func firewallReason(err error) Reason {
	switch {
	case errors.Is(err, nftables.ErrInconsistent):
		return ReasonDumpInconsistent
	case errors.Is(err, nftables.ErrMalformed):
		return ReasonParseError
	case errors.Is(err, nftables.ErrTooLarge):
		return ReasonBudgetExceeded
	}
	return reasonOf(err)
}

// tableKey names a table: its family and name.
type tableKey struct {
	family nftables.Family
	name   string
}

// setRuleset outlines the ruleset: tables with their owners, base chains
// with the end of the inbound ones, DOCKER-USER chains. The chains are
// walked once: a Kubernetes node has tens of thousands.
func (d *firewallData) setRuleset(rs *nftables.Ruleset) {
	d.Tables, d.BaseChains, d.DockerUser = []fwTable{}, []fwChain{}, []fwChain{}
	owners := map[tableKey]map[string]bool{}
	for _, c := range rs.Chains {
		k := tableKey{c.Family, c.Table}
		if owners[k] == nil {
			owners[k] = map[string]bool{}
		}
		addChainOwners(owners[k], c)
		switch {
		case c.Base && len(d.BaseChains) == maxFirewallBaseChains:
			d.BaseChainsTruncated = true
		case c.Base:
			d.BaseChains = append(d.BaseChains, chainOf(c, rs))
		case c.Name == nftables.DockerUser && len(d.DockerUser) == maxDockerUser:
			d.DockerUserTruncated = true
		case c.Name == nftables.DockerUser:
			d.DockerUser = append(d.DockerUser, chainOf(c, rs))
		}
	}
	for _, t := range rs.Tables {
		if len(d.Tables) == maxFirewallTables {
			d.TablesTruncated = true
			break
		}
		d.Tables = append(d.Tables, tableOf(t, owners[tableKey{t.Family, t.Name}]))
	}
}

// addChainOwners adds who a chain says made its table: iptables-nft by its
// base chain names, others by prefixes.
func addChainOwners(owners map[string]bool, c nftables.Chain) {
	if c.Base && slices.Contains(iptablesTables, c.Table) && slices.Contains(iptablesChains, c.Name) {
		owners["iptables-nft"] = true
	}
	for _, p := range ownerByPrefix {
		if strings.HasPrefix(c.Name, p.prefix) {
			owners[p.owner] = true
		}
	}
}

// tableOf is a table with the owners its chains name, and its own name.
func tableOf(t nftables.Table, chainOwners map[string]bool) fwTable {
	guess := slices.AppendSeq([]string{}, maps.Keys(chainOwners))
	if slices.Contains(ownerTables, t.Name) {
		guess = append(guess, t.Name)
	}
	if owner, ok := ownerByTable[t.Name]; ok {
		guess = append(guess, owner)
	}
	slices.Sort(guess)
	return fwTable{Family: t.Family.String(), Name: checkedName(t.Name), Dormant: t.Flags&nftables.TableDormant != 0, OwnerGuess: slices.Compact(guess)}
}

func chainOf(c nftables.Chain, rs *nftables.Ruleset) fwChain {
	out := fwChain{Family: c.Family.String(), Table: checkedName(c.Table), Name: checkedName(c.Name)}
	if c.Base {
		out.Type = checkedBy(c.Type, chainTypeRe.MatchString)
		out.Hook, out.Priority, out.Policy = c.HookName(), &c.Priority, c.PolicyName()
		for _, dev := range c.Devices {
			out.Devices = append(out.Devices, checkedBy(dev, ifaceNameRe.MatchString))
		}
	}
	n, ok := rs.RulesCount(c)
	if !ok {
		if c.Base && nftables.Inbound(c) { // past the chains a read reads
			v := nftables.VerdictUnknown
			out.Terminal = &v
		}
		return out
	}
	out.RulesCount = &n
	if c.Base {
		v, target := rs.End(c)
		if v == nftables.VerdictJump {
			v += ":" + checkedName(target)
		}
		out.Terminal = &v
	}
	return out
}

func checkedName(s string) string { return checkedBy(s, nftNameRe.MatchString) }

// checkedBy is checked for a plain string.
func checkedBy(s string, valid func(string) bool) string { return *checked(&s, valid) }

// firewallView: partial when an eBPF dataplane runs in PID 1's network
// namespace.
func firewallView(sc *scanCtx, gaps *gapList) string {
	running, err := roleProcessesRunning(sc)
	gaps.add("/proc", err)
	for _, name := range ebpfDataplanes {
		if slices.Contains(running, name) {
			return viewPartial
		}
	}
	return viewFull
}

// legacyTablesPresent: iptables-legacy tables are registered in PID 1's
// network namespace; their rules are not read.
func legacyTablesPresent(sc *scanCtx, gaps *gapList) bool {
	present := false
	for _, p := range []string{"/proc/1/net/ip_tables_names", "/proc/1/net/ip6_tables_names"} {
		b, err := sc.read(p, smallFileLimit)
		gaps.optional(p, err) // not there: the module is not loaded
		for name := range strings.FieldsSeq(string(b)) {
			present = present || legacyTableRe.MatchString(name)
		}
	}
	return present
}

// readUFW reads ufw's configuration as ufw does, and finds its chains in
// the ruleset; null when ufw is neither installed nor loaded.
func readUFW(sc *scanCtx, rs *nftables.Ruleset, gaps *gapList) *fwUFW {
	u := fwUFW{
		RuntimeRulesV4: rulesOf(rs, nftables.FamilyIP, "filter", nftables.UFWUser),
		RuntimeRulesV6: rulesOf(rs, nftables.FamilyIP6, "filter", nftables.UFW6User),
	}
	conf, err := sc.read("/etc/ufw/ufw.conf", smallFileLimit)
	if errors.Is(err, fs.ErrNotExist) && u.RuntimeRulesV4 == nil && u.RuntimeRulesV6 == nil {
		return nil
	}
	gaps.optional("/etc/ufw/ufw.conf", err)
	u.ConfigEnabled = ufwEnabled(conf)
	if defaults, err := sc.read("/etc/default/ufw", smallFileLimit); err == nil {
		v := ufwVars(defaults)
		u.DefaultInputPolicy = checked(presentValue(v, "default_input_policy"), ufwPolicyRe.MatchString)
		u.DefaultForwardPolicy = checked(presentValue(v, "default_forward_policy"), ufwPolicyRe.MatchString)
		ipv6 := v["ipv6"] == ufwYes
		u.IPv6 = &ipv6
	} else {
		gaps.optional("/etc/default/ufw", err)
	}
	u.ServiceEnabled = serviceEnabled(sc, "ufw.service")
	return &u
}

// ufwVars reads /etc/default/ufw as ufw's Python does: only a line that
// starts KEY=word or KEY="word" counts — not one indented, nor 'word' in
// single quotes; it is split at every "=", key and value lowercased, quotes
// trimmed; the last one of a key wins.
func ufwVars(b []byte) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(string(b), "\n") {
		if !ufwLineRe.MatchString(line) {
			continue
		}
		parts := strings.Split(strings.TrimSpace(line), "=")
		out[strings.ToLower(parts[0])] = strings.Trim(strings.ToLower(parts[1]), `"'`)
	}
	return out
}

// ufwEnabled is ENABLED of ufw.conf as ufw-init — a shell script sourcing
// the file at boot — compares it: "yes" or "YES" exactly, after the shell's
// quotes and a trailing comment.
func ufwEnabled(b []byte) bool {
	value := ""
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ENABLED="); ok {
			value = shellWord(v)
		}
	}
	return value == ufwYes || value == "YES"
}

// shellWord is the value of a shell assignment: inside its quotes, or up to
// the first blank.
func shellWord(v string) string {
	for _, q := range []string{`"`, `'`} {
		if rest, ok := strings.CutPrefix(v, q); ok {
			w, _, _ := strings.Cut(rest, q)
			return w
		}
	}
	if f := strings.Fields(v); len(f) > 0 {
		return f[0]
	}
	return ""
}

// readFirewalld reads firewalld.conf and finds firewalld's table; null when
// firewalld is neither installed nor running.
func readFirewalld(sc *scanCtx, rs *nftables.Ruleset, gaps *gapList) *fwFirewalld {
	f := fwFirewalld{RuntimeTablePresent: hasTable(rs, nftables.FamilyINet, "firewalld")}
	conf, err := sc.read("/etc/firewalld/firewalld.conf", smallFileLimit)
	if errors.Is(err, fs.ErrNotExist) && !f.RuntimeTablePresent {
		return nil
	}
	gaps.optional("/etc/firewalld/firewalld.conf", err)
	v := firewalldVars(conf)
	f.Backend = checked(presentValue(v, "FirewallBackend"), fwBackendRe.MatchString)
	f.DefaultZone = checked(presentValue(v, "DefaultZone"), fwZoneRe.MatchString)
	f.ServiceEnabled = serviceEnabled(sc, "firewalld.service")
	return &f
}

// firewalldVars reads firewalld.conf as firewalld does: '#' and ';' start a
// comment line; a line is split at every "=" and dropped unless that gives
// two parts, or when the value is empty; the first of a key wins.
func firewalldVars(b []byte) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			continue
		}
		k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if _, seen := out[k]; !seen && v != "" {
			out[k] = v
		}
	}
	return out
}

func presentValue(vars map[string]string, key string) *string {
	if v, ok := vars[key]; ok {
		return &v
	}
	return nil
}

// serviceEnabled: the unit is enabled for multi-user.target; null without
// systemd.
func serviceEnabled(sc *scanCtx, unit string) *bool {
	if sc.env.Init != initSystemd {
		return nil
	}
	enabled := unitEnabled(sc, unit, "multi-user.target")
	return &enabled
}

func hasTable(rs *nftables.Ruleset, f nftables.Family, name string) bool {
	return rs != nil && slices.ContainsFunc(rs.Tables, func(t nftables.Table) bool { return t.Family == f && t.Name == name })
}

// rulesOf is the number of rules of a chain read, nil when it is not there.
func rulesOf(rs *nftables.Ruleset, f nftables.Family, table, name string) *int {
	if rs == nil {
		return nil
	}
	if n, ok := rs.RulesCount(nftables.Chain{Family: f, Table: table, Name: name}); ok {
		return &n
	}
	return nil
}

// The gen trigger: the generation is cheap to read and
// changes with every change of the ruleset. A change rebuilds the firewall
// section in an unscheduled pass, at most every firewallGenGap — on a
// Kubernetes node the generation moves all the time — and that pass is sent
// only when the section changed for the backend (Run).
const (
	firewallGenPoll = time.Minute
	firewallGenGap  = 15 * time.Minute
	triggerFirewall = "firewall"
)

// watchGen polls the generation beside Run until ctx ends.
func (c *Collector) watchGen(ctx context.Context) {
	ticker := time.NewTicker(firewallGenPoll)
	defer ticker.Stop()
	var st genPoll
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.checkGen(ctx, &st)
		}
	}
}

// genPoll is what watchGen keeps between polls.
type genPoll struct {
	triggered time.Time // the last firewall pass asked for
	failing   bool      // the last poll could not read the generation
}

// checkGen is one poll: a firewall pass when the ruleset changed, at most
// once per firewallGenGap. A poll that starts or stops failing is logged.
func (c *Collector) checkGen(ctx context.Context, st *genPoll) {
	if c.now().Sub(st.triggered) < firewallGenGap {
		return
	}
	changed, err := c.firewallChanged()
	switch {
	case err != nil && !st.failing:
		c.Error(ctx, "security: nftables generation unreadable, firewall changes wait for the interval", "error", err)
	case err == nil && st.failing:
		c.Print(ctx, "security: nftables generation readable again")
	}
	st.failing = err != nil
	if changed {
		st.triggered = c.now()
		c.Trigger(triggerFirewall, SectionFirewall)
	}
}

// firewallChanged: the generation moved since the section read it, or
// nf_tables got loaded since. Before the section ran, or after it failed,
// false: there is nothing to compare with, and the next interval rebuilds
// it anyway.
func (c *Collector) firewallChanged() (bool, error) {
	dep, ran := c.dep(SectionFirewall)
	res, ok := dep.res.(firewallResult)
	if !ran || !ok {
		return false, nil
	}
	// A module unloaded since would be loaded again by the request. /sys is
	// never a remote filesystem: no mount table needed for this lstat.
	if !res.builtin {
		if _, err := os.Lstat(c.root + "/sys/module/nf_tables"); err != nil {
			return false, nil
		}
	}
	if !res.loaded {
		return true, nil
	}
	conn, err := c.nftDial(res.netns)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	gen, err := nftables.ReadGen(conn)
	return err == nil && gen != res.gen, err
}
