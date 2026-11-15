package security

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/nftables"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// replayConn serves a recording of the nftables package's testdata.
type replayConn struct{ *nftables.Replay }

func (replayConn) Close() error { return nil }

// nftReplay dials a fresh replay of testdata/<name>.json of the nftables
// package and records the namespace asked for.
func nftReplay(t *testing.T, name string, netns *string) nftDialer {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "nftables", "testdata", name+".json"))
	require.NoError(t, err)
	return func(ns string) (nftConn, error) {
		if netns != nil {
			*netns = ns
		}
		r, err := nftables.NewReplay(b)
		return replayConn{r}, err
	}
}

// noDial fails the test on a request: it would load nf_tables.
func noDial(t *testing.T) nftDialer {
	return func(string) (nftConn, error) {
		t.Fatal("the request would load nf_tables")
		return nil, nil
	}
}

// firewallFixture is a host with nf_tables loaded and ufw installed,
// enabled and loaded (the ufw-docker recording).
func firewallFixture() map[string]string {
	return merge(hostProc(), map[string]string{
		"sys/module/nf_tables/": "",
		"etc/ufw/ufw.conf":      "# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n",
		"etc/default/ufw": "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n" +
			"DEFAULT_FORWARD_POLICY=\"DROP\"\nIPT_MODULES=\"\"\n",
		"etc/systemd/system/multi-user.target.wants/ufw.service": "-> /usr/lib/systemd/system/ufw.service",
		"usr/lib/systemd/system/ufw.service":                     "[Unit]\n",
	})
}

// firewallOf runs the section with the environment its fixture gives.
func firewallOf(t *testing.T, sc *scanCtx) (Section, firewallData, firewallResult) {
	t.Helper()
	_, sc.env = collectEnvironment(sc)
	sec, res := collectFirewall(t.Context(), sc)
	d, _ := sec.Data.(firewallData)
	r, _ := res.(firewallResult)
	return sec, d, r
}

func TestFirewall(t *testing.T) {
	sc := fixture(t, firewallFixture())
	var netns string
	sc.nftDial = nftReplay(t, "ufw-docker", &netns)
	sec, d, res := firewallOf(t, sc)

	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	assert.Empty(t, netns, "the agent's namespace is PID 1's")
	assert.True(t, d.NFTLoaded)
	assert.Equal(t, viewFull, d.FirewallView)
	assert.False(t, d.LegacyTablesPresent)
	assert.True(t, res.loaded)
	assert.False(t, res.builtin)
	assert.NotZero(t, res.gen, "kept for the gen trigger, not sent")

	tables := map[string]fwTable{}
	for _, tb := range d.Tables {
		tables[tb.Family+" "+tb.Name] = tb
	}
	assert.Equal(t, []string{"docker", "iptables-nft", "ufw"}, tables["ip filter"].OwnerGuess)
	assert.Equal(t, []string{"fail2ban"}, tables["inet f2b-table"].OwnerGuess)
	assert.Equal(t, []string{"docker", "iptables-nft"}, tables["ip nat"].OwnerGuess)

	chains := map[string]fwChain{}
	for _, c := range d.BaseChains {
		chains[c.Family+" "+c.Table+" "+c.Name] = c
	}
	assert.Equal(t, fwChain{Family: "ip", Table: "filter", Name: "INPUT", Type: "filter", Hook: "input", Priority: new(int32(0)),
		Policy: "drop", RulesCount: new(6), Terminal: new("drop")}, chains["ip filter INPUT"])
	assert.Equal(t, "drop", *chains["ip6 filter FORWARD"].Terminal)
	assert.Equal(t, "accept", *chains["inet f2b-table f2b-chain"].Terminal)
	assert.Equal(t, int32(-1), *chains["inet f2b-table f2b-chain"].Priority)
	out := chains["ip filter OUTPUT"]
	assert.Nil(t, out.RulesCount, "output is not read")
	assert.Nil(t, out.Terminal)
	assert.Equal(t, "accept", out.Policy)
	assert.Contains(t, d.DockerUser, fwChain{Family: "ip", Table: "filter", Name: "DOCKER-USER", RulesCount: new(0)})

	assert.Equal(t, &fwUFW{ConfigEnabled: true, ServiceEnabled: new(true), DefaultInputPolicy: new("drop"),
		DefaultForwardPolicy: new("drop"), IPv6: new(true), RuntimeRulesV4: new(4), RuntimeRulesV6: new(4)}, d.UFW)
	assert.Nil(t, d.Firewalld, "not installed, no table")

	b, err := json.Marshal(sec)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"terminal":"drop"`)
	assert.NotContains(t, string(b), "ufw-before-input", "regular chains are not listed")
	assert.NotContains(t, string(b), `"gen"`)
}

func TestFirewalld(t *testing.T) {
	files := merge(hostProc(), map[string]string{
		"sys/module/nf_tables/": "",
		"etc/firewalld/firewalld.conf": "# firewalld config file\n; also a comment\nDefaultZone = public\n" +
			"FirewallBackend=nftables\nIPv6_rpfilter=yes\n",
		"etc/systemd/system/multi-user.target.wants/firewalld.service": "-> /usr/lib/systemd/system/firewalld.service",
	})
	terminals := func(d firewallData) map[string]string {
		out := map[string]string{}
		for _, c := range d.BaseChains {
			if c.Terminal != nil {
				out[c.Name] = c.Policy + " -> " + *c.Terminal
			}
		}
		return out
	}

	sc := fixture(t, files)
	sc.nftDial = nftReplay(t, "firewalld", nil)
	sec, d, _ := firewallOf(t, sc)
	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	assert.Equal(t, &fwFirewalld{ServiceEnabled: new(true), Backend: new("nftables"), DefaultZone: new("public"), RuntimeTablePresent: true}, d.Firewalld)
	assert.Nil(t, d.UFW)
	assert.Equal(t, map[string]string{"filter_INPUT": "accept -> reject", "filter_FORWARD": "accept -> reject"}, terminals(d),
		"the trap: the policy accepts, the chain rejects")
	assert.Equal(t, []string{"firewalld"}, d.Tables[0].OwnerGuess)

	t.Run("default zone trusted", func(t *testing.T) {
		sc := fixture(t, files)
		sc.nftDial = nftReplay(t, "firewalld-trusted", nil)
		_, d, _ := firewallOf(t, sc)
		assert.Equal(t, map[string]string{"filter_INPUT": "accept -> accept", "filter_FORWARD": "accept -> accept"}, terminals(d),
			"the zone accepts before the reject at the end")
	})

	t.Run("installed, not running", func(t *testing.T) {
		sc := fixture(t, merge(hostProc(), map[string]string{
			"sys/module/nf_tables/":        "",
			"etc/firewalld/firewalld.conf": "DefaultZone=my zone\nFirewallBackend=ipchains\n",
		}))
		sc.nftDial = nftReplay(t, "debian-default", nil)
		_, d, _ := firewallOf(t, sc)
		assert.Equal(t, &fwFirewalld{ServiceEnabled: new(false), Backend: new(valueInvalid), DefaultZone: new(valueInvalid)}, d.Firewalld)
	})
}

func TestFirewallUFWFlushed(t *testing.T) {
	// ENABLED=yes, but nftables.service flushed the ruleset after ufw.
	sc := fixture(t, firewallFixture())
	sc.nftDial = nftReplay(t, "debian-default", nil)
	sec, d, _ := firewallOf(t, sc)
	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	require.NotNil(t, d.UFW)
	assert.True(t, d.UFW.ConfigEnabled)
	assert.Nil(t, d.UFW.RuntimeRulesV4)
	assert.Nil(t, d.UFW.RuntimeRulesV6)
	assert.Equal(t, []string{}, d.Tables[0].OwnerGuess, "a ruleset of the user")
	assert.Equal(t, []fwChain{}, d.DockerUser)
}

func TestFirewallLeftovers(t *testing.T) {
	// ufw and firewalld removed, their rules still loaded.
	sc := fixture(t, merge(hostProc(), map[string]string{"sys/module/nf_tables/": ""}))
	sc.nftDial = nftReplay(t, "ufw-docker", nil)
	_, d, _ := firewallOf(t, sc)
	require.NotNil(t, d.UFW, "its chains are there")
	assert.False(t, d.UFW.ConfigEnabled)
	assert.Equal(t, 4, *d.UFW.RuntimeRulesV4)
	assert.Nil(t, d.UFW.DefaultInputPolicy, "no /etc/default/ufw")

	sc = fixture(t, merge(hostProc(), map[string]string{"sys/module/nf_tables/": ""}))
	sc.nftDial = nftReplay(t, "firewalld", nil)
	_, d, _ = firewallOf(t, sc)
	require.NotNil(t, d.Firewalld, "its table is there")
	assert.True(t, d.Firewalld.RuntimeTablePresent)
	assert.Nil(t, d.Firewalld.DefaultZone)
}

func TestFirewallNFTables(t *testing.T) {
	release := map[string]string{"proc/sys/kernel/osrelease": "6.8.0-90-generic\n"}

	t.Run("not loaded: nothing asked", func(t *testing.T) {
		sc := fixture(t, merge(hostProc(), release, map[string]string{
			"lib/modules/6.8.0-90-generic/modules.builtin": "kernel/net/netfilter/nfnetlink.ko\n",
		}))
		sc.nftDial = noDial(t)
		sec, d, res := firewallOf(t, sc)
		require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
		assert.False(t, d.NFTLoaded)
		assert.Nil(t, d.Tables)
		assert.Nil(t, d.UFW)
		assert.Equal(t, firewallResult{}, res)
	})
	t.Run("built in: no /sys/module entry", func(t *testing.T) {
		sc := fixture(t, merge(hostProc(), release, map[string]string{
			"usr/lib/modules/6.8.0-90-generic/modules.builtin": "kernel/net/netfilter/nfnetlink.ko\nkernel/net/netfilter/nf_tables.ko\n",
		}))
		sc.nftDial = nftReplay(t, "debian-default", nil)
		sec, d, res := firewallOf(t, sc)
		require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
		assert.True(t, d.NFTLoaded, "/usr/lib/modules read when /lib/modules has none")
		assert.True(t, res.builtin)
	})
	t.Run("cannot be told", func(t *testing.T) {
		sc := fixture(t, merge(hostProc(), release))
		sc.nftDial = noDial(t)
		sec, d, _ := firewallOf(t, sc)
		require.Equal(t, StatusPartial, sec.Status)
		assert.Equal(t, []Gap{{Path: "/lib/modules/6.8.0-90-generic/modules.builtin", Reason: ReasonNotFound}}, sec.Gaps)
		assert.False(t, d.NFTLoaded)
	})
	t.Run("no kernel release", func(t *testing.T) {
		sc := fixture(t, hostProc())
		sc.nftDial = noDial(t)
		sec, _, _ := firewallOf(t, sc)
		assert.Equal(t, []Gap{{Path: "/proc/sys/kernel/osrelease", Reason: ReasonNotFound}}, sec.Gaps)
	})
}

func TestFirewallNamespace(t *testing.T) {
	sc := fixture(t, merge(firewallFixture(), map[string]string{"proc/self/ns/net": "-> net:[4026532999]"}))
	var netns string
	sc.nftDial = nftReplay(t, "ufw-docker", &netns)
	sec, _, res := firewallOf(t, sc)
	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	assert.Equal(t, "/proc/1/ns/net", netns, "PID 1's ruleset, not the agent's")
	assert.Equal(t, "/proc/1/ns/net", res.netns, "the gen trigger asks there too")
}

func TestFirewallErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Reason
	}{
		{"no CAP_NET_ADMIN", syscall.EPERM, ReasonPermissionDenied},
		{"changing all the time", nftables.ErrInconsistent, ReasonDumpInconsistent},
		{"malformed", nftables.ErrMalformed, ReasonParseError},
		{"too large", nftables.ErrTooLarge, ReasonBudgetExceeded},
		{"no reply", os.ErrDeadlineExceeded, ReasonTimeout},
		{"setns", fs.ErrPermission, ReasonPermissionDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := fixture(t, firewallFixture())
			sc.nftDial = func(string) (nftConn, error) { return nil, tc.err }
			sec, _, res := firewallOf(t, sc)
			assert.Equal(t, unknown(tc.want), sec)
			assert.Equal(t, firewallResult{}, res, "nothing for the gen trigger to start from")
		})
	}
	t.Run("a request not answered", func(t *testing.T) {
		sc := fixture(t, firewallFixture())
		sc.nftDial = func(string) (nftConn, error) { return replayConn{&nftables.Replay{}}, nil }
		sec, _, _ := firewallOf(t, sc)
		assert.Equal(t, StatusUnknown, sec.Status, "not an empty ruleset")
	})
}

func TestFirewallLegacyAndView(t *testing.T) {
	sc := fixture(t, merge(firewallFixture(), map[string]string{
		"proc/1/net/ip_tables_names":  "filter\nnat\n",
		"proc/1/net/ip6_tables_names": "",
		"proc/500/exe":                "-> /usr/bin/cilium-agent",
	}))
	sc.nftDial = nftReplay(t, "ufw-docker", nil)
	sec, d, _ := firewallOf(t, sc)
	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	assert.True(t, d.LegacyTablesPresent)
	assert.Equal(t, viewPartial, d.FirewallView, "eBPF filters out of sight")

	t.Run("an agent of another namespace", func(t *testing.T) {
		sc := fixture(t, merge(firewallFixture(), map[string]string{
			"proc/500/exe":    "-> /usr/bin/cilium-agent",
			"proc/500/ns/net": "-> net:[4026532999]",
		}))
		sc.nftDial = nftReplay(t, "ufw-docker", nil)
		_, d, _ := firewallOf(t, sc)
		assert.Equal(t, viewFull, d.FirewallView, "a cilium-agent in a container filters its own namespace")
	})
	t.Run("names not of a table", func(t *testing.T) {
		sc := fixture(t, merge(firewallFixture(), map[string]string{"proc/1/net/ip_tables_names": "\n"}))
		sc.nftDial = nftReplay(t, "ufw-docker", nil)
		_, d, _ := firewallOf(t, sc)
		assert.False(t, d.LegacyTablesPresent)
	})
}

func TestUFWVars(t *testing.T) {
	v := ufwVars([]byte("# comment\nIPV6=yes\nDEFAULT_INPUT_POLICY=\"REJECT\"\nDEFAULT_FORWARD_POLICY='ACCEPT'\n" +
		"DEFAULT_OUTPUT_POLICY = drop\n  LOGLEVEL=low\nA=b=c\nIPV6=no\nbare\n"))
	assert.Equal(t, map[string]string{"ipv6": "no", "default_input_policy": "reject", "a": "b"}, v,
		"as ufw's Python: KEY=word at the start of the line only, split at every =, the last one wins")
}

func TestUFWEnabled(t *testing.T) {
	for conf, want := range map[string]bool{
		"ENABLED=yes\n":              true,
		"ENABLED=YES\n":              true,
		"ENABLED=\"yes\"\n":          true,
		"ENABLED='yes'\n":            true,
		"ENABLED=yes # on at boot\n": true,
		"  ENABLED=yes\n":            true,
		"ENABLED=Yes\n":              false, // ufw-init compares yes and YES only
		"ENABLED=no\nENABLED=yes\n":  true,
		"ENABLED=yes\nENABLED=no\n":  false,
		"# ENABLED=yes\n":            false,
		"ENABLED=\n":                 false,
		"LOGLEVEL=low\n":             false,
	} {
		assert.Equal(t, want, ufwEnabled([]byte(conf)), "%q", conf)
	}
}

func TestFirewalldVars(t *testing.T) {
	v := firewalldVars([]byte("# c\n; c\nDefaultZone = trusted \nDefaultZone=public\nFirewallBackend=nftables=x\n" +
		"FirewallBackend=\nFirewallBackend=iptables\nbare\n"))
	assert.Equal(t, map[string]string{"DefaultZone": "trusted", "FirewallBackend": "iptables"}, v,
		"as firewalld: two parts or the line is dropped, empty values dropped, the first of a key wins")
}

func TestFirewallTruncated(t *testing.T) {
	rs := &nftables.Ruleset{}
	for i := range maxFirewallTables + 1 {
		name := "t" + strconv.Itoa(i)
		rs.Tables = append(rs.Tables, nftables.Table{Family: nftables.FamilyIP, Name: name})
		rs.Chains = append(rs.Chains,
			nftables.Chain{Family: nftables.FamilyIP, Table: name, Name: "out", Base: true, Hook: 3, Type: "filter"},
			nftables.Chain{Family: nftables.FamilyIP, Table: name, Name: nftables.DockerUser})
	}
	var d firewallData
	d.setRuleset(rs)
	assert.Len(t, d.Tables, maxFirewallTables)
	assert.True(t, d.TablesTruncated)
	assert.Len(t, d.BaseChains, maxFirewallBaseChains)
	assert.True(t, d.BaseChainsTruncated)
	assert.Len(t, d.DockerUser, maxDockerUser)
	assert.True(t, d.DockerUserTruncated)

	in := chainOf(nftables.Chain{Family: nftables.FamilyIP, Table: "t", Name: "in", Base: true, Hook: 1, Type: "filter"}, rs)
	require.NotNil(t, in.Terminal)
	assert.Equal(t, nftables.VerdictUnknown, *in.Terminal, "an inbound chain past the chains read is unknown, not silent")
	assert.Nil(t, in.RulesCount)
}

func TestFirewallNames(t *testing.T) {
	tb := tableOf(nftables.Table{Family: nftables.FamilyINet, Name: "my table"}, nil)
	assert.Equal(t, valueInvalid, tb.Name, "a name nft would quote")
	assert.Equal(t, []string{}, tb.OwnerGuess)
	c := chainOf(nftables.Chain{Family: nftables.FamilyNetdev, Table: "t", Name: "in", Base: true, Type: "weird",
		Devices: []string{"eth0", "a very long interface name"}}, &nftables.Ruleset{})
	assert.Equal(t, valueInvalid, c.Type)
	assert.Equal(t, []string{"eth0", valueInvalid}, c.Devices)
	assert.Nil(t, c.RulesCount)
}

func TestFirewallNetlinkDump(t *testing.T) {
	sc := fixture(t, firewallFixture())
	var rec atomic.Pointer[nftables.Recorder]
	sc.nftDial = recordingDialer(nftReplay(t, "ufw-docker", nil), &rec)
	sec, _, _ := firewallOf(t, sc)
	require.Equal(t, StatusOK, sec.Status)

	dir := filepath.Join(t.TempDir(), "dump")
	require.NoError(t, writeNetlinkDump(dir, rec.Load()))
	file := filepath.Join(dir, netlinkDumpFile)
	fi, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "the full rules: the owner only")
	b, err := os.ReadFile(file)
	require.NoError(t, err)
	r, err := nftables.NewReplay(b)
	require.NoError(t, err)
	rs, err := nftables.Read(r, nftables.Inbound)
	require.NoError(t, err, "a dump replays as a fixture")
	assert.NotEmpty(t, rs.Tables)

	require.ErrorIs(t, writeNetlinkDump(dir, rec.Load()), fs.ErrExist, "a dump is never written over")
	shared := t.TempDir()
	require.NoError(t, os.Chmod(shared, 0o777))
	require.ErrorContains(t, writeNetlinkDump(shared, rec.Load()), "only it writes", "a directory others write")
	require.ErrorContains(t, writeNetlinkDump(dir, nil), "nothing to dump", "the section asked nothing")
	_, err = DryRun(t.Context(), embedlog.Logger{}, Config{}, t.TempDir(), "1.2.3", DryRunOptions{Sections: []string{SectionSysctl}, NetlinkDump: dir})
	require.ErrorContains(t, err, "nothing to dump")
}

func TestFirewallGenTrigger(t *testing.T) {
	recorded, err := nftables.ReadGen(mustDial(t, nftReplay(t, "ufw-docker", nil)))
	require.NoError(t, err)
	newCollector := func(t *testing.T, files map[string]string, res firewallResult) (*Collector, *time.Time) {
		c, now := newTestCollector(t, files)
		c.nftDial = nftReplay(t, "ufw-docker", nil)
		c.results[SectionFirewall] = depResult{sec: Section{Status: StatusOK}, res: res}
		return c, now
	}

	t.Run("generation moved", func(t *testing.T) {
		c, now := newCollector(t, firewallFixture(), firewallResult{loaded: true, gen: recorded + 1})
		var st genPoll
		c.checkGen(t.Context(), &st)
		assert.Equal(t, Trigger{Cause: triggerFirewall, Sections: []string{SectionFirewall}}, c.queued.trigger())
		assert.Equal(t, *now, st.triggered)

		c.queued = triggerSet{}
		*now = now.Add(firewallGenGap - time.Second)
		c.checkGen(t.Context(), &st)
		assert.True(t, c.queued.empty(), "at most one firewall pass per firewallGenGap")
		*now = now.Add(time.Second)
		c.checkGen(t.Context(), &st)
		assert.False(t, c.queued.empty())
	})
	t.Run("same generation", func(t *testing.T) {
		c, _ := newCollector(t, firewallFixture(), firewallResult{loaded: true, gen: recorded})
		assert.False(t, changed(t, c))
	})
	t.Run("asked in the namespace read", func(t *testing.T) {
		c, _ := newCollector(t, firewallFixture(), firewallResult{loaded: true, gen: recorded, netns: "/proc/1/ns/net"})
		var netns string
		c.nftDial = nftReplay(t, "ufw-docker", &netns)
		changed(t, c)
		assert.Equal(t, "/proc/1/ns/net", netns)
	})
	t.Run("nf_tables loaded since", func(t *testing.T) {
		c, _ := newCollector(t, firewallFixture(), firewallResult{})
		assert.True(t, changed(t, c))
	})
	t.Run("nf_tables unloaded since: not asked", func(t *testing.T) {
		c, _ := newCollector(t, hostProc(), firewallResult{loaded: true, gen: 1})
		c.nftDial = noDial(t)
		assert.False(t, changed(t, c))
	})
	t.Run("built in: no /sys/module entry needed", func(t *testing.T) {
		c, _ := newCollector(t, hostProc(), firewallResult{loaded: true, builtin: true, gen: recorded + 1})
		assert.True(t, changed(t, c))
	})
	t.Run("the section never read", func(t *testing.T) {
		c, _ := newCollector(t, firewallFixture(), firewallResult{})
		c.results[SectionFirewall] = depResult{sec: unknown(ReasonPermissionDenied)}
		assert.False(t, changed(t, c), "waits for the next interval")
		delete(c.results, SectionFirewall)
		assert.False(t, changed(t, c), "before the first pass")
	})
	t.Run("a poll that fails is logged once", func(t *testing.T) {
		c, now := newCollector(t, firewallFixture(), firewallResult{loaded: true, gen: recorded})
		logger, logged := captureLogs(t)
		c.Logger = logger
		c.nftDial = func(string) (nftConn, error) { return nil, syscall.EPERM }
		var st genPoll
		c.checkGen(t.Context(), &st)
		c.checkGen(t.Context(), &st)
		assert.True(t, st.failing)
		assert.Equal(t, 1, strings.Count(logged(), "generation unreadable"))
		assert.True(t, c.queued.empty())

		c.nftDial = nftReplay(t, "ufw-docker", nil)
		*now = now.Add(time.Minute)
		c.checkGen(t.Context(), &st)
		assert.False(t, st.failing)
		assert.Contains(t, logged(), "readable again")
	})
}

// changed is firewallChanged that reads the generation without an error.
func changed(t *testing.T, c *Collector) bool {
	t.Helper()
	ch, err := c.firewallChanged()
	require.NoError(t, err)
	return ch
}

func mustDial(t *testing.T, dial nftDialer) nftConn {
	t.Helper()
	conn, err := dial("")
	require.NoError(t, err)
	return conn
}

func TestUnscheduledPassChanged(t *testing.T) {
	c, _ := newTestCollector(t, firewallFixture())
	c.nftDial = nftReplay(t, "ufw-docker", nil)
	c.sections = []sectionDef{{name: SectionFirewall, budget: firewallBudget, host: true, run: collectFirewall}}
	gen := Trigger{Cause: triggerFirewall, Sections: []string{SectionFirewall}}

	_, changed := c.pass(t.Context(), Trigger{Cause: triggerStart})
	assert.True(t, changed, "the first run")
	_, changed = c.pass(t.Context(), gen)
	assert.False(t, changed, "the same outline: nothing new for the backend")
	c.nftDial = nftReplay(t, "docker-user", nil)
	_, changed = c.pass(t.Context(), gen)
	assert.True(t, changed)
}

func TestRunDue(t *testing.T) {
	c, now := newTestCollector(t, firewallFixture())
	c.nftDial = nftReplay(t, "ufw-docker", nil)
	c.sections = []sectionDef{{name: SectionFirewall, budget: firewallBudget, host: true, run: collectFirewall}}
	s := newSchedule(*now, time.Hour, 0)

	c.runDue(t.Context(), s, *now)
	require.Len(t, c.Inventory(), 1, "the first full pass")

	s.pending.add(Trigger{Cause: triggerFirewall, Sections: []string{SectionFirewall}})
	c.runDue(t.Context(), s, now.Add(minUnscheduledGap))
	assert.Empty(t, c.Inventory(), "unchanged: not sent")

	c.nftDial = nftReplay(t, "docker-user", nil)
	s.pending.add(Trigger{Cause: triggerFirewall, Sections: []string{SectionFirewall}})
	c.runDue(t.Context(), s, now.Add(2*minUnscheduledGap))
	got := c.Inventory()
	require.Len(t, got, 1, "changed: sent")
	assert.Equal(t, triggerFirewall, dataOf(t, got[0]).Trigger)
}

func TestSameForBackend(t *testing.T) {
	a := Section{Status: StatusOK, DurationMs: 3, Data: firewallData{NFTLoaded: true, FirewallView: viewFull}}
	b := Section{Status: StatusOK, DurationMs: 9, Data: firewallData{NFTLoaded: true, FirewallView: viewFull}}
	assert.True(t, sameForBackend(a, b), "the duration changes on every run")
	b.Data = firewallData{NFTLoaded: true, FirewallView: viewPartial}
	assert.False(t, sameForBackend(a, b))
	assert.False(t, sameForBackend(a, unknown(ReasonTimeout)))
}
