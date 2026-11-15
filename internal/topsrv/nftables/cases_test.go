package nftables

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rulesetCase is a ruleset in testdata: <name>.iptables, .ip6tables and
// .nft are loaded in that order into a network namespace by the netns test,
// which records the replies of the kernel as <name>.json; TestRulesets reads
// the recording anywhere. Both check the same expectations.
type rulesetCase struct {
	name string
	// ends: "family table chain" of every base chain Inbound picks → End,
	// "jump:CHAIN" for a jump past MaxDepth.
	ends map[string]string
	// rules: "family table chain" → rules read.
	rules map[string]int
}

var rulesetCases = []rulesetCase{
	{
		// ufw enabled, Docker 29 with the iptables backend, fail2ban:
		// INPUT ends with a jump to an empty ufw chain, then the policy.
		name: "ufw-docker",
		ends: map[string]string{
			"ip filter INPUT":          VerdictDrop,
			"ip filter FORWARD":        VerdictDrop,
			"ip6 filter INPUT":         VerdictDrop,
			"ip6 filter FORWARD":       VerdictDrop,
			"inet f2b-table f2b-chain": VerdictAccept,
		},
		rules: map[string]int{
			"ip filter INPUT": 6, "ip filter DOCKER-USER": 0, "ip filter ufw-track-input": 0,
			"ip filter ufw-user-input": 4, "ip6 filter ufw6-user-input": 4,
		},
	},
	{
		// ufw disabled, WireGuard forwarding: INPUT accepts by policy;
		// FORWARD ends with a jump to DOCKER-FORWARD, whose last rule is a
		// match, and drops by policy.
		name: "ufw-off-wireguard",
		ends: map[string]string{
			"ip filter INPUT":    VerdictAccept,
			"ip filter FORWARD":  VerdictDrop,
			"ip6 filter INPUT":   VerdictAccept,
			"ip6 filter FORWARD": VerdictDrop,
		},
		rules: map[string]int{"ip filter INPUT": 1, "ip filter DOCKER-FORWARD": 4},
	},
	{
		// ufw with DEFAULT_INPUT_POLICY="ACCEPT": the drop of ufw-not-local
		// comes after its returns for local addresses and does not decide.
		name: "ufw-accept",
		ends: map[string]string{
			"ip filter INPUT":    VerdictAccept,
			"ip filter FORWARD":  VerdictDrop,
			"ip6 filter INPUT":   VerdictAccept,
			"ip6 filter FORWARD": VerdictDrop,
		},
	},
	{
		// ufw and a DOCKER-USER that drops forwarding from the uplink; IPv6
		// forwarding accepted by policy.
		name: "docker-user",
		ends: map[string]string{
			"ip filter INPUT":    VerdictDrop,
			"ip filter FORWARD":  VerdictDrop,
			"ip6 filter INPUT":   VerdictDrop,
			"ip6 filter FORWARD": VerdictAccept,
		},
		rules: map[string]int{"ip filter DOCKER-USER": 3, "ip filter ufw-user-input": 4},
	},
	{
		// /etc/nftables.conf of Debian 13: enabled is not protecting.
		name: "debian-default",
		ends: map[string]string{
			"inet filter input":   VerdictAccept,
			"inet filter forward": VerdictAccept,
		},
		rules: map[string]int{"inet filter input": 0},
	},
	{
		// firewalld 1.3.4: policy accept, the last rule rejects.
		name: "firewalld",
		ends: map[string]string{
			"inet firewalld filter_INPUT":   VerdictReject,
			"inet firewalld filter_FORWARD": VerdictReject,
		},
		rules: map[string]int{"inet firewalld filter_INPUT": 6},
	},
	{
		// firewalld with the default zone trusted (target ACCEPT): the zone
		// chain, reached by an unconditional goto, accepts before the
		// final reject.
		name: "firewalld-trusted",
		ends: map[string]string{
			"inet firewalld filter_INPUT":   VerdictAccept,
			"inet firewalld filter_FORWARD": VerdictAccept,
		},
	},
	{
		// Docker 29.9 with the nftables backend: verdict maps per bridge.
		// ip filter with FORWARD → DOCKER-USER is left from its first start
		// with the iptables backend: switching cleans Docker's own chains,
		// not DOCKER-USER.
		name: "docker-nftables",
		ends: map[string]string{
			"ip filter FORWARD":                 VerdictAccept,
			"ip6 filter FORWARD":                VerdictAccept,
			"ip docker-bridges filter-FORWARD":  VerdictAccept,
			"ip6 docker-bridges filter-FORWARD": VerdictAccept,
		},
		rules: map[string]int{"ip filter DOCKER-USER": 0, "ip docker-bridges filter-FORWARD": 2},
	},
	{
		// Text in rules (comments, a set name, log prefixes) for the leak
		// test of the security section; the last rule sets a mark, logs
		// and drops: statements and a verdict, unconditional.
		name: "sentinel",
		ends: map[string]string{"inet filter input": VerdictDrop},
	},
}

func chainName(c Chain) string { return c.Family.String() + " " + c.Table + " " + c.Name }

func checkRuleset(t *testing.T, rs *Ruleset, tc rulesetCase) {
	t.Helper()
	ends := map[string]string{}
	byName := map[string]Chain{}
	for _, c := range rs.Chains {
		byName[chainName(c)] = c
		if c.Base && Inbound(c) {
			v, target := rs.End(c)
			if v == VerdictJump {
				v += ":" + target
			}
			ends[chainName(c)] = v
		}
	}
	assert.Equal(t, tc.ends, ends)
	for name, n := range tc.rules {
		c, ok := byName[name]
		require.True(t, ok, name)
		got, ok := rs.RulesCount(c)
		require.True(t, ok, "rules of %s not read", name)
		assert.Equal(t, n, got, name)
	}
}

func TestRulesets(t *testing.T) {
	for _, tc := range rulesetCases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := os.ReadFile("testdata/" + tc.name + ".json")
			require.NoError(t, err)
			replay, err := NewReplay(b)
			require.NoError(t, err)
			rs, err := Read(replay, Inbound)
			require.NoError(t, err)
			checkRuleset(t, rs, tc)
		})
	}
}
