//go:build integration && linux

package nftables

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNetnsRulesets loads each ruleset of rulesetCases into a network
// namespace of its own and reads it the way the agent reads PID 1's: Dial
// switches into the namespace for the socket only. Needs root, nft and
// iptables-nft. NFTABLES_RECORD=1 writes the replies as testdata/<name>.json
// for TestRulesets.
func TestNetnsRulesets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make network namespaces")
	}
	for _, tool := range []string{"ip", "nft", "iptables-nft-restore", "ip6tables-nft-restore"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	selfNs, err := os.Readlink("/proc/self/ns/net")
	require.NoError(t, err)
	for _, tc := range rulesetCases {
		t.Run(tc.name, func(t *testing.T) {
			ns := loadNetns(t, tc.name)
			c, err := Dial("/run/netns/" + ns)
			require.NoError(t, err)
			defer c.Close()
			rec := &Recorder{X: c}
			rs, err := Read(rec, Inbound)
			require.NoError(t, err)
			checkRuleset(t, rs, tc)

			after, err := os.Readlink("/proc/self/ns/net")
			require.NoError(t, err)
			assert.Equal(t, selfNs, after, "the test left its namespace")
			if os.Getenv("NFTABLES_RECORD") == "1" {
				b, err := rec.JSON()
				require.NoError(t, err)
				require.NoError(t, os.WriteFile("testdata/"+tc.name+".json", append(b, '\n'), 0o644))
			}
		})
	}
}

// TestNetnsGenChanges: a change between two reads moves the generation.
func TestNetnsGenChanges(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to make network namespaces")
	}
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	ns := loadNetns(t, "debian-default")
	c, err := Dial("/run/netns/" + ns)
	require.NoError(t, err)
	defer c.Close()
	before, err := ReadGen(c)
	require.NoError(t, err)
	run(t, nil, "ip", "netns", "exec", ns, "nft", "add", "table", "ip", "probe")
	after, err := ReadGen(c)
	require.NoError(t, err)
	assert.NotEqual(t, before, after)
}

// loadNetns makes a namespace with the ruleset of a case, removed when the
// test ends.
func loadNetns(t *testing.T, name string) string {
	t.Helper()
	ns := "topsrv-" + name
	run(t, nil, "ip", "netns", "add", ns)
	t.Cleanup(func() { run(t, nil, "ip", "netns", "del", ns) })
	loaders := []struct {
		ext  string
		args []string
	}{
		{".iptables", []string{"iptables-nft-restore"}},
		{".ip6tables", []string{"ip6tables-nft-restore"}},
		{".nft", []string{"nft", "-f", "-"}},
	}
	for _, l := range loaders {
		f, err := os.Open("testdata/" + name + l.ext)
		if os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err)
		run(t, f, append([]string{"ip", "netns", "exec", ns}, l.args...)...)
		f.Close()
	}
	return ns
}

func run(t *testing.T, stdin *os.File, args ...string) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%v: %s", args, out)
}
