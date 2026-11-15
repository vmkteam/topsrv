package security

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// sentinelFiles plants the §13 markers where the collector reads, and where
// later sections will: none may reach the snapshot or the logs. Each PR adds
// markers for its sections. The sshd and sudoers fixtures of hostFixture
// carry more: a key command token and a sudo command.
func sentinelFiles() map[string]string {
	return map[string]string{
		"proc/cmdline":            "BOOT_IMAGE=/vmlinuz ro mitigations=auto iscsi_password=SENTINELSECRET quiet\n",
		"proc/102/cmdline":        "/usr/local/bin/k3s\x00server\x00--token\x00SENTINELSECRET\x00",
		"proc/1/environ":          "LD_PRELOAD=/SENTINEL.so\x00container=docker\x00",
		"proc/sys/kernel/tainted": "SENTINELLINE\n", // a broken source: a gap, never its content

		// accounts: a hash, GECOS, a malformed line, a group password
		"etc/shadow":  "root:$6$SENTINELHASH$abc:19700:0:99999:7:::\n",
		"etc/passwd":  "root:x:0:0:Sentinel Person:/root:/bin/bash\nSENTINELLINE\n",
		"etc/gshadow": "root:*::\nsudo:$6$SENTINELHASH$grp::alice\n",

		// authorizedKeys: option values, the comment, a key that does not parse
		"root/.ssh/authorized_keys": `command="/usr/bin/SENTINEL",environment="TOKEN=SENTINELSECRET",from="192.0.2.1" ` +
			"ssh-ed25519 " + b64(ed25519Blob(1)) + " sentinel@example.com\n" +
			"ssh-ed25519 SENTINELLINE sentinel@example.com\n",

		// sshd: presence-only values, values sshd refuses (an enum value is
		// lowercased: sentinelvalue), a token where a keyword should be (sent
		// as "invalid", not as the word)
		"etc/ssh/sshd_config.d/90-sentinel.conf": "Banner /etc/SENTINEL_banner\n" +
			"TrustedUserCAKeys /etc/ssh/SENTINEL_ca.pub\n" +
			"Port SENTINELSECRET\n" +
			"PermitRootLogin SentinelValue\n" +
			"MaxAuthTries SENTINELSECRET\n" +
			"Ciphers SENTINELSECRET\n" +
			"AuthenticationMethods publickey,SENTINELSECRET\n" +
			"ListenAddress 192.0.2.1:SENTINELSECRET\n" +
			"SENTINELSECRET yes\n" +
			"Match SENTINELSECRET x\n" +
			"Match LocalPort SENTINELSECRET\n",

		// sudoers: Defaults values, an alias of commands, a line sudo refuses;
		// doas: the command and its arguments
		"etc/sudoers.d/sentinel": "Defaults mailto=\"SENTINEL@example.com\"\n" +
			"Defaults env_keep += \"SENTINELVAR\"\n" +
			"Cmnd_Alias SVC = /usr/bin/SENTINEL --token SENTINELSECRET\n" +
			"alice ALL = NOPASSWD: SVC\n" +
			"SENTINELLINE is not sudoers\n",
		"etc/doas.conf": "permit nopass alice as root cmd /usr/bin/SENTINEL args SENTINELSECRET\n",
	}
}

// captureLogs builds a verbose logger whose output goes to a temp file, and
// returns it with a func reading everything logged. embedlog binds the
// standard streams when the logger is built, so they are swapped only for
// that call; tests of this package do not run in parallel.
func captureLogs(t *testing.T) (embedlog.Logger, func() string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "log")
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, f
	logger := embedlog.NewLogger(true, false)
	os.Stdout, os.Stderr = stdout, stderr
	return logger, func() string {
		b, err := os.ReadFile(f.Name())
		require.NoError(t, err)
		return string(b)
	}
}

func TestNoSecretsLeak(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		host  bool // the host sections run and read the markers
	}{
		{"host", merge(hostFixture(), sentinelFiles()), true},
		// in a container the environment of PID 1 is read for container=
		{"container", merge(hostFixture(), sentinelFiles(), map[string]string{"proc/self/ns/pid": "-> pid:[4026532501]"}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestCollector(t, tc.files)
			logger, logged := captureLogs(t)
			c.Logger = logger
			// a panicking parser logs its error
			bad := &fakeSection{next: func(context.Context) Section { panic(errors.New("parse SENTINELLINE: invalid syntax")) }}
			c.sections = append(c.sections, bad.def("bad", time.Second))

			p := c.pass(t.Context(), Trigger{Cause: triggerStart})
			c.finish(t.Context(), p)

			snapshot, logs := toJSON(t, p), logged()
			require.Contains(t, logs, "sentinel_test.go:", "the panic is logged with its type and site")
			if tc.host {
				requireMarkersRead(t, dataOf(t, p))
			}
			for _, marker := range []string{"SENTINEL", "sentinel@example.com", "Sentinel Person", "sentinelvalue"} {
				assert.NotContains(t, snapshot, marker, "snapshot")
				assert.NotContains(t, logs, marker, "logs")
			}
		})
	}
}

// requireMarkersRead fails unless the sections read the files holding the
// markers: a section that comes out unknown would pass the leak check for
// nothing.
func requireMarkersRead(t *testing.T, d Data) {
	t.Helper()
	for _, name := range []string{SectionAccounts, SectionSSHD, SectionAuthorizedKeys, SectionSudoers} {
		require.Contains(t, []Status{StatusOK, StatusPartial}, d.Sections[name].Status, "%s: %+v", name, d.Sections[name])
	}

	acc := d.Sections[SectionAccounts].Data.(accountsData)
	require.NotEmpty(t, acc.Users)
	assert.Equal(t, "root", acc.Users[0].Name)
	assert.NotEmpty(t, acc.Users[0].PWToken, "shadow read")
	assert.NotEmpty(t, acc.Malformed, "the malformed passwd line")

	sshd := d.Sections[SectionSSHD].Data.(sshdData)
	assert.Equal(t, true, sshd.Effective["Banner"].Value, "the drop-in read")
	assert.Equal(t, true, sshd.Effective["AuthorizedKeysCommand"].Value)
	assert.Len(t, sshd.ParseErrors, 8, "the values and Match lines sshd refuses")
	assert.False(t, sshd.ConfigValid)
	assert.NotEmpty(t, sshd.UnknownKeywords)

	keys := d.Sections[SectionAuthorizedKeys].Data.(authKeysData)
	require.NotEmpty(t, keys.Users)
	require.NotEmpty(t, keys.Users[0].Files)
	require.NotEmpty(t, keys.Users[0].Files[0].Keys)
	key := keys.Users[0].Files[0].Keys[0]
	assert.Equal(t, fingerprint(ed25519Blob(1)), key.FP)
	assert.True(t, key.Options.Command && key.Options.From, "options read, values dropped")

	sudo := d.Sections[SectionSudoers].Data.(sudoData)
	assert.True(t, slices.ContainsFunc(sudo.Rules, func(r sudoRule) bool { return slices.Contains(r.Principals, "alice") }),
		"the rule using the alias")
	assert.Len(t, sudo.DoasRules, 1)
}
