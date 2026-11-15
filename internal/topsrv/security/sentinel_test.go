package security

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
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
			"Defaults logfile=/var/log/SENTINEL.log, timestamp_timeout=SENTINELSECRET\n" +
			"Cmnd_Alias SVC = /usr/bin/SENTINEL --token SENTINELSECRET\n" +
			"alice ALL = NOPASSWD: SVC\n" +
			"SENTINELLINE is not sudoers\n",
		"etc/doas.conf": "permit nopass alice as root cmd /usr/bin/SENTINEL args SENTINELSECRET\n",

		// docker: the roles fixture's dockerd (pid 100) with secrets on its
		// command line, and in daemon.json; no socket, so the
		// configuration is what is read
		"proc/100/cmdline": "/usr/bin/dockerd\x00-H\x00unix:///run/docker.sock\x00--tlskey\x00/etc/SENTINEL.key\x00--registry-mirror\x00https://u:SENTINELSECRET@example.com\x00",
		"usr/bin/dockerd":  "",
		"etc/docker/daemon.json": `{"iptables": false, "firewall-backend": "SENTINELSECRET", "userns-remap": "SENTINEL",
			"registry-mirrors": ["https://u:SENTINELSECRET@example.com"], "hosts": ["tcp://u:SENTINELSECRET@0.0.0.0:2375"]}`,

		// accounts: login.defs keys of a form shadow refuses and keys not sent,
		// PAM arguments; authorizedKeys: a .netrc with a password
		"etc/login.defs":     "ENCRYPT_METHOD SENTINELSECRET\nMAIL_DIR /var/SENTINEL\nPASS_MAX_DAYS 90\n",
		"etc/pam.d/sentinel": "auth required pam_exec.so /usr/bin/SENTINEL SENTINELSECRET\nauth sufficient pam_unix.so nullok\n",
		"root/.netrc":        "machine example.com login root password SENTINELSECRET\n",

		// updates: a proxy password and a hook command apt reads with the
		// periodic keys, a value of an unexpected form, a line apt refuses
		"etc/apt/apt.conf.d/01proxy": "Acquire::http::Proxy \"http://u:SENTINELSECRET@192.0.2.1:3128\";\n" +
			"DPkg::Pre-Invoke { \"/usr/bin/SENTINEL --token SENTINELSECRET\"; };\n",
		"etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Update-Package-Lists \"1\";\n" +
			"APT::Periodic::Unattended-Upgrade \"SENTINELSECRET\";\n",
		"etc/apt/apt.conf.d/99broken": "SENTINELLINE is not apt.conf\n",
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
	for _, name := range []string{SectionAccounts, SectionSSHD, SectionAuthorizedKeys, SectionSudoers, SectionUpdates, SectionDocker} {
		require.Contains(t, []Status{StatusOK, StatusPartial}, d.Sections[name].Status, "%s: %+v", name, d.Sections[name])
	}

	acc := d.Sections[SectionAccounts].Data.(accountsData)
	require.NotEmpty(t, acc.Users)
	assert.Equal(t, "root", acc.Users[0].Name)
	assert.NotEmpty(t, acc.Users[0].PWToken, "shadow read")
	assert.NotEmpty(t, acc.Malformed, "the malformed passwd line")
	assert.Equal(t, map[string]string{"ENCRYPT_METHOD": valueInvalid, "PASS_MAX_DAYS": "90"}, acc.LoginDefs)
	assert.Equal(t, []string{"/etc/pam.d/sentinel"}, acc.PAMNullok)

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
	require.Len(t, keys.TrustFiles, 1, "the .netrc found, never read")

	sudo := d.Sections[SectionSudoers].Data.(sudoData)
	assert.True(t, slices.ContainsFunc(sudo.Rules, func(r sudoRule) bool { return slices.Contains(r.Principals, "alice") }),
		"the rule using the alias")
	assert.Len(t, sudo.DoasRules, 1)
	assert.True(t, *sudo.Defaults.Logfile, "the logfile read, its path dropped")
	assert.Equal(t, valueInvalid, *sudo.Defaults.Timeout)

	dk := d.Sections[SectionDocker].Data.(dockerData)
	assert.False(t, *dk.Config.IPTables, "daemon.json read")
	assert.Equal(t, valueInvalid, *dk.Config.FirewallBackend)
	assert.Equal(t, []dockerHost{{Proto: "unix", Addr: "/run/docker.sock", Source: hostFromCmdline}}, dk.Hosts, "the flags read")

	apt := d.Sections[SectionUpdates].Data.(updatesData).APT
	require.NotNil(t, apt)
	assert.Equal(t, valueInvalid, *apt.Periodic.UnattendedUpgrade, "the value read and replaced")
	assert.Len(t, apt.ParseErrors, 1, "the line apt refuses")
}

// TestNoSecretsLeakUpdates covers the updates sources of the hosts the
// Debian fixture of TestNoSecretsLeak does not read: dnf-automatic and
// Alpine cron jobs. updates logs nothing, so its data is what is checked.
func TestNoSecretsLeakUpdates(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		read  func(t *testing.T, d updatesData)
	}{
		{"rpm", map[string]string{
			"var/lib/rpm/rpmdb.sqlite": "",
			"etc/dnf/automatic.conf": "[commands]\nupgrade_type = SENTINELSECRET\nreboot_command = \"/usr/bin/SENTINEL --token SENTINELSECRET\"\n" +
				"[email]\nemail_from = SENTINEL@example.com\nemail_host = SENTINELSECRET.example.com\n",
		}, func(t *testing.T, d updatesData) {
			assert.Equal(t, valueInvalid, *d.DNFAutomatic.UpgradeType, "the value read and replaced")
		}},
		{"apk", map[string]string{
			"lib/apk/db/installed": "",
			"etc/crontabs/root":    "0 4 * * * apk upgrade --repository http://u:SENTINELSECRET@192.0.2.1/alpine\n",
		}, func(t *testing.T, d updatesData) {
			assert.Equal(t, []string{"/etc/crontabs/root"}, d.APK.UpgradeJobs, "the job line read")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sec := collectUpdates(t.Context(), fixture(t, tc.files))
			require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
			tc.read(t, sec.Data.(updatesData))
			assert.NotContains(t, strings.ToUpper(toJSON(t, sec)), "SENTINEL")
		})
	}
}
