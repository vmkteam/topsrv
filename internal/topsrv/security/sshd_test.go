package security

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sshdFixture is a Debian 12 cloud image: the cloud-init drop-in enables
// passwords, the listener runs with -o, sshd-session links libpam.
func sshdFixture() map[string]string {
	return map[string]string{
		"etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n" +
			"PermitRootLogin prohibit-password\n" +
			"PasswordAuthentication no\n" +
			"KbdInteractiveAuthentication no\n" +
			"UsePAM yes\n" +
			"X11Forwarding yes\n" +
			"Banner none\n" +
			"AuthorizedKeysCommand /usr/bin/fetch-keys --token SENTINELSECRET %u\n" +
			"Subsystem sftp /usr/lib/openssh/sftp-server\n" +
			"Match User deploy\n" +
			"  AuthorizedKeysFile /etc/ssh/keys/%u\n" +
			"  PasswordAuthentication yes\n" +
			"Match Address 10.0.0.0/8\n" +
			"  PermitRootLogin yes\n",
		"etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
		"proc/1/ns/mnt":                   "-> mnt:[4026531841]",
		"proc/700/exe":                    "-> /usr/sbin/sshd",
		"proc/700/ns/mnt":                 "-> mnt:[4026531841]",
		"proc/700/cmdline":                "sshd: /usr/sbin/sshd -D -o MaxAuthTries=3 [listener] 0 of 10-100 startups\x00\x00",
		"proc/700/stat":                   "700 (sshd) S 1 700 700 0 -1 4194560 2000 0 0 0 1 2 0 0 20 0 1 0 1234500 10000000 2000\n",
		"proc/stat":                       "cpu 1 2 3\nbtime 1794700000\n",
		"proc/701/exe":                    "-> /usr/lib/openssh/sshd-session",
		"proc/701/cmdline":                "sshd-session: alice [priv]\x00",
		"usr/sbin/sshd":                   "\x7fELF...libc.so.6...",
		"usr/lib/openssh/sshd-session":    "\x7fELF...libpam.so.0...libc.so.6",
		"lib/systemd/system/ssh.service":  "[Service]\nEnvironmentFile=-/etc/default/ssh\nExecStartPre=/usr/sbin/sshd -t\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\n",
		"etc/systemd/system/sshd.service": "-> /lib/systemd/system/ssh.service",
		"etc/default/ssh":                 "SSHD_OPTS=\n",
		"etc/systemd/system/multi-user.target.wants/ssh.service": "",
	}
}

func sshdOf(t *testing.T, files map[string]string) (Section, sshdData, *sshdResult) {
	t.Helper()
	sc := fixture(t, files)
	sec, res := collectSSHD(t.Context(), sc)
	d, _ := sec.Data.(sshdData)
	r, _ := res.(*sshdResult)
	return sec, d, r
}

func TestSSHD(t *testing.T) {
	sec, d, res := sshdOf(t, merge(hostProc(), sshdFixture()))
	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)

	t.Run("effective values with their source", func(t *testing.T) {
		assert.Equal(t, sshdValue{Value: "yes", Source: "/etc/ssh/sshd_config.d/50-cloud-init.conf:1"}, d.Effective["PasswordAuthentication"],
			"the cloud-init drop-in is included first and wins")
		assert.Equal(t, sshdValue{Value: "prohibit-password", Source: "/etc/ssh/sshd_config:2"}, d.Effective["PermitRootLogin"])
		assert.Equal(t, sshdValue{Value: "3", Source: "cmdline"}, d.Effective["MaxAuthTries"], "-o of the running listener")
		assert.Equal(t, sshdValue{Value: nil, Source: "unset"}, d.Effective["PermitEmptyPasswords"], "no default filled in")
		assert.Equal(t, sshdValue{Value: false, Source: "/etc/ssh/sshd_config:7"}, d.Effective["Banner"], "none is not set")
		assert.Equal(t, sshdValue{Value: true, Source: "/etc/ssh/sshd_config:8"}, d.Effective["AuthorizedKeysCommand"], "only whether it is set")
		assert.Len(t, d.Effective, len(sshdEffectiveKeys))
	})

	t.Run("match blocks", func(t *testing.T) {
		require.Len(t, d.MatchBlocks, 2)
		assert.Equal(t, []string{"User", "deploy"}, d.MatchBlocks[0].Criteria)
		assert.True(t, d.MatchBlocks[0].Evaluable)
		assert.Equal(t, "yes", d.MatchBlocks[0].Keys["PasswordAuthentication"].Value)
		assert.False(t, d.MatchBlocks[1].Evaluable, "an address depends on the connection")
		assert.NotContains(t, d.MatchBlocks[1].Keys, "PasswordAuthentication", "blocks list only what they set")
	})

	t.Run("listener and files", func(t *testing.T) {
		assert.True(t, d.Listener.Found)
		assert.True(t, d.Listener.FlagsFromCmdline)
		require.NotNil(t, d.Listener.StartedAt)
		assert.Equal(t, time.Unix(1794700000+12345, 0).UTC(), *d.Listener.StartedAt, "btime + ticks/100")
		assert.True(t, d.ConfigValid)
		assert.Equal(t, "/etc/ssh/sshd_config", d.ConfigFile)
		require.Len(t, d.Files, 2)
		assert.Equal(t, "/etc/ssh/sshd_config", d.Files[0].Path)
		assert.Regexp(t, `^[0-9a-f]{64}$`, d.Files[0].SHA256)
		assert.False(t, d.Files[0].MTime.IsZero())
		require.NotNil(t, d.PAMCompiled)
		assert.True(t, *d.PAMCompiled, "sshd-session links libpam")
	})

	t.Run("the result for authorizedKeys", func(t *testing.T) {
		require.NotNil(t, res)
		assert.Equal(t, defaultAuthorizedKeysFiles, res.authorizedKeysFiles)
		assert.Equal(t, map[string][]string{"deploy": {"/etc/ssh/keys/%u"}}, res.userKeysFiles)
		assert.True(t, res.strictModes)
		assert.True(t, res.keysCommand)
		assert.False(t, res.trustedCA)
	})

	t.Run("no command line of a key command on the wire", func(t *testing.T) {
		assert.NotContains(t, toJSON(t, sec), "SENTINELSECRET")
		assert.NotContains(t, toJSON(t, sec), "fetch-keys")
	})
}

func TestSSHDFlags(t *testing.T) {
	t.Run("no listener: flags from the unit and its environment file", func(t *testing.T) {
		files := merge(hostProc(), sshdFixture(), map[string]string{
			"etc/default/ssh":     "SSHD_OPTS=\"-f /etc/ssh/alt_config -p 2222\"\n",
			"etc/ssh/alt_config":  "PermitRootLogin no\nPort 22\n",
			"proc/700/cmdline":    "sshd: alice@pts/0\x00", // a session only
			"etc/systemd/system/": "",
		})
		_, d, _ := sshdOf(t, files)

		assert.False(t, d.Listener.Found)
		assert.Equal(t, "/etc/ssh/alt_config", d.ConfigFile)
		assert.Equal(t, sshdValue{Value: []string{"2222"}, Source: "cmdline"}, d.Effective["Port"], "-p drops the Port lines")
		assert.Equal(t, "no", d.Effective["PermitRootLogin"].Value)
	})

	t.Run("a drop-in replaces ExecStart", func(t *testing.T) {
		files := merge(hostProc(), sshdFixture(), map[string]string{
			"proc/700/cmdline": "sshd: alice@pts/0\x00",
			"etc/systemd/system/ssh.service.d/override.conf": "[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -o PermitRootLogin=no\n",
		})
		_, d, _ := sshdOf(t, files)

		assert.Equal(t, sshdValue{Value: "no", Source: "cmdline"}, d.Effective["PermitRootLogin"])
	})

	t.Run("sshd in a container is not the host's", func(t *testing.T) {
		files := merge(hostProc(), sshdFixture(), map[string]string{"proc/700/ns/mnt": "-> mnt:[4026532900]"})
		_, d, _ := sshdOf(t, files)

		assert.False(t, d.Listener.Found)
		assert.NotContains(t, d.Effective["MaxAuthTries"].Source, "cmdline")
	})

	t.Run("socket activation without a listener (Ubuntu 24.04)", func(t *testing.T) {
		files := merge(hostProc(), sshdFixture(), map[string]string{
			"proc/700/cmdline": "sshd: alice@pts/0\x00",
			"etc/systemd/system/sockets.target.wants/ssh.socket": "-> /lib/systemd/system/ssh.socket",
			"lib/systemd/system/ssh.socket":                      "",
		})
		_, d, _ := sshdOf(t, files)

		assert.True(t, d.SocketActivated)
		assert.False(t, d.Listener.Found)
	})

	t.Run("Alpine: conf.d, no PAM in the binaries", func(t *testing.T) {
		files := map[string]string{
			"etc/ssh/sshd_config": "PasswordAuthentication yes\n",
			"etc/conf.d/sshd":     "SSHD_OPTS=\"-o PermitRootLogin=yes\"\n",
			"usr/sbin/sshd":       "\x7fELF...libc.musl-x86_64.so.1",
		}
		_, d, _ := sshdOf(t, merge(hostProc(), files))

		assert.Equal(t, sshdValue{Value: "yes", Source: "cmdline"}, d.Effective["PermitRootLogin"])
		require.NotNil(t, d.PAMCompiled)
		assert.False(t, *d.PAMCompiled)
	})
}

func TestSSHDStatus(t *testing.T) {
	t.Run("not installed: na", func(t *testing.T) {
		sec, _, res := sshdOf(t, hostProc())
		assert.Equal(t, StatusNA, sec.Status)
		require.NotNil(t, res)
		assert.True(t, res.notInstalled, "authorizedKeys is na too")
	})

	t.Run("an unreadable main config (RHEL, 0600, no root): unknown, not defaults", func(t *testing.T) {
		sc := fixture(t, merge(hostProc(), sshdFixture()))
		unreadable(t, sc, "etc/ssh/sshd_config")
		sec, res := collectSSHD(t.Context(), sc)

		assert.Equal(t, StatusUnknown, sec.Status)
		assert.Equal(t, ReasonPermissionDenied, sec.Reason)
		assert.Nil(t, res)
	})

	t.Run("an unreadable drop-in: partial, the config is not valid as read", func(t *testing.T) {
		sc := fixture(t, merge(hostProc(), sshdFixture()))
		unreadable(t, sc, "etc/ssh/sshd_config.d/50-cloud-init.conf")
		sec, _ := collectSSHD(t.Context(), sc)

		assert.Equal(t, StatusPartial, sec.Status)
		assert.Equal(t, []Gap{{Path: "/etc/ssh/sshd_config.d/50-cloud-init.conf", Reason: ReasonPermissionDenied}}, sec.Gaps)
		assert.False(t, sec.Data.(sshdData).ConfigValid)
	})

	t.Run("refused lines and unknown keywords: codes, not text", func(t *testing.T) {
		files := merge(hostProc(), sshdFixture())
		files["etc/ssh/sshd_config"] += "DebianBanner no\nBanner \"SENTINELLINE\n"
		sec, d, _ := sshdOf(t, files)

		assert.Equal(t, []lineRef{{File: "/etc/ssh/sshd_config", Line: 15, Code: "DebianBanner"}}, d.UnknownKeywords)
		assert.Equal(t, []lineRef{{File: "/etc/ssh/sshd_config", Line: 16, Code: "unterminated_quote"}}, d.ParseErrors)
		assert.False(t, d.ConfigValid)
		assert.NotContains(t, toJSON(t, sec), "SENTINELLINE")
	})
}

func TestProcessStart(t *testing.T) {
	sc := fixture(t, map[string]string{
		"proc/9/stat": "9 (a) b) c) S 1 9 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0\n", // parentheses in comm
		"proc/stat":   "btime 1000\n",
	})

	got := processStart(sc, "9")

	require.NotNil(t, got)
	assert.Equal(t, time.Unix(1005, 0).UTC(), *got)
	assert.Nil(t, processStart(sc, "10"))
}

func TestExpandEnv(t *testing.T) {
	env := map[string]string{"SSHD_OPTS": "-p 2222", "X": "x"}
	assert.Equal(t, "/usr/sbin/sshd -D -p 2222", expandEnv("/usr/sbin/sshd -D $SSHD_OPTS", env))
	assert.Equal(t, "a-x-b", expandEnv("a-${X}-b", env))
	assert.Equal(t, "a  b", expandEnv("a $MISSING b", env))
	assert.Equal(t, "cost$", expandEnv("cost$", env))
}

func TestSSHDConfigSymlinkedDir(t *testing.T) {
	files := merge(hostProc(), sshdFixture())
	root := t.TempDir()
	writeTree(t, root, files)
	require.NoError(t, os.RemoveAll(filepath.Join(root, "etc/ssh/sshd_config.d")))
	require.NoError(t, os.Mkdir(filepath.Join(root, "conf.d"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "conf.d/10-x.conf"), []byte("PermitRootLogin no\n"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(root, "conf.d"), filepath.Join(root, "etc/ssh/sshd_config.d")))
	sc := &scanCtx{root: root}

	sec, _ := collectSSHD(t.Context(), sc)

	d := sec.Data.(sshdData)
	assert.Equal(t, "no", d.Effective["PermitRootLogin"].Value, "a symlinked drop-in directory is followed, as sshd does")
	assert.Len(t, d.Effective, len(sshdEffectiveKeys))
}
