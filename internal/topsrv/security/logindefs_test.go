package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginDefs(t *testing.T) {
	t.Run("Debian, a drop-in, values of a form shadow refuses", func(t *testing.T) {
		var gaps gapList
		got := collectLoginDefs(fixture(t, map[string]string{
			"etc/login.defs": "# comment\nMAIL_DIR        /var/mail\nUMASK\t\t022\nPASS_MAX_DAYS\t99999\n" +
				"PASS_MIN_DAYS\t0\nENCRYPT_METHOD SHA512\nUID_MIN 1000\nPASS_WARN_AGE SENTINEL\n",
			"etc/login.defs.d/50-local.conf": "PASS_MAX_DAYS 365\nENCRYPT_METHOD YESCRYPT\n",
			"etc/login.defs.d/README":        "PASS_MAX_DAYS 1\n",
		}), &gaps)
		assert.Empty(t, gaps)
		assert.Equal(t, map[string]string{"UMASK": "022", "PASS_MAX_DAYS": "365", "PASS_MIN_DAYS": "0",
			"ENCRYPT_METHOD": "YESCRYPT", "UID_MIN": "1000", "PASS_WARN_AGE": valueInvalid}, got)
	})
	t.Run("the vendor file when /etc has none", func(t *testing.T) {
		var gaps gapList
		got := collectLoginDefs(fixture(t, map[string]string{"usr/etc/login.defs": "PASS_MAX_DAYS 90\n"}), &gaps)
		assert.Equal(t, map[string]string{"PASS_MAX_DAYS": "90"}, got)
	})
	t.Run("none: Alpine without shadow", func(t *testing.T) {
		var gaps gapList
		assert.Nil(t, collectLoginDefs(fixture(t, nil), &gaps))
		assert.Empty(t, gaps)
	})
}

func TestShells(t *testing.T) {
	var gaps gapList
	shells := collectShells(fixture(t, map[string]string{"etc/shells": "# /etc/shells\n/bin/sh\n/bin/bash\n/usr/bin/zsh\n"}), &gaps)
	assert.True(t, shells["/bin/bash"])
	assert.False(t, shells["/usr/sbin/nologin"])
	assert.Equal(t, map[string]bool{"/bin/sh": true, "/bin/csh": true}, collectShells(fixture(t, nil), &gaps), "getusershell's default")
	assert.Empty(t, gaps)
}

func TestPAMNullok(t *testing.T) {
	var gaps gapList
	got := collectPAMNullok(fixture(t, map[string]string{
		// Debian 12 common-auth as shipped
		"etc/pam.d/common-auth":     "auth\t[success=1 default=ignore]\tpam_unix.so nullok\nauth\trequisite\t\t\tpam_deny.so\n",
		"etc/pam.d/common-password": "password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n",
		// RHEL 9 authselect
		"etc/pam.d/system-auth": "auth        sufficient                                   pam_unix.so nullok\n",
		"etc/pam.d/sshd":        "# pam_unix.so nullok in a comment\n@include common-auth\n",
		"etc/pam.d/su":          "-auth [default=ignore success=ok] /lib/x86_64-linux-gnu/security/pam_unix.so try_first_pass nullok_secure\n",
		"etc/pam.d/other":       "auth required pam_exec.so /usr/bin/SENTINEL SENTINELSECRET nullok\n",
		"usr/lib/pam.d/login":   "auth sufficient pam_unix.so nullok\n",
		"usr/lib/pam.d/sshd":    "auth sufficient pam_unix.so nullok\n", // overridden by /etc/pam.d/sshd
	}), &gaps)
	assert.Empty(t, gaps)
	assert.Equal(t, []string{"/etc/pam.d/common-auth", "/etc/pam.d/su", "/etc/pam.d/system-auth", "/usr/lib/pam.d/login"}, got)

	assert.Nil(t, collectPAMNullok(fixture(t, nil), &gaps), "no PAM")
	empty := collectPAMNullok(fixture(t, map[string]string{"etc/pam.d/": ""}), &gaps)
	require.NotNil(t, empty)
	assert.Empty(t, empty)
}

func TestAccountsShellListed(t *testing.T) {
	_, d, _ := accountsOf(t, merge(accountsFixture(), map[string]string{"etc/shells": "/bin/bash\n/bin/sh\n"}))
	byName := map[string]account{}
	for _, u := range d.Users {
		byName[u.Name] = u
	}
	assert.True(t, *byName["root"].ShellListed)
	assert.False(t, *byName["alice"].ShellListed, "/bin/zsh is not listed")
	assert.False(t, *byName["daemon"].ShellListed)
}
