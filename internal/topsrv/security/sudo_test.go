package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sudoFixture is Debian's default policy with a cloud-init drop-in, a file
// sudo skips, and the host name for %h.
func sudoFixture() map[string]string {
	return map[string]string{
		"etc/sudoers": "Defaults\tuse_pty\nroot\tALL=(ALL:ALL) ALL\n%sudo\tALL=(ALL:ALL) ALL\n" +
			"@include /etc/sudoers.%h\n@includedir /etc/sudoers.d\n",
		"etc/sudoers.web1":            "deploy ALL = (root) NOPASSWD: /usr/bin/systemctl restart SENTINELCMD\n",
		"etc/sudoers.d/90-cloud-init": "ubuntu ALL=(ALL) NOPASSWD:ALL\n",
		"etc/sudoers.d/admin.conf":    "eve ALL=(ALL) NOPASSWD: ALL\n",
		"proc/sys/kernel/hostname":    "web1.example.com\n",
		"etc/nsswitch.conf":           "passwd: files\nsudoers: files sss\n",
	}
}

func TestSudoers(t *testing.T) {
	sec := collectSudoers(t.Context(), fixture(t, sudoFixture()))
	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	d := sec.Data.(sudoData)

	assert.True(t, d.SudoPresent)
	require.Len(t, d.Rules, 4)
	assert.Equal(t, sudoRule{Order: 3, Source: "/etc/sudoers.web1:1", Principals: []string{"deploy"}, HostsAll: true,
		Runas: &sudoRunas{Users: []string{"root"}, Groups: []string{}}, NopasswdAll: true, NopasswdAny: true}, d.Rules[2],
		"%h is the short host name")
	assert.Equal(t, 4, d.Rules[3].Order)
	assert.True(t, d.Rules[3].NopasswdAll)
	assert.Equal(t, []string{"/etc/sudoers.d/admin.conf"}, d.IgnoredFiles, "sudo never reads a name with a dot")
	assert.Equal(t, []string{"sss"}, d.ExternalSources)
	require.NotNil(t, d.Defaults.UsePTY)
	assert.True(t, *d.Defaults.UsePTY)
	assert.Nil(t, d.Defaults.Authenticate, "not set")
	assert.Nil(t, d.DoasRules, "no doas.conf")
	assert.Len(t, d.Files, 3)
	assert.NotContains(t, toJSON(t, sec), "SENTINELCMD", "command texts are not sent")
}

func TestSudoersStatus(t *testing.T) {
	t.Run("neither sudo nor doas: na", func(t *testing.T) {
		assert.Equal(t, StatusNA, collectSudoers(t.Context(), fixture(t, nil)).Status)
	})

	t.Run("sudoers 0440 without root: unknown, not empty", func(t *testing.T) {
		sc := fixture(t, sudoFixture())
		unreadable(t, sc, "etc/sudoers")
		sec := collectSudoers(t.Context(), sc)
		assert.Equal(t, StatusUnknown, sec.Status)
		assert.Equal(t, ReasonPermissionDenied, sec.Reason)
	})

	t.Run("an unreadable include: partial", func(t *testing.T) {
		sc := fixture(t, sudoFixture())
		unreadable(t, sc, "etc/sudoers.web1")
		sec := collectSudoers(t.Context(), sc)
		assert.Equal(t, StatusPartial, sec.Status)
		assert.Equal(t, []Gap{{Path: "/etc/sudoers.web1", Reason: ReasonPermissionDenied}}, sec.Gaps)
	})

	t.Run("Alpine: doas only", func(t *testing.T) {
		sec := collectSudoers(t.Context(), fixture(t, map[string]string{
			"etc/doas.conf":      "permit persist :wheel\n",
			"etc/doas.d/20.conf": "permit nopass deploy as root cmd /sbin/rc-service\n",
			"etc/doas.d/README":  "not a .conf",
		}))
		require.Equal(t, StatusOK, sec.Status)
		d := sec.Data.(sudoData)
		assert.False(t, d.SudoPresent)
		assert.Empty(t, d.Rules)
		assert.Equal(t, []doasRule{
			{Source: "/etc/doas.conf:1", Permit: true, Principal: ":wheel", Persist: true, AsRoot: true},
			{Source: "/etc/doas.d/20.conf:1", Permit: true, Principal: "deploy", Nopass: true, AsRoot: true, Cmd: true},
		}, d.DoasRules)
	})
}
