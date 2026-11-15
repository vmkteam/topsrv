package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ubuntuUpdates is Ubuntu 24.04 with unattended-upgrades enabled: the real
// apt.conf.d of testdata, the timers enabled, apt-daily run once.
func ubuntuUpdates(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{
		"var/lib/dpkg/status":                                            "",
		"usr/bin/unattended-upgrade":                                     "",
		"run/systemd/system/":                                            "",
		"usr/lib/systemd/system/apt-daily.timer":                         "",
		"usr/lib/systemd/system/apt-daily-upgrade.timer":                 "",
		"etc/systemd/system/timers.target.wants/apt-daily.timer":         "-> /usr/lib/systemd/system/apt-daily.timer",
		"etc/systemd/system/timers.target.wants/apt-daily-upgrade.timer": "-> /usr/lib/systemd/system/apt-daily-upgrade.timer",
		"var/lib/systemd/timers/stamp-apt-daily.timer":                   "",
		"var/lib/apt/periodic/update-stamp":                              "",
		"var/lib/apt/periodic/download-upgradeable-stamp":                "",
	}
	for p, content := range testdataTree(t, "apt/ubuntu-24.04") {
		files[strings.TrimPrefix(p, "/")] = content
	}
	return files
}

func updatesOf(t *testing.T, files map[string]string) (Section, updatesData) {
	t.Helper()
	sec := collectUpdates(t.Context(), fixture(t, files))
	d, _ := sec.Data.(updatesData)
	return sec, d
}

func TestUpdatesAPT(t *testing.T) {
	sec, d := updatesOf(t, ubuntuUpdates(t))

	require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	assert.Equal(t, "dpkg", d.Manager)
	require.NotNil(t, d.APT)
	assert.Nil(t, d.DNFAutomatic)
	a := d.APT
	assert.True(t, a.ConfigValid)
	assert.Equal(t, aptPeriodic{UpdatePackageLists: new("1"), UnattendedUpgrade: new("1")}, a.Periodic)
	assert.True(t, a.Unattended.Installed)
	assert.Equal(t, []string{"${distro_id}:${distro_codename}", "${distro_id}:${distro_codename}-security",
		"${distro_id}ESMApps:${distro_codename}-apps-security", "${distro_id}ESM:${distro_codename}-infra-security"},
		a.Unattended.AllowedOrigins, "Ubuntu lists Allowed-Origins")
	assert.Empty(t, a.Unattended.OriginsPatterns)
	assert.Nil(t, a.Unattended.AutoReboot, "commented out in 50unattended-upgrades")
	assert.NotNil(t, a.Stamps.Update)
	assert.NotNil(t, a.Stamps.DownloadUpgradeable)
	assert.Nil(t, a.Stamps.UpdateSuccess)
	assert.Nil(t, a.Stamps.Upgrade, "unattended-upgrade never ran")
	assert.Len(t, a.Files, 6)
	assert.Empty(t, a.ParseErrors)
	require.Len(t, d.Timers, 2)
	assert.Equal(t, "apt-daily.timer", d.Timers[0].Name)
	assert.True(t, d.Timers[0].Enabled)
	assert.False(t, d.Timers[0].Masked)
	assert.NotNil(t, d.Timers[0].LastTriggerAt)
	assert.Nil(t, d.Timers[1].LastTriggerAt)
	assert.NotNil(t, d.LastPkgDBChangeAt)
}

func TestUpdatesAPTEdges(t *testing.T) {
	t.Run("Debian lists Origins-Pattern", func(t *testing.T) {
		files := map[string]string{"var/lib/dpkg/status": ""}
		for p, content := range testdataTree(t, "apt/debian-12") {
			files[strings.TrimPrefix(p, "/")] = content
		}
		_, d := updatesOf(t, files)
		assert.Len(t, d.APT.Unattended.OriginsPatterns, 3)
		assert.Empty(t, d.APT.Unattended.AllowedOrigins)
		assert.False(t, d.APT.Unattended.Installed)
		assert.Empty(t, d.Timers, "no systemd")
	})
	t.Run("values of an unexpected form", func(t *testing.T) {
		_, d := updatesOf(t, map[string]string{
			"var/lib/dpkg/status": "",
			"etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Update-Package-Lists \"always\";\n" +
				"APT::Periodic::Unattended-Upgrade \"weekly\";\nUnattended-Upgrade::Automatic-Reboot \"maybe\";\n",
		})
		assert.Equal(t, "always", *d.APT.Periodic.UpdatePackageLists)
		assert.Equal(t, valueInvalid, *d.APT.Periodic.UnattendedUpgrade)
		assert.Equal(t, valueInvalid, *d.APT.Unattended.AutoReboot)
	})
	t.Run("a line apt refuses", func(t *testing.T) {
		sec, d := updatesOf(t, map[string]string{
			"var/lib/dpkg/status":                "",
			"etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic x y;\n",
		})
		assert.Equal(t, StatusOK, sec.Status, "apt refusing a file is a fact, not a gap")
		assert.False(t, d.APT.ConfigValid)
		assert.Equal(t, []lineRef{{File: aptConfDir + "/20auto-upgrades", Line: 2, Code: aptCodeExtraJunk}}, d.APT.ParseErrors)
	})
	t.Run("too many origins", func(t *testing.T) {
		list := strings.Repeat("\"o\";", maxOrigins+1)
		_, d := updatesOf(t, map[string]string{
			"var/lib/dpkg/status":                      "",
			"etc/apt/apt.conf.d/50unattended-upgrades": "Unattended-Upgrade::Origins-Pattern {" + list + "};\n",
		})
		assert.Len(t, d.APT.Unattended.OriginsPatterns, maxOrigins)
		assert.True(t, d.APT.Unattended.Truncated)
	})
	t.Run("a masked timer", func(t *testing.T) {
		files := ubuntuUpdates(t)
		files["etc/systemd/system/apt-daily-upgrade.timer"] = "-> /dev/null"
		_, d := updatesOf(t, files)
		assert.True(t, d.Timers[1].Masked)
		assert.True(t, d.Timers[1].Enabled, "the wants link stays, the mask wins: the backend weighs both")
	})
	t.Run("masked by an empty file", func(t *testing.T) {
		files := ubuntuUpdates(t)
		files["etc/systemd/system/apt-daily.timer"] = ""
		_, d := updatesOf(t, files)
		assert.True(t, d.Timers[0].Masked)
	})
	t.Run("an include that is not there", func(t *testing.T) {
		sec, d := updatesOf(t, map[string]string{
			"var/lib/dpkg/status":       "",
			"etc/apt/apt.conf.d/10site": "#include /etc/apt/site.conf;\n",
		})
		assert.Equal(t, StatusPartial, sec.Status)
		assert.Equal(t, []Gap{{Path: "/etc/apt/site.conf", Reason: ReasonNotFound}}, sec.Gaps)
		assert.False(t, d.APT.ConfigValid, "apt fails on it")
	})
	t.Run("an unreadable apt.conf.d", func(t *testing.T) {
		sc := fixture(t, map[string]string{"var/lib/dpkg/status": "", "etc/apt/apt.conf.d/20auto-upgrades": ""})
		unreadable(t, sc, "etc/apt/apt.conf.d")
		t.Cleanup(func() { require.NoError(t, os.Chmod(filepath.Join(sc.root, "etc/apt/apt.conf.d"), 0o755)) }) // TempDir removes it
		sec := collectUpdates(t.Context(), sc)
		assert.Equal(t, StatusPartial, sec.Status)
		assert.False(t, sec.Data.(updatesData).APT.ConfigValid)
	})
}

func TestUpdatesDNF(t *testing.T) {
	rocky := map[string]string{
		"var/lib/rpm/rpmdb.sqlite": "",
		"run/systemd/system/":      "",
		"etc/dnf/automatic.conf": "[commands]\nupgrade_type = default\nrandom_sleep = 0\ndownload_updates = yes\n" +
			"apply_updates = no\nreboot = never\nreboot_command = \"shutdown -r +5 'Rebooting after applying package updates'\"\n" +
			"[emitters]\nemit_via = stdio\n[email]\nemail_from = root@example.com\n",
		"usr/lib/systemd/system/dnf-automatic.timer":                         "",
		"usr/lib/systemd/system/dnf-automatic-install.timer":                 "",
		"etc/systemd/system/timers.target.wants/dnf-automatic-install.timer": "-> /usr/lib/systemd/system/dnf-automatic-install.timer",
	}
	t.Run("Rocky 9: install timer over apply_updates = no", func(t *testing.T) {
		sec, d := updatesOf(t, rocky)
		require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
		assert.Equal(t, "rpm", d.Manager)
		assert.Equal(t, &dnfAutomatic{Installed: true, ApplyUpdates: new("no"), DownloadUpdates: new("yes"),
			UpgradeType: new("default"), Reboot: new("never"), Files: d.DNFAutomatic.Files}, d.DNFAutomatic)
		assert.Equal(t, []timerState{{Name: "dnf-automatic.timer"}, {Name: "dnf-automatic-install.timer", Enabled: true}}, d.Timers)
	})
	t.Run("Fedora: dnf5, /etc overrides /usr/share", func(t *testing.T) {
		_, d := updatesOf(t, map[string]string{
			"usr/lib/sysimage/rpm/rpmdb.sqlite":           "",
			"usr/share/dnf5/dnf5-plugins/automatic.conf":  "[commands]\napply_updates = no\nupgrade_type = default\n",
			"etc/dnf/dnf5-plugins/automatic.conf":         "[commands]\napply_updates = yes\nupgrade_type = SENTINEL\n",
			"usr/lib/systemd/system/dnf5-automatic.timer": "",
			"usr/lib/systemd/system/dnf-automatic.timer":  "-> dnf5-automatic.timer", // systemctl: alias
			"run/systemd/system/":                         "",
		})
		assert.True(t, d.DNFAutomatic.DNF5)
		assert.Equal(t, "yes", *d.DNFAutomatic.ApplyUpdates)
		assert.Equal(t, valueInvalid, *d.DNFAutomatic.UpgradeType)
		assert.Len(t, d.DNFAutomatic.Files, 2)
		assert.Equal(t, []timerState{{Name: "dnf5-automatic.timer"}}, d.Timers, "the alias is left out")
	})
	t.Run("no dnf-automatic", func(t *testing.T) {
		_, d := updatesOf(t, map[string]string{"var/lib/rpm/rpmdb.sqlite": ""})
		assert.Equal(t, &dnfAutomatic{Files: []fileMeta{}}, d.DNFAutomatic)
	})
}

func TestUpdatesAPK(t *testing.T) {
	sec, d := updatesOf(t, map[string]string{
		"lib/apk/db/installed":           "",
		"etc/crontabs/root":              "# min hour day month weekday command\n*/15 * * * * run-parts /etc/periodic/15min\n",
		"etc/periodic/daily/apk-upgrade": "#!/bin/sh\napk update && apk upgrade --available\n",
		"etc/periodic/weekly/commented":  "#!/bin/sh\n# apk upgrade\n",
		"etc/periodic/monthly/apk-fix":   "#!/bin/sh\napk fix\n",
		"etc/periodic/daily/old/":        "", // run-parts skips it
		"etc/periodic/README":            "not a directory",
	})
	assert.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	assert.Equal(t, "apk", d.Manager)
	assert.Equal(t, []string{"/etc/periodic/daily/apk-upgrade"}, d.APK.UpgradeJobs)
}

func TestUpdatesNoManager(t *testing.T) {
	sec, _ := updatesOf(t, map[string]string{"etc/os-release": "ID=unknown\n"})
	assert.Equal(t, StatusNA, sec.Status)
}

func TestUpdatesStampTimes(t *testing.T) {
	sc := fixture(t, map[string]string{"var/lib/dpkg/status": "", "var/lib/apt/periodic/upgrade-stamp": ""})
	at := time.Date(2026, 11, 14, 6, 25, 0, 0, time.UTC)
	require.NoError(t, os.Chtimes(filepath.Join(sc.root, "var/lib/apt/periodic/upgrade-stamp"), at, at))
	d := collectUpdates(t.Context(), sc).Data.(updatesData)
	assert.Equal(t, at, *d.APT.Stamps.Upgrade)
}
