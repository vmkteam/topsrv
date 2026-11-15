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
	return merge(files, testdataTree(t, "apt/ubuntu-24.04")) // writeTree joins "/etc/..." under the root
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
		_, d := updatesOf(t, merge(map[string]string{"var/lib/dpkg/status": ""}, testdataTree(t, "apt/debian-12")))
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
	t.Run("entries apt does not read", func(t *testing.T) {
		files := ubuntuUpdates(t)
		files["etc/apt/apt.conf.d/backup/"] = ""
		files["etc/apt/apt.conf.d/60gone"] = "-> ../removed.conf"
		files["etc/apt/apt.conf.d/70local"] = "-> ../local.conf"
		files["etc/apt/local.conf"] = "Unattended-Upgrade::Automatic-Reboot \"true\";\n"
		sec, d := updatesOf(t, files)
		require.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
		assert.True(t, d.APT.ConfigValid, "a directory and a dangling link are skipped, as apt skips them")
		assert.Equal(t, "true", *d.APT.Unattended.AutoReboot, "a link to a file is read")
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
	t.Run("Fedora: dnf5 reads five sources, later keys win", func(t *testing.T) {
		_, d := updatesOf(t, map[string]string{
			"usr/lib/sysimage/rpm/rpmdb.sqlite": "",
			"usr/share/dnf5/dnf5-plugins/automatic.conf": "[commands]\napply_updates = no\nupgrade_type = default\n" +
				"reboot = never\ndownload_updates = no\n",
			"usr/share/dnf5/dnf5-plugins/automatic.conf.d/10-vendor.conf": "[commands]\ndownload_updates = yes\n",
			"etc/dnf/dnf5-plugins/automatic.conf":                         "[commands]\nupgrade_type = SENTINEL\n",
			"etc/dnf/automatic.conf":                                      "[commands]\napply_updates = yes\n",
			"etc/dnf/automatic.conf.d/90-local.conf":                      "[commands]\nreboot = when-needed\n",
			"etc/dnf/automatic.conf.d/README":                             "[commands]\nreboot = never\n", // not *.conf
			"usr/lib/systemd/system/dnf5-automatic.timer":                 "",
			"usr/lib/systemd/system/dnf-automatic.timer":                  "-> dnf5-automatic.timer", // systemctl: alias
			"run/systemd/system/":                                         "",
		})
		a := d.DNFAutomatic
		assert.True(t, a.DNF5)
		assert.Equal(t, "yes", *a.ApplyUpdates, "/etc/dnf/automatic.conf, read by dnf5 since 5.2.7")
		assert.Equal(t, "yes", *a.DownloadUpdates)
		assert.Equal(t, valueInvalid, *a.UpgradeType)
		assert.Equal(t, "when-needed", *a.Reboot)
		assert.Equal(t, []string{
			"/usr/share/dnf5/dnf5-plugins/automatic.conf", "/usr/share/dnf5/dnf5-plugins/automatic.conf.d/10-vendor.conf",
			"/etc/dnf/dnf5-plugins/automatic.conf", "/etc/dnf/automatic.conf", "/etc/dnf/automatic.conf.d/90-local.conf",
		}, pathsOf(a.Files))
		assert.Equal(t, []timerState{{Name: "dnf5-automatic.timer"}}, d.Timers, "the alias is left out")
	})
	t.Run("an ostree host updates by rpm-ostreed or bootc", func(t *testing.T) {
		_, d := updatesOf(t, map[string]string{
			"usr/lib/sysimage/rpm/rpmdb.sqlite":                                          "",
			"run/ostree-booted":                                                          "",
			"run/systemd/system/":                                                        "",
			"usr/lib/systemd/system/dnf5-automatic.timer":                                "",
			"usr/lib/systemd/system/rpm-ostreed-automatic.timer":                         "",
			"usr/lib/systemd/system/bootc-fetch-apply-updates.timer":                     "",
			"usr/lib/systemd/system/timers.target.wants/bootc-fetch-apply-updates.timer": "-> ../bootc-fetch-apply-updates.timer",
		})
		assert.True(t, d.OSTreeBooted, "dnf-automatic timers do not run there")
		assert.Equal(t, []timerState{{Name: "dnf5-automatic.timer"}, {Name: "rpm-ostreed-automatic.timer"},
			{Name: "bootc-fetch-apply-updates.timer", Enabled: true}}, d.Timers)
	})
	t.Run("no dnf-automatic", func(t *testing.T) {
		_, d := updatesOf(t, map[string]string{"var/lib/rpm/rpmdb.sqlite": ""})
		assert.Equal(t, &dnfAutomatic{Files: []fileMeta{}}, d.DNFAutomatic)
	})
}

func TestUpdatesAPK(t *testing.T) {
	const job = "#!/bin/sh\napk update && apk upgrade --available\n"
	sc := fixture(t, map[string]string{
		"lib/apk/db/installed":              "",
		"etc/crontabs/root":                 "# min hour day month weekday command\n*/15 * * * * run-parts /etc/periodic/15min\n",
		"etc/periodic/daily/apk-upgrade":    job,
		"etc/periodic/daily/apk-upgrade.sh": job, // busybox 1.36 runs a name with a dot
		"etc/periodic/daily/apk-upgrade~":   job, // run-parts skips the name
		"etc/periodic/daily/.apk-upgrade":   job, // and a leading dot
		"etc/periodic/weekly/no-exec-bit":   job, // and a file it may not execute
		"etc/periodic/weekly/commented":     "#!/bin/sh\n# apk upgrade\n",
		"etc/periodic/monthly/apk-fix":      "#!/bin/sh\napk fix\n",
		"etc/periodic/daily/old/":           "", // and a subdirectory
		"etc/periodic/README":               "not a directory",
	})
	for _, p := range []string{"daily/apk-upgrade", "daily/apk-upgrade.sh", "daily/apk-upgrade~", "daily/.apk-upgrade",
		"weekly/commented", "monthly/apk-fix"} {
		require.NoError(t, os.Chmod(filepath.Join(sc.root, "etc/periodic", p), 0o755))
	}
	sec := collectUpdates(t.Context(), sc)
	d := sec.Data.(updatesData)
	assert.Equal(t, StatusOK, sec.Status, "gaps: %v", sec.Gaps)
	assert.Equal(t, "apk", d.Manager)
	assert.Equal(t, []string{"/etc/periodic/daily/apk-upgrade", "/etc/periodic/daily/apk-upgrade.sh"}, d.APK.UpgradeJobs)
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

func pathsOf(files []fileMeta) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}
