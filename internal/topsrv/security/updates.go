package security

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/inventory"
)

// Paths the updates section reads (§7.8).
const (
	pathUnattendedUpgrade = "/usr/bin/unattended-upgrade"
	pathAPTPeriodic       = "/var/lib/apt/periodic"
	pathTimerStamps       = "/var/lib/systemd/timers"
	pathDNFAutomatic      = "/etc/dnf/automatic.conf"
	pathDNF5AutomaticUsr  = "/usr/share/dnf5/dnf5-plugins/automatic.conf"
	pathDNF5AutomaticEtc  = "/etc/dnf/dnf5-plugins/automatic.conf"
	pathAlpineCrontab     = "/etc/crontabs/root"
	pathAlpinePeriodic    = "/etc/periodic"
)

// Limits of the updates section.
const (
	updatesFileLimit = 256 << 10
	maxOrigins       = 64  // per list
	maxOriginLen     = 256 // an origin pattern longer than this is cut off
)

type updatesData struct {
	// Manager is the package manager of the host: dpkg, rpm or apk.
	Manager      string        `json:"manager"`
	APT          *aptUpdates   `json:"apt"`          // null unless dpkg
	DNFAutomatic *dnfAutomatic `json:"dnfAutomatic"` // null unless rpm
	APK          *apkUpdates   `json:"apk"`          // null unless apk
	// Timers are the systemd timers of the manager's update tools that are
	// installed; empty without systemd.
	Timers            []timerState `json:"timers"`
	LastPkgDBChangeAt *time.Time   `json:"lastPkgDbChangeAt"`
}

type aptUpdates struct {
	// ConfigValid: apt reads the configuration; false — a line it refuses
	// (parseErrors), and every apt command fails until it is fixed.
	ConfigValid bool          `json:"configValid"`
	Periodic    aptPeriodic   `json:"periodic"`
	Unattended  aptUnattended `json:"unattended"`
	Stamps      aptStamps     `json:"stamps"`
	Files       []fileMeta    `json:"files"`
	ParseErrors []lineRef     `json:"parseErrors"`
}

// aptPeriodic are the APT::Periodic intervals apt.systemd.daily reads: a
// number of days, with an s, m, h or d suffix, or "always"; "0" is off.
// null when not set.
type aptPeriodic struct {
	Enable                      *string `json:"enable"`
	UpdatePackageLists          *string `json:"updatePackageLists"`
	DownloadUpgradeablePackages *string `json:"downloadUpgradeablePackages"`
	UnattendedUpgrade           *string `json:"unattendedUpgrade"`
}

type aptUnattended struct {
	Installed bool `json:"installed"`
	// OriginsPatterns (Debian) and AllowedOrigins (Ubuntu) are the archives
	// unattended-upgrade installs from, as written: ${distro_codename} and
	// the like are not expanded.
	OriginsPatterns []string `json:"originsPatterns"`
	AllowedOrigins  []string `json:"allowedOrigins"`
	AutoReboot      *string  `json:"autoReboot"`
	Truncated       bool     `json:"truncated,omitempty"` // a list was cut at maxOrigins
}

// aptStamps are the mtimes of what apt.systemd.daily touches when a step
// ran (update-success-stamp: the lists were fetched without an error).
type aptStamps struct {
	Update              *time.Time `json:"update"`
	UpdateSuccess       *time.Time `json:"updateSuccess"`
	DownloadUpgradeable *time.Time `json:"downloadUpgradeable"`
	Upgrade             *time.Time `json:"upgrade"`
}

type dnfAutomatic struct {
	Installed bool `json:"installed"` // a configuration file of dnf-automatic is there
	DNF5      bool `json:"dnf5"`
	// [commands] of the configuration; null when not set.
	ApplyUpdates    *string    `json:"applyUpdates"`
	DownloadUpdates *string    `json:"downloadUpdates"`
	UpgradeType     *string    `json:"upgradeType"`
	Reboot          *string    `json:"reboot"`
	Files           []fileMeta `json:"files"`
}

type apkUpdates struct {
	// UpgradeJobs are the cron files that run apk upgrade: Alpine has no
	// update service of its own.
	UpgradeJobs []string `json:"upgradeJobs"`
}

type timerState struct {
	Name          string     `json:"name"`
	Enabled       bool       `json:"enabled"`
	Masked        bool       `json:"masked"`
	LastTriggerAt *time.Time `json:"lastTriggerAt"`
}

// updateTimers are the timers that update packages, by manager.
var updateTimers = map[string][]string{
	inventory.ManagerDpkg: {"apt-daily.timer", "apt-daily-upgrade.timer"},
	inventory.ManagerRpm: {"dnf-automatic.timer", "dnf-automatic-download.timer", "dnf-automatic-install.timer",
		"dnf-automatic-notifyonly.timer", "dnf5-automatic.timer"},
}

// maskDirs are where a unit is masked: a mask in /usr is a packaging bug.
var maskDirs = []string{"/etc/systemd/system", "/run/systemd/system"}

func collectUpdates(_ context.Context, sc *scanCtx) Section {
	var gaps gapList
	manager, db := packageDB(sc)
	if manager == "" {
		return Section{Status: StatusNA}
	}
	d := updatesData{Manager: manager, Timers: []timerState{}}
	switch manager {
	case inventory.ManagerDpkg:
		d.APT = collectAPT(sc, &gaps)
	case inventory.ManagerRpm:
		d.DNFAutomatic = collectDNFAutomatic(sc, &gaps)
	case inventory.ManagerApk:
		d.APK = collectAPK(sc, &gaps)
	}
	if sc.exists("/run/systemd/system") {
		d.Timers = collectTimers(sc, updateTimers[manager], &gaps)
	}
	d.LastPkgDBChangeAt = mtimeOf(sc, db, &gaps)
	return collected(gaps, d)
}

// packageDB is the manager of the host and its database, in the order of
// inventory.Managers.
func packageDB(sc *scanCtx) (manager, path string) {
	if sc.exists(inventory.DpkgStatusPath) {
		return inventory.ManagerDpkg, inventory.DpkgStatusPath
	}
	for _, p := range inventory.RpmDBPaths() {
		if sc.exists(p) {
			return inventory.ManagerRpm, p
		}
	}
	if sc.exists(inventory.ApkInstalledPath) {
		return inventory.ManagerApk, inventory.ApkInstalledPath
	}
	return "", ""
}

func collectAPT(sc *scanCtx, gaps *gapList) *aptUpdates {
	cfg := readAPTConfig(aptFiles{
		readFile: func(p string) ([]byte, error) { return sc.read(p, updatesFileLimit) },
		readDir:  sc.readDirNames,
	})
	for _, re := range cfg.readErrs {
		gaps.add(re.path, re.err)
	}
	a := &aptUpdates{ConfigValid: cfg.err == nil && len(cfg.readErrs) == 0, Files: []fileMeta{}, ParseErrors: []lineRef{}}
	if cfg.err != nil {
		a.ParseErrors = append(a.ParseErrors, *cfg.err)
	}
	for _, p := range cfg.files {
		if m, err := statFile(sc, p); err == nil {
			a.Files = append(a.Files, m)
		}
	}
	a.Periodic = aptPeriodic{
		Enable:                      checked(cfg.value("APT::Periodic::Enable"), isAPTInterval),
		UpdatePackageLists:          checked(cfg.value("APT::Periodic::Update-Package-Lists"), isAPTInterval),
		DownloadUpgradeablePackages: checked(cfg.value("APT::Periodic::Download-Upgradeable-Packages"), isAPTInterval),
		UnattendedUpgrade:           checked(cfg.value("APT::Periodic::Unattended-Upgrade"), isAPTInterval),
	}
	u := &a.Unattended
	u.Installed = sc.exists(pathUnattendedUpgrade)
	u.OriginsPatterns, u.Truncated = capOrigins(cfg.list("Unattended-Upgrade::Origins-Pattern"), u.Truncated)
	u.AllowedOrigins, u.Truncated = capOrigins(cfg.list("Unattended-Upgrade::Allowed-Origins"), u.Truncated)
	u.AutoReboot = checked(cfg.value("Unattended-Upgrade::Automatic-Reboot"), isAPTBool)
	a.Stamps = aptStamps{
		Update:              mtimeOf(sc, pathAPTPeriodic+"/update-stamp", gaps),
		UpdateSuccess:       mtimeOf(sc, pathAPTPeriodic+"/update-success-stamp", gaps),
		DownloadUpgradeable: mtimeOf(sc, pathAPTPeriodic+"/download-upgradeable-stamp", gaps),
		Upgrade:             mtimeOf(sc, pathAPTPeriodic+"/upgrade-stamp", gaps),
	}
	return a
}

func capOrigins(list []string, truncated bool) ([]string, bool) {
	if len(list) > maxOrigins {
		list, truncated = list[:maxOrigins], true
	}
	for i, o := range list {
		if len(o) > maxOriginLen {
			list[i], truncated = o[:maxOriginLen], true
		}
	}
	return list, truncated
}

// checked returns v when valid accepts it, valueInvalid otherwise: the text
// of a configuration line is never sent, only a value the tool accepts.
func checked(v *string, valid func(string) bool) *string {
	if v == nil || valid(*v) {
		return v
	}
	s := valueInvalid
	return &s
}

var aptIntervalRe = regexp.MustCompile(`^(always|[0-9]{1,9}[smhd]?)$`)

// isAPTInterval is what apt.systemd.daily takes as an interval.
func isAPTInterval(v string) bool { return aptIntervalRe.MatchString(v) }

// boolWords are the booleans libdnf takes; apt takes these and more.
var (
	boolWords    = []string{"0", "1", "no", "yes", "false", "true", "off", "on"}
	aptBoolWords = slices.Concat(boolWords, []string{"without", "with", "disable", "enable"})
)

// isAPTBool is StringToBool of strutl.cc.
func isAPTBool(v string) bool { return slices.Contains(aptBoolWords, strings.ToLower(v)) }

func collectDNFAutomatic(sc *scanCtx, gaps *gapList) *dnfAutomatic {
	d := &dnfAutomatic{Files: []fileMeta{}}
	paths := []string{pathDNFAutomatic}
	if sc.exists(pathDNF5AutomaticUsr) || sc.exists(pathDNF5AutomaticEtc) {
		d.DNF5, paths = true, []string{pathDNF5AutomaticUsr, pathDNF5AutomaticEtc} // the second overrides
	}
	commands := map[string]string{}
	for _, p := range paths {
		b, err := sc.read(p, updatesFileLimit)
		if err != nil {
			gaps.optional(p, err)
			continue
		}
		d.Installed = true
		if m, err := statFile(sc, p); err == nil {
			d.Files = append(d.Files, m)
		}
		maps.Copy(commands, iniSection(string(b), "commands"))
	}
	get := func(k string, valid func(string) bool) *string {
		v, ok := commands[k]
		if !ok {
			return nil
		}
		return checked(&v, valid)
	}
	d.ApplyUpdates = get("apply_updates", isDNFBool)
	d.DownloadUpdates = get("download_updates", isDNFBool)
	d.UpgradeType = get("upgrade_type", oneOfFold("default", "security"))
	d.Reboot = get("reboot", oneOfFold("never", "when-changed", "when-needed"))
	return d
}

// isDNFBool is a boolean of the dnf configuration.
func isDNFBool(v string) bool { return slices.Contains(boolWords, strings.ToLower(v)) }

func oneOfFold(values ...string) func(string) bool {
	return func(v string) bool { return slices.Contains(values, strings.ToLower(v)) }
}

// iniSection returns the keys of one [section] of an INI file, later
// lines winning; "#" and ";" start comments.
func iniSection(text, section string) map[string]string {
	out := map[string]string{}
	in := false
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case line[0] == '[' && strings.HasSuffix(line, "]"):
			in = strings.TrimSpace(line[1:len(line)-1]) == section
		case in:
			if k, v, ok := strings.Cut(line, "="); ok {
				out[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// apkUpgradeRe is a cron line or script line that runs apk upgrade.
var apkUpgradeRe = regexp.MustCompile(`(^|[\s;&|/])apk\s([^#\n]*\s)?upgrade(\s|$)`)

func collectAPK(sc *scanCtx, gaps *gapList) *apkUpdates {
	a := &apkUpdates{UpgradeJobs: []string{}}
	files := []string{pathAlpineCrontab}
	dirs, err := sc.readDir(pathAlpinePeriodic)
	gaps.optional(pathAlpinePeriodic, err)
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		names, err := fileNames(sc.readDir(pathAlpinePeriodic + "/" + dir.Name())) // run-parts skips subdirectories
		gaps.optional(pathAlpinePeriodic+"/"+dir.Name(), err)
		for _, n := range names {
			files = append(files, pathAlpinePeriodic+"/"+dir.Name()+"/"+n)
		}
	}
	for _, p := range files {
		b, err := sc.read(p, updatesFileLimit)
		if err != nil {
			gaps.optional(p, err)
			continue
		}
		for line := range strings.SplitSeq(string(b), "\n") {
			if t := strings.TrimSpace(line); t != "" && t[0] != '#' && apkUpgradeRe.MatchString(t) {
				a.UpgradeJobs = append(a.UpgradeJobs, p)
				break
			}
		}
	}
	return a
}

// collectTimers reads the state of timers the way systemctl would, without
// D-Bus: a unit file in a unit directory is installed, a link in a
// timers.target.wants directory enables it, a link to /dev/null or an
// empty file in /etc or /run masks it, and a Persistent timer's stamp file
// is touched when it last fired.
func collectTimers(sc *scanCtx, names []string, gaps *gapList) []timerState {
	out := []timerState{}
	for _, name := range names {
		t := timerState{Name: name}
		installed, alias := false, false
		for _, dir := range unitDirs {
			if !installed && sc.exists(dir+"/"+name) {
				installed, alias = true, unitAlias(sc, dir+"/"+name)
			}
		}
		if alias {
			continue // its target is in the list itself (dnf-automatic → dnf5-automatic on Fedora)
		}
		for _, dir := range maskDirs {
			t.Masked = t.Masked || unitMasked(sc, dir+"/"+name)
		}
		if !installed && !t.Masked {
			continue
		}
		for _, dir := range unitDirs {
			t.Enabled = t.Enabled || sc.exists(dir+"/timers.target.wants/"+name)
		}
		t.LastTriggerAt = mtimeOf(sc, pathTimerStamps+"/stamp-"+name, gaps)
		out = append(out, t)
	}
	return out
}

// unitAlias: the unit file is a link to a unit of another name, as
// systemctl's "alias" state.
func unitAlias(sc *scanCtx, unit string) bool {
	target, err := sc.readlink(unit)
	return err == nil && target != "/dev/null" && path.Base(target) != path.Base(unit)
}

func unitMasked(sc *scanCtx, path string) bool {
	if target, err := sc.readlink(path); err == nil {
		return target == "/dev/null"
	}
	fi, err := sc.stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Size() == 0
}

// mtimeOf is the mtime of path; nil when it does not exist, a gap when it
// cannot be read.
func mtimeOf(sc *scanCtx, path string, gaps *gapList) *time.Time {
	fi, err := sc.stat(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			gaps.add(path, err)
		}
		return nil
	}
	t := fi.ModTime().UTC()
	return &t
}
