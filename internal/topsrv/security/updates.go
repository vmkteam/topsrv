package security

import (
	"context"
	"maps"
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
	pathOSTreeBooted      = "/run/ostree-booted"
)

// dnf5AutomaticFiles in the order dnf5-automatic reads them, later keys
// winning (5.2.10+; /etc/dnf/automatic.conf since 5.2.7, the .conf.d
// directories after the file they extend since 5.4). A name ending in "/"
// is a directory of *.conf. dnf4 reads /etc/dnf/automatic.conf alone.
var dnf5AutomaticFiles = []string{
	pathDNF5AutomaticUsr, pathDNF5AutomaticUsr + ".d/",
	pathDNF5AutomaticEtc, // deprecated
	pathDNFAutomatic, pathDNFAutomatic + ".d/",
}

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
	// OSTreeBooted: an image-based host (CoreOS, Silverblue, bootc). The
	// dnf-automatic timers do not run there (ConditionPathExists=
	// !/run/ostree-booted); rpm-ostreed or bootc update the image.
	OSTreeBooted bool `json:"ostreeBooted,omitempty"`
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
		"dnf-automatic-notifyonly.timer", "dnf5-automatic.timer",
		"rpm-ostreed-automatic.timer", "bootc-fetch-apply-updates.timer"},
}

func collectUpdates(ctx context.Context, sc *scanCtx) Section {
	var gaps gapList
	manager, db := inventory.PrimaryDB(sc.root)
	if manager == "" {
		return Section{Status: StatusNA}
	}
	d := updatesData{Manager: manager, Timers: []timerState{}}
	switch manager {
	case inventory.ManagerDpkg:
		d.APT = collectAPT(ctx, sc, &gaps)
	case inventory.ManagerRpm:
		d.DNFAutomatic = collectDNFAutomatic(sc, &gaps)
		d.OSTreeBooted = sc.exists(pathOSTreeBooted)
	case inventory.ManagerApk:
		d.APK = collectAPK(sc, &gaps)
	}
	if sc.exists("/run/systemd/system") {
		d.Timers = collectTimers(sc, updateTimers[manager], &gaps)
	}
	d.LastPkgDBChangeAt = mtimeOf(sc, db, &gaps)
	return collected(gaps, d)
}

func collectAPT(ctx context.Context, sc *scanCtx, gaps *gapList) *aptUpdates {
	cfg := readAPTConfig(ctx, aptFiles{
		readFile: func(p string) ([]byte, error) { return sc.read(p, updatesFileLimit) },
		readDir:  func(dir string) ([]string, error) { return infoNames(sc.readDirFiles(dir)) },
	})
	*gaps = append(*gaps, cfg.gaps...)
	a := &aptUpdates{ConfigValid: cfg.valid(), Files: filesMeta(sc, cfg.files), ParseErrors: append([]lineRef{}, cfg.errs...)}
	isInterval := aptIntervalRe.MatchString
	a.Periodic = aptPeriodic{
		Enable:                      checked(cfg.value("APT::Periodic::Enable"), isInterval),
		UpdatePackageLists:          checked(cfg.value("APT::Periodic::Update-Package-Lists"), isInterval),
		DownloadUpgradeablePackages: checked(cfg.value("APT::Periodic::Download-Upgradeable-Packages"), isInterval),
		UnattendedUpgrade:           checked(cfg.value("APT::Periodic::Unattended-Upgrade"), isInterval),
	}
	u := &a.Unattended
	u.Installed = sc.exists(pathUnattendedUpgrade)
	u.OriginsPatterns = u.capped(cfg.list("Unattended-Upgrade::Origins-Pattern"))
	u.AllowedOrigins = u.capped(cfg.list("Unattended-Upgrade::Allowed-Origins"))
	u.AutoReboot = checked(cfg.value("Unattended-Upgrade::Automatic-Reboot"), isAPTBool)
	a.Stamps = aptStamps{
		Update:              mtimeOf(sc, pathAPTPeriodic+"/update-stamp", gaps),
		UpdateSuccess:       mtimeOf(sc, pathAPTPeriodic+"/update-success-stamp", gaps),
		DownloadUpgradeable: mtimeOf(sc, pathAPTPeriodic+"/download-upgradeable-stamp", gaps),
		Upgrade:             mtimeOf(sc, pathAPTPeriodic+"/upgrade-stamp", gaps),
	}
	return a
}

// capped keeps at most maxOrigins patterns of maxOriginLen bytes, and
// marks the cut.
func (u *aptUnattended) capped(list []string) []string {
	if len(list) > maxOrigins {
		list, u.Truncated = list[:maxOrigins], true
	}
	for i, o := range list {
		if len(o) > maxOriginLen {
			list[i], u.Truncated = strings.ToValidUTF8(o[:maxOriginLen], ""), true // not a rune cut in half
		}
	}
	return list
}

// aptIntervalRe is what apt.systemd.daily takes as an interval.
var aptIntervalRe = regexp.MustCompile(`^(always|[0-9]{1,9}[smhd]?)$`)

// boolWords are the booleans libdnf takes; apt takes these and more.
var (
	boolWords    = []string{"0", "1", "no", "yes", "false", "true", "off", "on"}
	aptBoolWords = slices.Concat(boolWords, []string{"without", "with", "disable", "enable"})
)

// isAPTBool is StringToBool of strutl.cc, isDNFBool a boolean of the dnf
// configuration.
var (
	isAPTBool = oneOfFold(aptBoolWords...)
	isDNFBool = oneOfFold(boolWords...)
)

func collectDNFAutomatic(sc *scanCtx, gaps *gapList) *dnfAutomatic {
	d := &dnfAutomatic{}
	paths := []string{pathDNFAutomatic}
	if sc.exists(pathDNF5AutomaticUsr) || sc.exists(pathDNF5AutomaticEtc) {
		d.DNF5, paths = true, dnfConfFiles(sc, dnf5AutomaticFiles, gaps)
	}
	commands := map[string]string{}
	var read []string
	for _, p := range paths {
		b, err := sc.read(p, updatesFileLimit)
		if err != nil {
			gaps.optional(p, err)
			continue
		}
		read = append(read, p)
		maps.Copy(commands, iniSection(string(b), "commands"))
	}
	d.Installed, d.Files = len(read) > 0, filesMeta(sc, read)
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

// dnfConfFiles expands the directories of paths (a name ending in "/") into
// their *.conf files, by name.
func dnfConfFiles(sc *scanCtx, paths []string, gaps *gapList) []string {
	var out []string
	for _, p := range paths {
		dir, isDir := strings.CutSuffix(p, "/")
		if !isDir {
			out = append(out, p)
			continue
		}
		files, err := sc.readDirFiles(dir)
		gaps.optional(dir, err)
		for _, fi := range files {
			if strings.HasSuffix(fi.Name(), ".conf") {
				out = append(out, dir+"/"+fi.Name())
			}
		}
	}
	return out
}

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

// runPartsNameRe is a name busybox run-parts runs (1.36+): letters, digits,
// "_", "-" and ".", no leading dot.
var runPartsNameRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]*$`)

func collectAPK(sc *scanCtx, gaps *gapList) *apkUpdates {
	a := &apkUpdates{UpgradeJobs: []string{}}
	files := []string{pathAlpineCrontab}
	dirs, err := sc.readDir(pathAlpinePeriodic)
	gaps.optional(pathAlpinePeriodic, err)
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		sub := pathAlpinePeriodic + "/" + dir.Name()
		jobs, err := sc.readDirFiles(sub)
		gaps.optional(sub, err)
		for _, fi := range jobs {
			if runPartsNameRe.MatchString(fi.Name()) && fi.Mode()&0o111 != 0 { // what run-parts executes
				files = append(files, sub+"/"+fi.Name())
			}
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
			if sc.exists(dir + "/" + name) {
				installed, alias = true, unitAlias(sc, dir+"/"+name)
				break
			}
		}
		if alias {
			continue // its target is in the list itself (dnf-automatic → dnf5-automatic on Fedora)
		}
		t.Masked = slices.ContainsFunc(maskDirs, func(dir string) bool { return unitMasked(sc, dir+"/"+name) })
		if !installed && !t.Masked {
			continue
		}
		t.Enabled = slices.ContainsFunc(unitDirs, func(dir string) bool { return sc.exists(dir + "/timers.target.wants/" + name) })
		t.LastTriggerAt = mtimeOf(sc, pathTimerStamps+"/stamp-"+name, gaps)
		out = append(out, t)
	}
	return out
}

// mtimeOf is the mtime of path; nil when it does not exist, a gap when it
// cannot be read.
func mtimeOf(sc *scanCtx, path string, gaps *gapList) *time.Time {
	fi, err := sc.stat(path)
	if err != nil {
		gaps.optional(path, err)
		return nil
	}
	t := fi.ModTime().UTC()
	return &t
}
