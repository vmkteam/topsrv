//go:build linux

package packages

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/vmkteam/embedlog"
)

const (
	apkInstalledPath = "/lib/apk/db/installed"
	apkWorldPath     = "/etc/apk/world"
)

// Apk is the apk-tools (Alpine) manager.
type Apk struct {
	embedlog.Logger
	root string
}

func NewApk(logger embedlog.Logger, root string) *Apk {
	return &Apk{Logger: logger, root: root}
}

func (m *Apk) Name() string { return ManagerApk }

// Scan reads /lib/apk/db/installed. apk-tools encodes each package as a
// paragraph with single-letter keys (P=name, V=version, A=arch, I=installed
// size bytes, o=origin, m=maintainer, L=license, t=build time, c=git commit,
// C=checksum, U=URL, T=description). Records are blank-line separated, no
// continuation lines.
func (m *Apk) Scan(_ context.Context) (Snapshot, error) {
	f, err := os.Open(m.root + apkInstalledPath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open apk db: %w", err)
	}
	defer f.Close()

	records, err := m.parseDB(f)
	if err != nil {
		return Snapshot{}, fmt.Errorf("parse apk db: %w", err)
	}

	pkgs := make([]Package, 0, len(records))
	for _, r := range records {
		if r["P"] == "" {
			continue
		}
		size, _ := strconv.ParseInt(r["I"], 10, 64)
		installTime, _ := strconv.ParseInt(r["t"], 10, 64)
		pkg := Package{
			Name:          r["P"],
			Version:       r["V"],
			Arch:          r["A"],
			Status:        StatusGeneric,
			SourceName:    r["o"], // origin: apk's source-package equivalent
			Vendor:        r["m"], // maintainer; apk has no separate Vendor field
			InstallTime:   installTime,
			InstalledSize: size,
			Homepage:      r["U"],
			GitCommit:     r["c"],
		}
		if r["L"] != "" {
			pkg.Licenses = []string{r["L"]}
		}
		m.setChecksum(&pkg, r["C"])
		pkgs = append(pkgs, pkg)
	}

	m.enrichAutoInstalled(pkgs)

	return Snapshot{Manager: ManagerApk, Packages: pkgs}, nil
}

// setChecksum parses apk's "C:" field, which encodes a hash with an algorithm
// prefix: Q1 = SHA1, Q2 = SHA256. Strips the prefix for cleaner JSON and
// records the algorithm explicitly.
func (m *Apk) setChecksum(pkg *Package, c string) {
	switch {
	case c == "":
		return
	case strings.HasPrefix(c, "Q1"):
		pkg.SigDigest = c[2:]
		pkg.SigAlgorithm = "sha1"
	case strings.HasPrefix(c, "Q2"):
		pkg.SigDigest = c[2:]
		pkg.SigAlgorithm = "sha256"
	default:
		pkg.SigDigest = c
	}
}

// enrichAutoInstalled flags packages NOT listed in /etc/apk/world as
// auto-installed (i.e. pulled in as a dependency). apk doesn't record install
// reason per-package; `world` is the canonical list of manually-requested
// packages. Anything installed but not in world arrived as a dependency.
//
// apk has NO per-package repoOrigin: the `installed` DB doesn't store which
// repository each package came from. Reconstructing this would require
// scanning every APKINDEX.tar.gz in /var/cache/apk/, which is brittle and
// slow — skipped.
func (m *Apk) enrichAutoInstalled(pkgs []Package) {
	f, err := os.Open(m.root + apkWorldPath)
	if err != nil {
		return
	}
	defer f.Close()

	manual := make(map[string]bool, 64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// world entries may carry version constraints (e.g. "nginx>1.20" or
		// "package=1.2-r3") — strip them to leave just the name.
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		name := line
		for i, r := range name {
			if r == '<' || r == '>' || r == '=' || r == '~' {
				name = name[:i]
				break
			}
		}
		manual[strings.TrimSpace(name)] = true
	}

	for i := range pkgs {
		if !manual[pkgs[i].Name] {
			pkgs[i].AutoInstalled = true
		}
	}
}

func (m *Apk) parseDB(r io.Reader) ([]map[string]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)

	var records []map[string]string
	cur := map[string]string{}
	flush := func() {
		if len(cur) > 0 {
			records = append(records, cur)
			cur = map[string]string{}
		}
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		cur[line[:1]] = line[2:]
	}
	flush()
	return records, sc.Err()
}
