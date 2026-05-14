//go:build linux

package packages

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
	"github.com/vmkteam/embedlog"
	// modernc.org/sqlite registers driver "sqlite" — required by anchore/go-rpmdb's
	// sqlite3 backend which calls sql.Open("sqlite", "file:...?mode=ro&immutable=1")
	// without registering one itself. Same pattern Trivy and Syft use. Phase 5
	// will gate this import behind a build tag for slim builds.
	_ "modernc.org/sqlite"
)

// rpmDBCandidates lists every supported rpm database path in priority order.
// First-match wins. SQLite (RHEL 9+, Fedora 32+) is tried first, then NDB
// (SUSE), then BDB (RHEL 7-8). Each variant has a sysimage equivalent for
// CoreOS / OSTree layouts.
var rpmDBCandidates = []string{
	"/var/lib/rpm/rpmdb.sqlite",          // RHEL 9+, Fedora 32+
	"/var/lib/rpm/Packages.db",           // SUSE / openSUSE NDB
	"/var/lib/rpm/Packages",              // RHEL 7-8 BDB
	"/usr/lib/sysimage/rpm/rpmdb.sqlite", // CoreOS / OSTree
	"/usr/lib/sysimage/rpm/Packages.db",
	"/usr/lib/sysimage/rpm/Packages",
}

// keyIDRe extracts the short key id from rpm's PGP/RSAHeader fields. rpm prints
// signatures as "RSA/SHA256, Mon Nov 20 ..., Key ID 199e2f91fd431d51".
var keyIDRe = regexp.MustCompile(`(?i)Key ID ([0-9a-f]{8,40})`)

// Rpm is the rpm manager (RHEL/Fedora/Rocky/Alma/CentOS/SUSE).
type Rpm struct {
	embedlog.Logger
	root string
}

func NewRpm(logger embedlog.Logger, root string) *Rpm {
	return &Rpm{Logger: logger, root: root}
}

func (m *Rpm) Name() string { return ManagerRpm }

// Scan parses the rpm database. BDB (`Packages`) is copy-then-parsed
// (Syft/Trivy pattern) to avoid mid-write inconsistency during `rpm -i` —
// BDB writes pages in-place. SQLite is opened read-only with `immutable=1`
// inside anchore/go-rpmdb. NDB is append-only and safe.
func (m *Rpm) Scan(_ context.Context) (Snapshot, error) {
	openPath, cleanup, err := m.openDB()
	if err != nil {
		return Snapshot{}, err
	}
	defer cleanup()

	db, err := rpmdb.Open(openPath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("rpmdb open %s: %w", openPath, err)
	}
	defer db.Close()

	infos, err := db.ListPackages()
	if err != nil {
		return Snapshot{}, fmt.Errorf("rpmdb list: %w", err)
	}

	pkgs := make([]Package, 0, len(infos))
	for _, p := range infos {
		pkgs = append(pkgs, m.toPackage(p))
	}

	m.enrichFromDnfHistory(pkgs)

	return Snapshot{Manager: ManagerRpm, Packages: pkgs}, nil
}

// findDB returns the first existing rpm database path under m.root, or "" if
// none found. Used by both Scan() (via openDB) and detectManagers().
func (m *Rpm) findDB() string {
	for _, p := range rpmDBCandidates {
		if fileExists(m.root + p) {
			return m.root + p
		}
	}
	return ""
}

// openDB locates the rpm database and, for BDB only, copies it to a tempfile
// to escape mid-write inconsistency. Returns the path to read and a cleanup
// function. Callers always defer cleanup().
func (m *Rpm) openDB() (string, func(), error) {
	dbPath := m.findDB()
	if dbPath == "" {
		return "", func() {}, fmt.Errorf("no rpm database found under %q", m.root)
	}
	if filepath.Base(dbPath) != "Packages" {
		return dbPath, func() {}, nil // sqlite/ndb — opened directly
	}
	tmp, err := m.copyToTemp(dbPath)
	if err != nil {
		return "", func() {}, fmt.Errorf("snapshot rpm BDB: %w", err)
	}
	return tmp, func() { os.Remove(tmp) }, nil
}

func (m *Rpm) toPackage(p *rpmdb.PackageInfo) Package {
	srcName, srcVer := m.parseSrcRpm(p.SourceRpm)
	pkg := Package{
		Name:            p.Name,
		Version:         p.Version,
		Release:         p.Release,
		Epoch:           p.Epoch,
		Arch:            p.Arch,
		Status:          StatusGeneric,
		SourceName:      srcName,
		SourceVersion:   srcVer,
		ModularityLabel: p.Modularitylabel,
		Vendor:          p.Vendor,
		GpgKeyID:        m.extractKeyID(p.PGP, p.RSAHeader),
		InstallTime:     int64(p.InstallTime),
		InstalledSize:   int64(p.Size),
	}
	if p.SigMD5 != "" {
		pkg.SigDigest = p.SigMD5
		pkg.SigAlgorithm = "md5"
	}
	if p.License != "" {
		pkg.Licenses = []string{p.License}
	}
	return pkg
}

// parseSrcRpm splits "name-VERSION-RELEASE.src.rpm" into name and VERSION-RELEASE.
// rpm guarantees this shape — RELEASE is anything after the last hyphen,
// VERSION is everything between the first and last hyphen. NEVRA without epoch.
func (m *Rpm) parseSrcRpm(s string) (name, version string) {
	if s == "" {
		return "", ""
	}
	s = strings.TrimSuffix(s, ".rpm")
	s = strings.TrimSuffix(s, ".src")
	relIdx := strings.LastIndexByte(s, '-')
	if relIdx <= 0 {
		return s, ""
	}
	verIdx := strings.LastIndexByte(s[:relIdx], '-')
	if verIdx <= 0 {
		return s, s[relIdx+1:]
	}
	return s[:verIdx], s[verIdx+1:]
}

// extractKeyID grabs the GPG short key id from rpm's PGP/RSAHeader strings.
// Returns the first match (PGP first, RSAHeader fallback). Both fields may be
// empty for unsigned/locally-built packages — that absence is meaningful.
func (m *Rpm) extractKeyID(fields ...string) string {
	for _, f := range fields {
		if match := keyIDRe.FindStringSubmatch(f); len(match) == 2 {
			return strings.ToLower(match[1])
		}
	}
	return ""
}

func (m *Rpm) copyToTemp(src string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.CreateTemp("", "rpmdb-topsrv-*")
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		os.Remove(out.Name())
		return "", err
	}
	return out.Name(), nil
}
