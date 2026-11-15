package inventory

import "os"

// Package database paths. A manager is present on the host when its database
// exists; the packages collector reads the same files.
const (
	DpkgStatusPath   = "/var/lib/dpkg/status"
	ApkInstalledPath = "/lib/apk/db/installed"
)

// rpmDBPaths lists every supported rpm database path in priority order.
// First match wins. SQLite (RHEL 9+, Fedora 32+) is tried first, then NDB
// (SUSE), then BDB (RHEL 7-8). Each variant has a sysimage equivalent for
// CoreOS / OSTree layouts.
var rpmDBPaths = []string{
	"/var/lib/rpm/rpmdb.sqlite",          // RHEL 9+, Fedora 32+
	"/var/lib/rpm/Packages.db",           // SUSE / openSUSE NDB
	"/var/lib/rpm/Packages",              // RHEL 7-8 BDB
	"/usr/lib/sysimage/rpm/rpmdb.sqlite", // CoreOS / OSTree
	"/usr/lib/sysimage/rpm/Packages.db",
	"/usr/lib/sysimage/rpm/Packages",
}

// RpmDB returns root + the first existing rpm database path, or "" if none.
func RpmDB(root string) string {
	if p := rpmDB(root); p != "" {
		return root + p
	}
	return ""
}

// rpmDB returns the first existing rpm database path as the host sees it.
func rpmDB(root string) string {
	for _, p := range rpmDBPaths {
		if fileExists(root + p) {
			return p
		}
	}
	return ""
}

// Managers returns every package manager whose database exists under root,
// in order dpkg → rpm → apk. Hosts with mixed origin (containers) yield
// several entries.
func Managers(root string) []string {
	var out []string
	if fileExists(root + DpkgStatusPath) {
		out = append(out, ManagerDpkg)
	}
	if RpmDB(root) != "" {
		out = append(out, ManagerRpm)
	}
	if fileExists(root + ApkInstalledPath) {
		out = append(out, ManagerApk)
	}
	return out
}

// PrimaryManager returns the first of Managers(root), or "" when the host has
// no known package database. Snapshots not tied to one manager use it for
// HostMeta.PackageManager.
func PrimaryManager(root string) string {
	m, _ := PrimaryDB(root)
	return m
}

// PrimaryDB returns PrimaryManager and the path of its database as the host
// sees it, without root; both "" without a known package database.
func PrimaryDB(root string) (manager, path string) {
	if fileExists(root + DpkgStatusPath) {
		return ManagerDpkg, DpkgStatusPath
	}
	if p := rpmDB(root); p != "" {
		return ManagerRpm, p
	}
	if fileExists(root + ApkInstalledPath) {
		return ManagerApk, ApkInstalledPath
	}
	return "", ""
}

// fileExists hides the err-ignoring intent of Stat. Marker-file probes
// don't distinguish "missing" from "no permission" — both mean "skip".
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
