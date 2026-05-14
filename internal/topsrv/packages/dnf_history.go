//go:build linux

package packages

import (
	"database/sql"
	"fmt"
	"os"
)

const dnfHistoryPath = "/var/lib/dnf/history.sqlite"

// libdnf TransactionItemReason codes (stable since 2020). Map 1:1 to what
// `dnf history info` reports under "Reason".
const (
	dnfReasonNone           = 0
	dnfReasonDependency     = 1
	dnfReasonUser           = 2
	dnfReasonClean          = 3
	dnfReasonWeakDependency = 4
	dnfReasonGroup          = 5
	dnfReasonExternalUser   = 6
)

// libdnf TransactionItemAction. We only care about state-changing actions.
const (
	dnfActionInstall   = 1
	dnfActionDowngrade = 2
	dnfActionUpgrade   = 6
	dnfActionReinstall = 9
)

const dnfStateDone = 1

// enrichFromDnfHistory merges repoOrigin + autoInstalled by walking
// /var/lib/dnf/history.sqlite (libdnf schema). For each (name, arch) we keep:
//   - reason from the *initial* INSTALL (libdnf zeroes reason on UPGRADE rows,
//     so taking the latest would lose user/dep classification)
//   - repo from the *latest* state-changing action (later upgrades may pull
//     from a different repo than the initial install)
//
// Opened read-only with immutable=1 — lock-safe vs concurrent `dnf install`.
// Absence of history.sqlite is normal on rpm-only systems — silently skip.
func (m *Rpm) enrichFromDnfHistory(pkgs []Package) {
	dbPath := m.root + dnfHistoryPath
	if _, err := os.Stat(dbPath); err != nil {
		return
	}

	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&immutable=1", dbPath))
	if err != nil {
		return
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT
			r.name,
			r.arch,
			COALESCE(repo.repoid, ''),
			ti.reason,
			ti.action
		FROM trans_item ti
		JOIN rpm r ON r.item_id = ti.item_id
		LEFT JOIN repo ON repo.id = ti.repo_id
		WHERE ti.state = ?
		  AND ti.action IN (?, ?, ?, ?)
		ORDER BY ti.id ASC
	`, dnfStateDone, dnfActionInstall, dnfActionDowngrade, dnfActionUpgrade, dnfActionReinstall)
	if err != nil {
		return // schema may differ in dnf5; silently skip
	}
	defer rows.Close()

	type entry struct {
		repo          string
		initialReason int
		hasInstall    bool
	}
	latest := make(map[string]entry, 256)

	for rows.Next() {
		var name, arch, repo string
		var reason, action int
		if err := rows.Scan(&name, &arch, &repo, &reason, &action); err != nil {
			continue
		}
		key := name + "/" + arch
		e := latest[key]
		if action == dnfActionInstall && !e.hasInstall {
			e.initialReason = reason
			e.hasInstall = true
		}
		if repo != "" {
			e.repo = repo // latest non-empty wins
		}
		latest[key] = e
	}

	for i := range pkgs {
		e, ok := latest[pkgs[i].Name+"/"+pkgs[i].Arch]
		if !ok {
			continue
		}
		// "@System" = repo unknown / installed before dnf history tracking.
		// Don't surface that as a meaningful repo origin.
		if e.repo != "" && e.repo != "@System" {
			pkgs[i].RepoOrigin = e.repo
		}
		if e.hasInstall && isAutoInstallReason(e.initialReason) {
			pkgs[i].AutoInstalled = true
		}
	}
}

func isAutoInstallReason(r int) bool {
	switch r {
	case dnfReasonDependency, dnfReasonWeakDependency, dnfReasonGroup:
		return true
	}
	return false
}
