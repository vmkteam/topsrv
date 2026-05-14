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
	dpkgStatusPath   = "/var/lib/dpkg/status"
	aptExtStatesPath = "/var/lib/apt/extended_states"
)

// Dpkg is the dpkg/apt manager. Owns parsing of /var/lib/dpkg/status,
// /var/lib/apt/extended_states (autoInstalled enrichment), and the shared
// RFC822 paragraph format used by both files.
type Dpkg struct {
	embedlog.Logger
	root string
}

func NewDpkg(logger embedlog.Logger, root string) *Dpkg {
	return &Dpkg{Logger: logger, root: root}
}

func (m *Dpkg) Name() string { return ManagerDpkg }

// Scan reads /var/lib/dpkg/status, filters to installed/held packages, and
// merges apt's auto-installed classification. dpkg's `Version` field
// already embeds epoch as a prefix ("1:6.7p1-5+deb8u2") — exactly what
// Vulners expects on the wire.
func (m *Dpkg) Scan(_ context.Context) (Snapshot, error) {
	f, err := os.Open(m.root + dpkgStatusPath)
	if err != nil {
		return Snapshot{}, fmt.Errorf("open dpkg status: %w", err)
	}
	defer f.Close()

	records, err := m.parseRFC822(f)
	if err != nil {
		return Snapshot{}, fmt.Errorf("parse dpkg status: %w", err)
	}

	pkgs := make([]Package, 0, len(records))
	for _, r := range records {
		status := r["Status"]
		if status != StatusInstalled && status != StatusHoldInstalled {
			continue
		}
		name := r["Package"]
		srcName, srcVersion := m.parseSource(r["Source"], name)

		size, _ := strconv.ParseInt(r["Installed-Size"], 10, 64)
		size *= 1024 // dpkg reports KiB

		pkgs = append(pkgs, Package{
			Name:          name,
			Version:       r["Version"], // already includes epoch prefix when present
			Arch:          r["Architecture"],
			Status:        status,
			SourceName:    srcName,
			SourceVersion: srcVersion,
			Vendor:        r["Maintainer"], // dpkg has no Vendor; Maintainer fills the supply-chain slot
			InstalledSize: size,
			Section:       r["Section"],
			Priority:      r["Priority"],
			Homepage:      r["Homepage"],
		})
	}

	m.enrichAutoInstalled(pkgs)

	return Snapshot{Manager: ManagerDpkg, Packages: pkgs}, nil
}

// parseSource splits dpkg's `Source:` field into name+version. Two valid forms:
//
//	Source: openssl                  → ("openssl", "")
//	Source: openssl (1.1.1-1ubuntu2) → ("openssl", "1.1.1-1ubuntu2")
//
// Empty Source is the common case (binary name == source name); per Debian
// convention we fall back to binaryName, otherwise CVE-mapping by source breaks.
func (m *Dpkg) parseSource(raw, binaryName string) (name, version string) {
	if raw == "" {
		return binaryName, ""
	}
	if i := strings.IndexByte(raw, '('); i > 0 {
		name = strings.TrimSpace(raw[:i])
		j := strings.IndexByte(raw[i+1:], ')')
		if j > 0 {
			version = strings.TrimSpace(raw[i+1 : i+1+j])
		}
		return name, version
	}
	return raw, ""
}

// enrichAutoInstalled merges apt's manually-installed vs auto-installed
// classification. apt records this in extended_states (also RFC822 paragraphs),
// separate from dpkg's status. Absence of the file is normal on systems
// that haven't run apt — silently skip.
func (m *Dpkg) enrichAutoInstalled(pkgs []Package) {
	f, err := os.Open(m.root + aptExtStatesPath)
	if err != nil {
		return
	}
	defer f.Close()

	records, err := m.parseRFC822(f)
	if err != nil {
		return
	}

	// key by "name/arch" — multiarch lets the same name coexist (libssl3:amd64 + libssl3:i386)
	auto := make(map[string]bool, len(records))
	for _, r := range records {
		if r["Auto-Installed"] != "1" {
			continue
		}
		auto[r["Package"]+"/"+r["Architecture"]] = true
	}

	for i := range pkgs {
		if auto[pkgs[i].Name+"/"+pkgs[i].Arch] {
			pkgs[i].AutoInstalled = true
		}
	}
}

// parseRFC822 parses a paragraph-per-record file. Records are blank-line
// separated. Continuation lines start with a space (or tab) and are joined to
// the previous field with "\n". Format used by dpkg status, apt
// extended_states, and apt history.log.
func (m *Dpkg) parseRFC822(r io.Reader) ([]map[string]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20) // 1 MiB lines (dpkg Description can be long)

	var records []map[string]string
	cur := map[string]string{}
	lastKey := ""

	flush := func() {
		if len(cur) > 0 {
			records = append(records, cur)
			cur = map[string]string{}
			lastKey = ""
		}
	}

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if lastKey != "" {
				cur[lastKey] += "\n" + strings.TrimSpace(line)
			}
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := line[:idx]
		val := strings.TrimSpace(line[idx+1:])
		cur[key] = val
		lastKey = key
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return records, nil
}
