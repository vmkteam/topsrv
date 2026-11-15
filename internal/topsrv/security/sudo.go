package security

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/vmkteam/topsrv/internal/topsrv/security/sudoers"
)

// Sources of the sudoers section.
const (
	pathSudoers    = "/etc/sudoers"
	pathDoasConf   = "/etc/doas.conf"
	pathDoasDir    = "/etc/doas.d"
	sudoFileLimit  = 1 << 20
	sudoHostnameAt = "/proc/sys/kernel/hostname"
)

// sudoData is the sudoers section: sudo, and doas on Alpine.
type sudoData struct {
	SudoPresent bool `json:"sudoPresent"`
	// Rules in file order: sudo applies the last match.
	Rules []sudoRule `json:"rules"`
	// Truncated: more rules than listed (500).
	Truncated      bool         `json:"truncated,omitempty"`
	Defaults       sudoDefaults `json:"defaults"`
	ScopedDefaults []sudoScoped `json:"scopedDefaults"`
	Files          []fileMeta   `json:"files"`
	IgnoredFiles   []string     `json:"ignoredFiles"`
	// ExternalSources: nsswitch.conf takes sudo rules from sss or ldap too;
	// those are not here.
	ExternalSources []string   `json:"externalSources"`
	ParseErrors     []lineRef  `json:"parseErrors"`
	DoasRules       []doasRule `json:"doasRules"` // null without doas.conf
}

type sudoRule struct {
	Order       int        `json:"order"`
	Source      string     `json:"source"`
	Principals  []string   `json:"principals"`
	HostsAll    bool       `json:"hostsAll"`
	Runas       *sudoRunas `json:"runas"` // null: runas_default, root
	CommandsAll bool       `json:"commandsAll"`
	NopasswdAll bool       `json:"nopasswdAll"`
	NopasswdAny bool       `json:"nopasswdAny"`
	Setenv      bool       `json:"setenv"`
}

type sudoRunas struct {
	Users       []string `json:"users"`
	Groups      []string `json:"groups"`
	HasNegation bool     `json:"hasNegation"`
}

type sudoDefaults struct {
	Authenticate *bool `json:"authenticate"`
	RootPW       *bool `json:"rootpw"`
	UsePTY       *bool `json:"usePty"`
	EnvKeepLD    bool  `json:"envKeepLD"`
}

type sudoScoped struct {
	Source         string   `json:"source"`
	Binding        string   `json:"binding"`
	List           []string `json:"list"`
	NoAuthenticate bool     `json:"noAuthenticate,omitempty"`
	RootPW         bool     `json:"rootpw,omitempty"`
	EnvKeepLD      bool     `json:"envKeepLD,omitempty"`
}

type doasRule struct {
	Source    string `json:"source"`
	Permit    bool   `json:"permit"`
	Principal string `json:"principal"`
	Nopass    bool   `json:"nopass"`
	Persist   bool   `json:"persist"`
	Keepenv   bool   `json:"keepenv"`
	AsRoot    bool   `json:"asRoot"`
	Cmd       bool   `json:"cmd"`
}

func collectSudoers(_ context.Context, sc *scanCtx) Section {
	var gaps gapList
	files := sudoers.Files{
		ReadFile: func(p string) ([]byte, error) { return sc.read(p, sudoFileLimit) },
		ReadDir:  func(dir string) ([]string, error) { return fileNames(sc.readDir(dir)) }, // sudo skips subdirectories
	}
	pol := sudoers.Parse(pathSudoers, shortHostname(sc), files)
	d := sudoData{SudoPresent: true}
	for _, re := range pol.ReadErrors {
		switch {
		case re.Path != pathSudoers:
			gaps.add(re.Path, re.Err)
		case errors.Is(re.Err, fs.ErrNotExist):
			d.SudoPresent = false
		default:
			return unknown(reasonOf(re.Err)) // 0440 root: without root nothing is known
		}
	}
	doas, doasFiles, doasErrs := readDoas(sc, &gaps)
	if !d.SudoPresent && doas == nil {
		return absent(gaps) // doas.conf unreadable is not "no doas"
	}
	d.Rules, d.Truncated = sudoRules(pol.Rules), pol.Truncated
	d.Defaults = sudoDefaults(pol.Defaults)
	d.ScopedDefaults = sudoScopedOf(pol.Scoped)
	d.IgnoredFiles = append([]string{}, pol.Ignored...)
	d.ExternalSources = sudoExternalSources(sc)
	d.ParseErrors = append(sudoRefs(pol.Errors), doasErrs...)
	d.DoasRules = doas
	d.Files = []fileMeta{}
	for _, p := range slices.Concat(pol.Files, doasFiles) {
		if m, err := statFile(sc, p); err == nil {
			d.Files = append(d.Files, m)
		}
	}
	return collected(gaps, d)
}

// readDoas reads doas.conf and doas.d/*.conf; nil rules without doas.conf.
func readDoas(sc *scanCtx, gaps *gapList) (rules []doasRule, files []string, errs []lineRef) {
	paths := []string{pathDoasConf}
	entries, err := sc.readDir(pathDoasDir)
	gaps.optional(pathDoasDir, err)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".conf") {
			paths = append(paths, pathDoasDir+"/"+e.Name())
		}
	}
	for _, p := range paths {
		b, err := sc.read(p, sudoFileLimit)
		if err != nil {
			gaps.optional(p, err)
			continue
		}
		if rules == nil {
			rules = []doasRule{}
		}
		files = append(files, p)
		parsed, refs := sudoers.ParseDoas(p, b)
		for _, r := range parsed {
			rules = append(rules, doasRule(r))
		}
		errs = append(errs, sudoRefs(refs)...)
	}
	return rules, files, errs
}

// fileNames lists the entries of a directory that are not directories.
func fileNames(entries []os.DirEntry, err error) ([]string, error) {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, err
}

// shortHostname is the host name up to the first dot, for %h in include
// paths.
func shortHostname(sc *scanCtx) string {
	b, _ := sc.read(sudoHostnameAt, smallFileLimit)
	name, _, _ := strings.Cut(strings.TrimSpace(string(b)), ".")
	return name
}

// sudoExternalSources are the sudoers sources of nsswitch.conf other than
// files.
func sudoExternalSources(sc *scanCtx) []string {
	out := []string{}
	b, err := sc.read(pathNSSwitch, smallFileLimit)
	if err != nil {
		return out
	}
	for _, src := range parseNSSwitch(b).Sudoers {
		if src != "files" {
			out = append(out, src)
		}
	}
	return out
}

func sudoRules(rules []sudoers.Rule) []sudoRule {
	out := make([]sudoRule, 0, len(rules))
	for i, r := range rules {
		sr := sudoRule{Order: i + 1, Source: r.Source, Principals: r.Principals, HostsAll: r.HostsAll,
			CommandsAll: r.CommandsAll, NopasswdAll: r.NopasswdAll, NopasswdAny: r.NopasswdAny, Setenv: r.Setenv}
		sr.Runas = (*sudoRunas)(r.Runas)
		out = append(out, sr)
	}
	return out
}

func sudoScopedOf(scoped []sudoers.ScopedDefault) []sudoScoped {
	out := make([]sudoScoped, 0, len(scoped))
	for _, s := range scoped {
		out = append(out, sudoScoped(s))
	}
	return out
}

func sudoRefs(refs []sudoers.Ref) []lineRef {
	out := make([]lineRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, lineRef(r))
	}
	return out
}
