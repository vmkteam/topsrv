package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/inventory"
)

// scanCtx is what a section gets: the root to read from ("" in production,
// a fixture directory in tests) and what earlier sections found.
type scanCtx struct {
	root string
	env  envData

	// timeSync reads the kernel clock state; nil where it cannot be read.
	timeSync func() (*timeSync, error)
}

// The accessors below are the only way sections touch the filesystem: each
// takes a path as the host sees it and prefixes the scan root. Files go
// through safefile.

func (sc *scanCtx) read(path string, limit int64) ([]byte, error) {
	return readFile(sc.root+path, limit)
}

// readHead reads up to n bytes from the start of a file.
func (sc *scanCtx) readHead(path string, n int64) ([]byte, error) {
	return readHead(sc.root+path, n)
}

func (sc *scanCtx) readDir(path string) ([]os.DirEntry, error) { return os.ReadDir(sc.root + path) }

func (sc *scanCtx) readlink(path string) (string, error) { return os.Readlink(sc.root + path) }

func (sc *scanCtx) stat(path string) (os.FileInfo, error) { return os.Stat(sc.root + path) }

// exists is a presence probe; any error, permission included, means absent.
func (sc *scanCtx) exists(path string) bool {
	_, err := os.Lstat(sc.root + path)
	return err == nil
}

// glob reports whether the pattern matches anything.
func (sc *scanCtx) glob(pattern string) bool {
	m, _ := filepath.Glob(sc.root + pattern)
	return len(m) > 0
}

// sameFile reports whether two paths, symlinks followed, are the same inode.
func (sc *scanCtx) sameFile(a, b string) (bool, error) {
	sa, err := sc.stat(a)
	if err != nil {
		return false, err
	}
	sb, err := sc.stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(sa, sb), nil
}

// sectionDef is one section of the snapshot.
type sectionDef struct {
	name   string
	budget time.Duration
	// host: reads state an app container does not share with the host
	// (its own /etc, pid and net namespaces).
	host bool
	run  func(context.Context, *scanCtx) Section
}

// allSections of this release, in pass order. Kernel facts are global, so
// the kernel section is collected in a container too.
var allSections = []sectionDef{
	{name: SectionKernel, budget: 2 * time.Second, run: collectKernel},
	{name: SectionSysctl, budget: 2 * time.Second, host: true, run: collectSysctl},
	{name: SectionRoleSignals, budget: 5 * time.Second, host: true, run: collectRoleSignals},
}

type cachedSection struct {
	sec Section
	at  time.Time
}

// pass runs the sections of t — every enabled one when t lists none — and
// builds a full snapshot from the section cache: an unscheduled pass
// rebuilds only its sections.
func (c *Collector) pass(ctx context.Context, t Trigger) inventory.Payload {
	start := c.now()
	sc := &scanCtx{root: c.root, timeSync: c.timeSync}
	var envSec Section
	envSec, sc.env = c.environment(sc)
	for _, def := range c.sections {
		if len(t.Sections) > 0 && !slices.Contains(t.Sections, def.name) {
			continue
		}
		c.store(def.name, c.runSection(ctx, def, sc), start)
	}

	host := inventory.DetectHost(c.root)
	host.PackageManager = inventory.PrimaryManager(c.root)
	return inventory.Payload{
		Kind:      Kind,
		ScannedAt: start.UTC(),
		Host:      host,
		Data: Data{
			SchemaVersion: SchemaVersion,
			Trigger:       t.Cause,
			Agent:         c.agent(sc),
			Environment:   envSec,
			Sections:      c.cachedSections(start),
		},
	}
}

func (c *Collector) environment(sc *scanCtx) (Section, envData) {
	if !c.supported {
		return unknown(ReasonUnsupportedPlatform), envData{ContainerKind: containerUnknown}
	}
	start := time.Now()
	sec, env := collectEnvironment(sc)
	sec.DurationMs = time.Since(start).Milliseconds()
	c.recordMetrics("environment", sec)
	return sec, env
}

func (c *Collector) agent(sc *scanCtx) Agent {
	a, err := readAgent(sc)
	if err != nil {
		a = Agent{UID: os.Geteuid()} // CapEff stays null: unknown
	}
	a.KeyID = c.key.id
	return a
}

// runSection runs one section under its budget. A blocking syscall cannot
// be cancelled in Go (a read on a hung NFS mount), so the section runs in its
// own goroutine: on timeout the pass moves on, and the section is not
// started again until that goroutine returns — at most one stuck thread per
// section.
func (c *Collector) runSection(ctx context.Context, def sectionDef, sc *scanCtx) Section {
	switch {
	case !c.supported:
		return unknown(ReasonUnsupportedPlatform)
	case def.host && sc.env.appContainer():
		return unknown(ReasonContainerEnv)
	case !c.startInflight(def.name):
		return unknown(ReasonTimeout) // still stuck since an earlier pass
	}

	sctx, cancel := context.WithTimeout(ctx, def.budget)
	defer cancel()
	start := time.Now()
	done := make(chan Section, 1)
	go func() {
		var sec Section
		defer func() {
			// Parsers read untrusted files: a bug there must not take the
			// agent down. Only the panic type and site are logged — its value
			// may quote the input.
			if r := recover(); r != nil {
				c.Error(ctx, "security: section panicked", "section", def.name,
					"error", fmt.Sprintf("panic %T at %s", r, panicSite()))
				sec = unknown(ReasonParseError)
			}
			c.endInflight(def.name)
			done <- sec
		}()
		sec = def.run(sctx, sc)
	}()

	var sec Section
	select {
	case sec = <-done:
	case <-sctx.Done():
		select {
		case sec = <-done: // returned right at the deadline
		default:
			sec = unknown(ReasonTimeout)
		}
	}
	sec.DurationMs = time.Since(start).Milliseconds()
	return sec
}

func (c *Collector) startInflight(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight[name] {
		return false
	}
	c.inflight[name] = true
	return true
}

func (c *Collector) endInflight(name string) {
	c.mu.Lock()
	c.inflight[name] = false
	c.mu.Unlock()
}

func (c *Collector) store(name string, sec Section, at time.Time) {
	c.recordMetrics(name, sec)
	c.mu.Lock()
	c.cache[name] = cachedSection{sec: sec, at: at}
	c.mu.Unlock()
}

// cachedSections returns every enabled section from the cache. A section not
// rebuilt for two intervals is reported as timed out rather than stale.
func (c *Collector) cachedSections(now time.Time) map[string]Section {
	maxAge := 2 * c.cfg.ParsedInterval()
	out := make(map[string]Section, len(c.sections))
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, def := range c.sections {
		cs, ok := c.cache[def.name]
		if !ok || now.Sub(cs.at) > maxAge {
			out[def.name] = unknown(ReasonTimeout)
			c.errCounts[[2]string{def.name, string(ReasonTimeout)}]++
			continue
		}
		out[def.name] = cs.sec
	}
	return out
}

// panicSite returns file:line of the code that panicked, for the log.
func panicSite() string {
	pcs := make([]uintptr, 32)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	afterPanic := false
	for {
		f, more := frames.Next()
		switch {
		case f.Function == "runtime.gopanic":
			afterPanic = true
		case afterPanic && !strings.HasPrefix(f.Function, "runtime."):
			return filepath.Base(f.File) + ":" + strconv.Itoa(f.Line)
		}
		if !more {
			return "unknown"
		}
	}
}
