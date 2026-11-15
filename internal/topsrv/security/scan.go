package security

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/dockerapi"
	"github.com/vmkteam/topsrv/internal/topsrv/inventory"
)

// scanCtx is what a section gets: the root to read from ("" in production,
// a fixture directory in tests) and what earlier sections found. A section
// that ran past its budget may still hold it, so what is filled in lazily
// or by the pass is guarded.
type scanCtx struct {
	root string
	env  envData

	// timeSync reads the kernel clock state; nil where it cannot be read.
	timeSync func() (*timeSync, error)
	key      tokenKey  // for tokens of secrets, see hmac.go
	now      time.Time // start of the pass; zero in tests means the clock
	// trustedUID owns what only root may own (the sshd listener and its
	// binary): 0; a fixture sets the test user.
	trustedUID int64

	mountsOnce sync.Once
	mounts     mounts // remote and pseudo mounts only, see riskyOnly
	mountsErr  error

	procsOnce sync.Once
	procs     []process
	procsErr  error

	// deps returns what an earlier section gave; nil in tests that need none.
	deps func(section string) (depResult, bool)

	// dockerClient talks to the socket at a path; nil is dockerapi.New. A
	// test serves a socket at a short path: the fixture's would pass the
	// 104 bytes a socket address takes on macOS.
	dockerClient func(path string) *dockerapi.Client
}

// depResult is how a section came out and the typed result later sections
// build on (accounts → sshd → authorizedKeys): a dependent tells "absent"
// from "unknown" by the section, not by a missing result.
type depResult struct {
	sec Section
	res any
}

// The accessors below are the only way sections touch the filesystem: each
// takes a path as the host sees it and prefixes the scan root. Files go
// through safefile. A path on a network or automount filesystem is refused
// before any syscall: touching it may hang or mount it.

func (sc *scanCtx) read(path string, limit int64) ([]byte, error) {
	if err := sc.local(path); err != nil {
		return nil, err
	}
	return readFile(sc.root+path, limit)
}

// readHead reads up to n bytes from the start of a file.
func (sc *scanCtx) readHead(path string, n int64) ([]byte, error) {
	if err := sc.local(path); err != nil {
		return nil, err
	}
	return readHead(sc.root+path, n)
}

func (sc *scanCtx) readDir(path string) ([]os.DirEntry, error) {
	if err := sc.local(path); err != nil {
		return nil, err
	}
	return readDir(sc.root + path)
}

func (sc *scanCtx) readlink(path string) (string, error) {
	if err := sc.local(path); err != nil {
		return "", err
	}
	return os.Readlink(sc.root + path)
}

func (sc *scanCtx) stat(path string) (os.FileInfo, error) {
	if err := sc.local(path); err != nil {
		return nil, err
	}
	return os.Stat(sc.root + path)
}

func (sc *scanCtx) lstat(path string) (os.FileInfo, error) {
	if err := sc.local(path); err != nil {
		return nil, err
	}
	return os.Lstat(sc.root + path)
}

// exists is a presence probe; any error, permission included, means absent.
func (sc *scanCtx) exists(path string) bool {
	if sc.local(path) != nil {
		return false
	}
	_, err := os.Lstat(sc.root + path)
	return err == nil
}

// glob reports whether the pattern matches anything.
func (sc *scanCtx) glob(pattern string) bool {
	if sc.local(filepath.Dir(pattern)) != nil {
		return false
	}
	m, _ := filepath.Glob(sc.root + pattern)
	return len(m) > 0
}

// The user accessors are for paths other users control (home directories):
// no symlink is followed, a path on a pseudo filesystem is refused like a
// remote one, and without a readable mount table nothing is touched.

// readUser reads a regular file at a path without symlinks (resolveUser's),
// opened component by component so that a directory swapped for a link in
// the meantime fails the open; never more than its size, so a file that
// streams (a pseudo file reports 0) cannot hang the read.
func (sc *scanCtx) readUser(path string, limit int64) ([]byte, fs.FileInfo, error) {
	if err := sc.localStrict(path, false); err != nil {
		return nil, nil, err
	}
	f, err := openNoSymlinks(sc.root, path, false)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if fi.Size() > limit {
		return nil, nil, &fs.PathError{Op: "read", Path: path, Err: errTooLarge}
	}
	b, err := io.ReadAll(io.LimitReader(f, fi.Size()))
	return b, fi, err
}

// readDirUser lists a user directory: resolved first, then opened without
// following a link, so a glob in a home cannot be led into autofs.
func (sc *scanCtx) readDirUser(dir string) ([]os.DirEntry, error) {
	resolved, err := sc.resolveUser(dir)
	if err != nil {
		return nil, err
	}
	if err = sc.localStrict(resolved, false); err != nil {
		return nil, err
	}
	f, err := openNoSymlinks(sc.root, resolved, true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, err
}

// lstatUser may look at a pseudo filesystem: an lstat neither blocks nor
// consumes (/dev is the home of "sys"); reading there is what is refused.
func (sc *scanCtx) lstatUser(path string) (os.FileInfo, error) {
	if err := sc.localStrict(path, true); err != nil {
		return nil, err
	}
	return os.Lstat(sc.root + path)
}

// maxSymlinks bounds symlink resolution, as the kernel's 40.
const maxSymlinks = 40

// resolveUser resolves the symlinks of a user path, as realpath(3) does,
// but checks every path against the mount table before it touches it: an
// lstat behind a link into autofs would mount it. Targets are host paths,
// read under the scan root.
func (sc *scanCtx) resolveUser(p string) (string, error) {
	resolved, links := "/", 0
	rest := strings.Split(strings.Trim(path.Clean(p), "/"), "/")
	for len(rest) > 0 {
		comp := rest[0]
		rest = rest[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			resolved = path.Dir(resolved)
			continue
		}
		next := path.Join(resolved, comp)
		fi, err := sc.lstatUser(next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if links++; links > maxSymlinks {
			return "", &fs.PathError{Op: opOpen, Path: p, Err: syscall.ELOOP}
		}
		target, err := os.Readlink(sc.root + next)
		if err != nil {
			return "", err
		}
		if path.IsAbs(target) {
			resolved = "/"
		}
		rest = append(strings.Split(strings.Trim(target, "/"), "/"), rest...)
	}
	return resolved, nil
}

// local refuses a path on a remote filesystem. An unreadable mount table
// lets system paths through: /proc and /etc are not where autofs lives.
func (sc *scanCtx) local(path string) error {
	m, err := sc.mountTable()
	if err == nil && m.isRemote(path) {
		return &fs.PathError{Op: opOpen, Path: path, Err: errRemoteFS}
	}
	return nil
}

// localStrict is local for user paths: a pseudo filesystem is refused too,
// unless only stat is allowed, and without the mount table a home directory
// may be on autofs, so it is not touched.
func (sc *scanCtx) localStrict(path string, statOnly bool) error {
	m, err := sc.mountTable()
	if err != nil {
		return err
	}
	switch t := m.fsTypeOf(path); {
	case isRemoteFS(t):
		return &fs.PathError{Op: opOpen, Path: path, Err: errRemoteFS}
	case isPseudoFS(t) && !statOnly:
		return &fs.PathError{Op: opOpen, Path: path, Err: errPseudoFS}
	}
	return nil
}

func (sc *scanCtx) mountTable() (mounts, error) {
	sc.mountsOnce.Do(func() {
		m, err := loadMounts(sc.root)
		sc.mounts, sc.mountsErr = m.riskyOnly(), err
	})
	return sc.mounts, sc.mountsErr
}

// today is the day of the pass, in days since 1970-01-01 as shadow counts.
func (sc *scanCtx) today() int64 {
	now := sc.now
	if now.IsZero() {
		now = time.Now()
	}
	return now.Unix() / int64(24*time.Hour/time.Second)
}

// dep returns an earlier section and its result: from this pass, or from
// the last pass it ran in. ok is false when it never ran (disabled).
func (sc *scanCtx) dep(section string) (Section, any, bool) {
	if sc.deps == nil {
		return Section{}, nil, false
	}
	d, ok := sc.deps(section)
	return d.sec, d.res, ok
}

// readDirNames lists the names in a directory, for the parsers that take
// names (sshdconf, sudoers).
func (sc *scanCtx) readDirNames(dir string) ([]string, error) {
	return entryNames(sc.readDir(dir))
}

func entryNames(entries []os.DirEntry, err error) ([]string, error) {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, err
}

// readDirFiles lists the regular files of a drop-in directory, symlinks
// followed, by name — what apt, sudo, dnf and run-parts read from one. A
// subdirectory, FIFO, device or dangling link is skipped, as those tools skip
// it. The FileInfo is the target's, under the name in the directory.
func (sc *scanCtx) readDirFiles(dir string) ([]fs.FileInfo, error) {
	entries, err := sc.readDir(dir)
	out := make([]fs.FileInfo, 0, len(entries))
	for _, e := range entries {
		var (
			fi   fs.FileInfo
			ierr error
		)
		switch t := e.Type(); {
		case t.IsRegular():
			fi, ierr = e.Info()
		case t&fs.ModeSymlink != 0:
			fi, ierr = sc.stat(dir + "/" + e.Name())
		default:
			continue
		}
		if ierr == nil && fi.Mode().IsRegular() { // gone since the listing, or a link to anything else
			out = append(out, fi)
		}
	}
	return out, err
}

// infoNames are the names of readDirFiles, for the parsers that take names.
func infoNames(infos []fs.FileInfo, err error) ([]string, error) {
	names := make([]string, 0, len(infos))
	for _, fi := range infos {
		names = append(names, fi.Name())
	}
	return names, err
}

// process is one entry of the /proc walk, shared by the sections of a pass.
type process struct {
	pid  string
	exe  string // /proc/PID/exe, " (deleted)" trimmed; "" when unreadable
	name string // base name of exe, or of argv[0] when exe is unreadable
}

// processes walks /proc once per pass. Processes come and go during the
// walk, so a vanished one is skipped. The list is incomplete — with
// fs.ErrPermission — when /proc is mounted with hidepid: =1 refuses the
// details of other users' processes, =2 hides them, PID 1 included. Of the
// command line only argv[0] is read, and only when the executable link is
// unreadable: the rest may hold secrets.
func (sc *scanCtx) processes() ([]process, error) {
	sc.procsOnce.Do(func() { sc.procs, sc.procsErr = walkProcesses(sc) })
	return sc.procs, sc.procsErr
}

func walkProcesses(sc *scanCtx) ([]process, error) {
	entries, err := sc.readDir("/proc")
	if err != nil {
		return nil, err
	}
	var (
		out     []process
		denied  error
		sawInit bool
	)
	for _, e := range entries {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		sawInit = sawInit || pid == "1"
		p, err := readProcess(sc, pid)
		switch {
		case errors.Is(err, fs.ErrPermission):
			denied = err
		case err != nil:
			continue // exited during the walk, or a kernel thread
		}
		out = append(out, p)
	}
	if !sawInit {
		denied = fs.ErrPermission
	}
	return out, denied
}

func readProcess(sc *scanCtx, pid string) (process, error) {
	p := process{pid: pid}
	exe, err := sc.readlink("/proc/" + pid + "/exe")
	switch {
	case err == nil:
		p.exe = strings.TrimSuffix(exe, " (deleted)")
		p.name = filepath.Base(p.exe)
		return p, nil
	case errors.Is(err, fs.ErrNotExist):
		return p, err // a kernel thread or gone: no argv to read either
	}
	head, err := sc.readHead("/proc/"+pid+"/cmdline", argv0Limit)
	if err != nil {
		return p, err
	}
	argv0, _, _ := strings.Cut(string(head), "\x00")
	argv0, _, _ = strings.Cut(argv0, " ") // a rewritten title: "k3s server"
	if argv0 != "" {
		p.name = filepath.Base(argv0)
	}
	return p, nil
}

// trustedProcess: a process that runs as root from a binary only root can
// change. Any user can start ~/bin/sshd -f ~/evil, whose -f and Include
// would otherwise make the agent read files of its choosing — or
// ~/bin/dockerd naming a socket and a daemon.json.
func trustedProcess(sc *scanCtx, p process) bool {
	proc, err := sc.stat("/proc/" + p.pid)
	if err != nil {
		return false
	}
	if uid, _ := fileOwner(proc); uid != sc.trustedUID || p.exe == "" {
		return false
	}
	exe, err := sc.stat(p.exe)
	if err != nil {
		return false
	}
	uid, _ := fileOwner(exe)
	return uid == sc.trustedUID && exe.Mode().Perm()&0o022 == 0
}

// sameNamespace: the process is in the namespace of PID 1, or that cannot
// be told.
func sameNamespace(sc *scanCtx, pid, kind, host string) bool {
	ns, err := sc.readlink("/proc/" + pid + "/ns/" + kind)
	return err != nil || host == "" || ns == host
}

// processStart is when a process started: field 22 of /proc/PID/stat, in
// clock ticks since boot (USER_HZ, 100 on Linux), plus btime of /proc/stat.
func processStart(sc *scanCtx, pid string) *time.Time {
	stat, err := sc.read("/proc/"+pid+"/stat", smallFileLimit)
	if err != nil {
		return nil
	}
	_, after, ok := bytes.CutLast(stat, []byte(")")) // comm may hold spaces and parentheses
	f := strings.Fields(string(after))
	if !ok || len(f) < 20 {
		return nil
	}
	ticks, err := strconv.ParseInt(f[19], 10, 64)
	if err != nil {
		return nil
	}
	b, err := sc.read("/proc/stat", procStatLimit)
	if err != nil {
		return nil
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			btime, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return nil
			}
			t := time.Unix(btime+ticks/100, 0).UTC()
			return &t
		}
	}
	return nil
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
	// run collects the section. A non-nil result is what later sections of
	// the pass build on (accounts → sshd → authorizedKeys); it is kept only
	// when the section finished within its budget.
	run func(context.Context, *scanCtx) (Section, any)
}

// allSections of this release, in pass order: a section comes after those
// whose results it reads. Kernel facts are global, so the kernel section is
// collected in a container too.
var allSections = []sectionDef{
	{name: SectionKernel, budget: 2 * time.Second, run: noResult(collectKernel)},
	{name: SectionSysctl, budget: 2 * time.Second, host: true, run: noResult(collectSysctl)},
	{name: SectionAccounts, budget: 2 * time.Second, host: true, run: collectAccounts},
	{name: SectionSSHD, budget: 3 * time.Second, host: true, run: collectSSHD},
	{name: SectionAuthorizedKeys, budget: 10 * time.Second, host: true, run: noResult(collectAuthorizedKeys)},
	{name: SectionSudoers, budget: 3 * time.Second, host: true, run: noResult(collectSudoers)},
	{name: SectionUpdates, budget: 2 * time.Second, host: true, run: noResult(collectUpdates)},
	{name: SectionDocker, budget: dockerAPIBudget + 3*time.Second, host: true, run: noResult(collectDocker)},
	{name: SectionRoleSignals, budget: 5 * time.Second, host: true, run: noResult(collectRoleSignals)},
}

// noResult adapts a section no other section builds on.
func noResult(f func(context.Context, *scanCtx) Section) func(context.Context, *scanCtx) (Section, any) {
	return func(ctx context.Context, sc *scanCtx) (Section, any) { return f(ctx, sc), nil }
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
	sc := &scanCtx{root: c.root, timeSync: c.timeSync, key: c.key, now: start, deps: c.dep, trustedUID: c.trustedUID}
	var envSec Section
	envSec, sc.env = c.environment(sc)
	for _, def := range c.sections {
		if len(t.Sections) > 0 && !slices.Contains(t.Sections, def.name) {
			continue
		}
		sec, res := c.runSection(ctx, def, sc)
		c.store(def.name, sec, res, start)
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
func (c *Collector) runSection(ctx context.Context, def sectionDef, sc *scanCtx) (Section, any) {
	switch {
	case !c.supported:
		return unknown(ReasonUnsupportedPlatform), nil
	case def.host && sc.env.appContainer():
		return unknown(ReasonContainerEnv), nil
	case !c.startInflight(def.name):
		return unknown(ReasonTimeout), nil // still stuck since an earlier pass
	}

	type outcome struct {
		sec Section
		res any
	}
	sctx, cancel := context.WithTimeout(ctx, def.budget)
	defer cancel()
	start := time.Now()
	done := make(chan outcome, 1)
	go func() {
		var o outcome
		defer func() {
			// Parsers read untrusted files: a bug there must not take the
			// agent down. Only the panic type and site are logged — its value
			// may quote the input.
			if r := recover(); r != nil {
				c.Error(ctx, "security: section panicked", "section", def.name,
					"error", fmt.Sprintf("panic %T at %s", r, panicSite()))
				o = outcome{sec: unknown(ReasonParseError)}
			}
			c.endInflight(def.name)
			done <- o
		}()
		o.sec, o.res = def.run(sctx, sc)
	}()

	var o outcome
	select {
	case o = <-done:
	case <-sctx.Done():
		select {
		case o = <-done: // returned right at the deadline
		default:
			o = outcome{sec: unknown(ReasonTimeout)}
		}
	}
	o.sec.DurationMs = time.Since(start).Milliseconds()
	return o.sec, o.res
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

func (c *Collector) store(name string, sec Section, res any, at time.Time) {
	c.recordMetrics(name, sec)
	c.mu.Lock()
	c.cache[name] = cachedSection{sec: sec, at: at}
	c.results[name] = depResult{sec: sec, res: res} // a fresh run replaces a stale result, a failed one too
	c.mu.Unlock()
}

// dep is scanCtx.deps: the last run of a section, for the sections after
// it and for an unscheduled pass that rebuilds a dependent alone.
func (c *Collector) dep(name string) (depResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, ok := c.results[name]
	return d, ok
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
