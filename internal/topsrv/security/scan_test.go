package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/inventory"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// hostFixture is a Debian host with every section's sources.
func hostFixture() map[string]string {
	roles := rolesFixture()
	delete(roles, "proc/self") // a directory here
	return merge(hostProc(), kernelFixture(), sysctlFixture(), roles, map[string]string{
		"etc/os-release":             "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
		"proc/sys/kernel/osrelease":  "6.1.0-27-amd64\n",
		"var/lib/dpkg/status":        "",
		"lib64/ld-linux-x86-64.so.2": "",
		"run/systemd/system/":        "",
	})
}

// newTestCollector returns a collector over a fixture root, with a fixed
// clock and no adjtimex.
func newTestCollector(t *testing.T, files map[string]string) (*Collector, *time.Time) {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, files)
	var cfg Config
	require.NoError(t, cfg.Validate())
	c := NewCollector(embedlog.Logger{}, cfg, t.TempDir())
	c.root, c.supported, c.timeSync = root, true, nil
	c.key = tokenKey{secret: make([]byte, keySize), id: "0a1b2c3d"}
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	return c, &now
}

func dataOf(t *testing.T, p inventory.Payload) Data {
	t.Helper()
	d := p.Data.(Data)
	return d
}

func TestPass(t *testing.T) {
	c, now := newTestCollector(t, hostFixture())

	p := c.pass(t.Context(), Trigger{Cause: triggerStart})

	assert.Equal(t, Kind, p.Kind)
	assert.Equal(t, *now, p.ScannedAt)
	assert.Equal(t, "debian", p.Host.OsID)
	assert.Equal(t, inventory.ManagerDpkg, p.Host.PackageManager, "required by the inventory endpoint")
	d := dataOf(t, p)
	assert.Equal(t, SchemaVersion, d.SchemaVersion)
	assert.Equal(t, triggerStart, d.Trigger)
	assert.Equal(t, "0a1b2c3d", d.Agent.KeyID)
	assert.Equal(t, 0, d.Agent.UID)
	assert.Contains(t, d.Agent.CapEff, "CAP_SYS_PTRACE")
	assert.Equal(t, StatusOK, d.Environment.Status)
	require.Len(t, d.Sections, 3)
	for name, sec := range d.Sections {
		assert.Equal(t, StatusOK, sec.Status, "%s: %v", name, sec.Gaps)
	}

	var wire map[string]any
	require.NoError(t, json.Unmarshal([]byte(toJSON(t, p)), &wire))
	data, isMap := wire["data"].(map[string]any)
	require.True(t, isMap)
	for _, key := range []string{"schemaVersion", "trigger", "agent", "environment", "sections"} {
		assert.Contains(t, data, key)
	}
}

// fakeSection counts runs and returns what next says. runs is atomic: a
// section runs in its own goroutine.
type fakeSection struct {
	runs atomic.Int32
	next func(ctx context.Context) Section
}

func (f *fakeSection) def(name string, budget time.Duration) sectionDef {
	return sectionDef{name: name, budget: budget, run: func(ctx context.Context, _ *scanCtx) Section {
		f.runs.Add(1)
		return f.next(ctx)
	}}
}

func TestPassSectionCache(t *testing.T) {
	c, now := newTestCollector(t, hostProc())
	a := &fakeSection{next: func(context.Context) Section { return ok("a1") }}
	b := &fakeSection{next: func(context.Context) Section { return ok("b1") }}
	c.sections = []sectionDef{a.def("a", time.Second), b.def("b", time.Second)}
	c.cfg.parsedInterval = time.Hour

	c.pass(t.Context(), Trigger{Cause: triggerStart})
	a.next = func(context.Context) Section { return ok("a2") }
	b.next = func(context.Context) Section { return ok("b2") }
	*now = now.Add(10 * time.Minute)
	d := dataOf(t, c.pass(t.Context(), Trigger{Cause: "inotify", Sections: []string{"b"}}))

	assert.EqualValues(t, 1, a.runs.Load(), "an unscheduled pass rebuilds only its sections")
	assert.EqualValues(t, 2, b.runs.Load())
	assert.Equal(t, "a1", d.Sections["a"].Data, "the rest comes from the cache")
	assert.Equal(t, "b2", d.Sections["b"].Data)

	*now = now.Add(2*time.Hour + time.Minute)
	d = dataOf(t, c.pass(t.Context(), Trigger{Cause: "inotify", Sections: []string{"b"}}))
	assert.Equal(t, unknown(ReasonTimeout), d.Sections["a"], "older than two intervals")
}

func TestPassWatchdog(t *testing.T) {
	c, _ := newTestCollector(t, hostProc())
	release := make(chan struct{})
	stuck := &fakeSection{next: func(context.Context) Section {
		<-release // a read on a hung NFS mount ignores the context
		return ok("late")
	}}
	fine := &fakeSection{next: func(context.Context) Section { return ok("fine") }}
	c.sections = []sectionDef{stuck.def("stuck", 20*time.Millisecond), fine.def("fine", time.Second)}

	d := dataOf(t, c.pass(t.Context(), Trigger{Cause: triggerStart}))
	assert.Equal(t, StatusUnknown, d.Sections["stuck"].Status)
	assert.Equal(t, ReasonTimeout, d.Sections["stuck"].Reason)
	assert.Equal(t, "fine", d.Sections["fine"].Data, "the pass goes on past a stuck section")

	d = dataOf(t, c.pass(t.Context(), Trigger{Cause: triggerInterval}))
	assert.Equal(t, ReasonTimeout, d.Sections["stuck"].Reason)
	assert.EqualValues(t, 1, stuck.runs.Load(), "not started again while the first run is stuck")
	require.NoError(t, testutil.CollectAndCompare(c, strings.NewReader(`
# HELP topsrv_security_section_inflight 1 while a section runs; stays 1 for a section stuck past its budget until it returns.
# TYPE topsrv_security_section_inflight gauge
topsrv_security_section_inflight{section="fine"} 0
topsrv_security_section_inflight{section="stuck"} 1
`), "topsrv_security_section_inflight"))

	close(release)
	require.Eventually(t, func() bool { return !c.isInflight("stuck") }, time.Second, time.Millisecond)
	d = dataOf(t, c.pass(t.Context(), Trigger{Cause: triggerInterval}))
	assert.Equal(t, "late", d.Sections["stuck"].Data)
	assert.EqualValues(t, 2, stuck.runs.Load())
}

func TestPassPanic(t *testing.T) {
	c, _ := newTestCollector(t, hostProc())
	bad := &fakeSection{next: func(context.Context) Section { panic("index out of range") }}
	c.sections = []sectionDef{bad.def("bad", time.Second)}

	d := dataOf(t, c.pass(t.Context(), Trigger{Cause: triggerStart}))

	assert.Equal(t, ReasonParseError, d.Sections["bad"].Reason)
	assert.False(t, c.isInflight("bad"))
}

func TestPassAppContainer(t *testing.T) {
	c, _ := newTestCollector(t, merge(hostFixture(), map[string]string{
		"proc/self/ns/pid": "-> pid:[4026532501]",
		".dockerenv":       "",
	}))

	d := dataOf(t, c.pass(t.Context(), Trigger{Cause: triggerStart}))

	assert.Equal(t, StatusOK, d.Sections[SectionKernel].Status, "kernel facts are global")
	assert.Equal(t, unknown(ReasonContainerEnv), withoutDuration(d.Sections[SectionSysctl]))
	assert.Equal(t, unknown(ReasonContainerEnv), withoutDuration(d.Sections[SectionRoleSignals]))
}

func TestPassUnsupportedPlatform(t *testing.T) {
	c, _ := newTestCollector(t, hostFixture())
	c.supported = false

	p := c.pass(t.Context(), Trigger{Cause: triggerStart})
	d := dataOf(t, p)

	assert.Equal(t, ReasonUnsupportedPlatform, d.Environment.Reason)
	for name, sec := range d.Sections {
		assert.Equal(t, ReasonUnsupportedPlatform, sec.Reason, name)
	}
	c.finish(t.Context(), p)
	assert.Empty(t, c.Inventory(), "nothing is sent from an unsupported platform")
}

func TestInventory(t *testing.T) {
	c, _ := newTestCollector(t, hostFixture())

	assert.Empty(t, c.Inventory(), "nothing before the first pass")
	c.finish(t.Context(), c.pass(t.Context(), Trigger{Cause: triggerStart}))
	got := c.Inventory()
	require.Len(t, got, 1)
	assert.Equal(t, Kind, got[0].Kind)
	assert.Empty(t, c.Inventory(), "one-shot")

	c.cfg.DisablePush = true
	c.finish(t.Context(), c.pass(t.Context(), Trigger{Cause: triggerInterval}))
	assert.Empty(t, c.Inventory(), "DisablePush keeps snapshots local")
}

func TestCollectorMetrics(t *testing.T) {
	c, _ := newTestCollector(t, hostFixture())
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(c))

	c.finish(t.Context(), c.pass(t.Context(), Trigger{Cause: triggerStart}))
	c.OnInventoryPushed(Kind)

	families, err := reg.Gather()
	require.NoError(t, err)
	names := make([]string, 0, len(families))
	for _, f := range families {
		names = append(names, f.GetName())
	}
	assert.ElementsMatch(t, []string{
		"topsrv_security_scan_duration_seconds",
		"topsrv_security_last_scan_timestamp_seconds",
		"topsrv_security_last_push_timestamp_seconds",
		"topsrv_security_snapshot_bytes",
		"topsrv_security_section_inflight",
	}, names, "no errors yet, so no error series")
	problems, err := testutil.GatherAndLint(reg)
	require.NoError(t, err)
	assert.Empty(t, problems)
}

func TestRun(t *testing.T) {
	c, _ := newTestCollector(t, hostFixture())
	c.now, c.delay = time.Now, 0
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx)
	}()

	var got []inventory.Payload
	require.Eventually(t, func() bool { got = c.Inventory(); return len(got) == 1 }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, triggerStart, dataOf(t, got[0]).Trigger)
	assert.FileExists(t, filepath.Join(c.stateDir, keyFile), "Run creates the token key")

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestDryRun(t *testing.T) {
	stateDir := t.TempDir()

	out, err := DryRun(t.Context(), embedlog.Logger{}, Config{}, stateDir, "1.2.3", []string{SectionSysctl})
	require.NoError(t, err)

	var p struct {
		Kind         string `json:"kind"`
		AgentVersion string `json:"agentVersion"`
		Data         Data   `json:"data"`
	}
	require.NoError(t, json.Unmarshal(out, &p))
	assert.Equal(t, Kind, p.Kind)
	assert.Equal(t, "1.2.3", p.AgentVersion, "the version the pusher would stamp")
	assert.Equal(t, "dry-run", p.Data.Trigger)
	assert.Equal(t, ephemeralKeyID, p.Data.Agent.KeyID)
	assert.Equal(t, []string{SectionSysctl}, slices.Collect(maps.Keys(p.Data.Sections)))
	assert.True(t, strings.HasPrefix(string(out), "{\n  \"kind\""), "indented")
	entries, err := os.ReadDir(stateDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "dry-run writes nothing")

	_, err = DryRun(t.Context(), embedlog.Logger{}, Config{}, stateDir, "1.2.3", []string{SectionSSHD})
	require.ErrorContains(t, err, `"sshd" is not collected by this version`)

	_, err = DryRun(t.Context(), embedlog.Logger{}, Config{DisabledSections: []string{SectionSysctl}}, stateDir, "1.2.3", []string{SectionSysctl})
	require.ErrorContains(t, err, `"sysctl" is disabled`)
}

func withoutDuration(s Section) Section {
	s.DurationMs = 0
	return s
}

func (c *Collector) isInflight(section string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inflight[section]
}

func TestTriggerCoalescesWithoutLoss(t *testing.T) {
	c, _ := newTestCollector(t, hostProc())

	for i := range 100 {
		c.Trigger("inotify", fmt.Sprintf("s%d", i))
	}

	assert.Len(t, c.queued.sections, 100, "no trigger dropped while Run is busy")
	assert.Equal(t, "inotify", c.queued.cause)
	assert.Len(t, c.wakeup, 1, "one wakeup for any number of triggers")
	c.Trigger("overflow")
	assert.Nil(t, c.queued.trigger().Sections, "a trigger without sections makes the pass full")
}

func TestRecoverPass(t *testing.T) {
	c, _ := newTestCollector(t, hostProc())
	logger, logged := captureLogs(t)
	c.Logger = logger

	_, ok := c.recoverPass(t.Context(), func() inventory.Payload { panic(errors.New("SENTINELLINE")) })

	assert.False(t, ok, "the snapshot is dropped, the agent goes on")
	assert.Contains(t, logged(), "panic *errors.errorString at scan_test.go:")
	assert.NotContains(t, logged(), "SENTINEL")
}

func TestReasonOf(t *testing.T) {
	for err, want := range map[error]Reason{
		fs.ErrPermission:         ReasonPermissionDenied,
		fs.ErrNotExist:           ReasonNotFound,
		errTooLarge:              ReasonBudgetExceeded,
		context.DeadlineExceeded: ReasonTimeout,
		&fs.PathError{Op: "open", Err: errNotRegular}: ReasonNotRegular,
		fmt.Errorf("line 3: %w", errParse):            ReasonParseError,
		syscall.EIO:                                   ReasonIOError,
	} {
		assert.Equal(t, want, reasonOf(err), "%v", err)
	}
}
