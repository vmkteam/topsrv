package security

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv/inventory"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

const labelSection = "section"

// Collector scans the host on a schedule and hands the snapshot to the
// pusher through Inventory. Scans run in one goroutine, section by section;
// /metrics only reads what the last pass left.
type Collector struct {
	embedlog.Logger

	cfg       Config
	stateDir  string
	sections  []sectionDef // enabled, in pass order
	root      string       // "" in production, a fixture in tests
	supported bool         // Linux; elsewhere every section is unsupported_platform
	timeSync  func() (*timeSync, error)
	now       func() time.Time
	delay     time.Duration // before the first pass
	wakeup    chan struct{} // Trigger → Run; the triggers themselves are in queued
	key       tokenKey

	scanDuration *prometheus.Desc
	scanErrors   *prometheus.Desc
	lastScanTS   *prometheus.Desc
	lastPushTS   *prometheus.Desc
	snapshotSize *prometheus.Desc
	inflightDesc *prometheus.Desc

	mu            sync.Mutex
	cache         map[string]cachedSection
	inflight      map[string]bool
	queued        triggerSet          // triggers not yet taken by Run
	pending       []inventory.Payload // one-shot, drained by Inventory
	durations     map[string]float64  // section → seconds, last run
	errCounts     map[[2]string]int   // {section, reason} → count
	lastScan      time.Time
	lastPush      time.Time
	snapshotBytes int
}

// NewCollector builds the collector; cfg must be validated. stateDir holds
// the token key.
func NewCollector(logger embedlog.Logger, cfg Config, stateDir string) *Collector {
	c := &Collector{
		Logger:    logger,
		cfg:       cfg,
		stateDir:  stateDir,
		supported: runtime.GOOS == "linux",
		timeSync:  timeSyncReader(),
		now:       time.Now,
		delay:     startDelay(),
		wakeup:    make(chan struct{}, 1),
		cache:     map[string]cachedSection{},
		inflight:  map[string]bool{},
		durations: map[string]float64{},
		errCounts: map[[2]string]int{},

		scanDuration: prometheus.NewDesc("topsrv_security_scan_duration_seconds",
			"Duration of the last run of a security section.", []string{labelSection}, nil),
		scanErrors: prometheus.NewDesc("topsrv_security_scan_errors_total",
			"Security sections that came out unknown, or with a gap, by reason.", []string{labelSection, "reason"}, nil),
		lastScanTS: prometheus.NewDesc("topsrv_security_last_scan_timestamp_seconds",
			"Unix time of the last security pass.", nil, nil),
		lastPushTS: prometheus.NewDesc("topsrv_security_last_push_timestamp_seconds",
			"Unix time of the last security snapshot accepted by /v1/inventory.", nil, nil),
		snapshotSize: prometheus.NewDesc("topsrv_security_snapshot_bytes",
			"JSON size of the last security snapshot.", nil, nil),
		inflightDesc: prometheus.NewDesc("topsrv_security_section_inflight",
			"1 while a section runs; stays 1 for a section stuck past its budget until it returns.", []string{labelSection}, nil),
	}
	for _, def := range allSections {
		if cfg.SectionEnabled(def.name) {
			c.sections = append(c.sections, def)
		}
	}
	return c
}

func (c *Collector) Name() string { return Kind }

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.scanDuration
	ch <- c.scanErrors
	ch <- c.lastScanTS
	ch <- c.lastPushTS
	ch <- c.snapshotSize
	ch <- c.inflightDesc
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for section, sec := range c.durations {
		ch <- prometheus.MustNewConstMetric(c.scanDuration, prometheus.GaugeValue, sec, section)
	}
	for k, n := range c.errCounts {
		ch <- prometheus.MustNewConstMetric(c.scanErrors, prometheus.CounterValue, float64(n), k[0], k[1])
	}
	for _, def := range c.sections {
		v := 0.0
		if c.inflight[def.name] {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.inflightDesc, prometheus.GaugeValue, v, def.name)
	}
	if c.lastScan.IsZero() {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.lastScanTS, prometheus.GaugeValue, float64(c.lastScan.Unix()))
	ch <- prometheus.MustNewConstMetric(c.snapshotSize, prometheus.GaugeValue, float64(c.snapshotBytes))
	if !c.lastPush.IsZero() {
		ch <- prometheus.MustNewConstMetric(c.lastPushTS, prometheus.GaugeValue, float64(c.lastPush.Unix()))
	}
}

// Inventory drains the pending snapshot. One-shot: only the latest
// snapshot is kept until the pusher takes it.
func (c *Collector) Inventory() []inventory.Payload {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.pending
	c.pending = nil
	return out
}

// OnInventoryPushed records a live send accepted by the backend.
func (c *Collector) OnInventoryPushed(string) {
	c.mu.Lock()
	c.lastPush = c.now()
	c.mu.Unlock()
}

// Trigger asks for an unscheduled pass of the sections, all of them when
// none are given. It never blocks and loses nothing: triggers coalesce
// until Run takes them.
func (c *Collector) Trigger(cause string, sections ...string) {
	c.mu.Lock()
	c.queued.add(Trigger{Cause: cause, Sections: sections})
	c.mu.Unlock()
	select {
	case c.wakeup <- struct{}{}:
	default: // Run has a wakeup pending already
	}
}

// Run scans on schedule until ctx is cancelled: first after a random 1–5
// minute delay, then every Interval ±10%, plus unscheduled passes from
// Trigger, at most one per minUnscheduledGap.
func (c *Collector) Run(ctx context.Context) {
	c.Print(ctx, "security: started", "interval", c.cfg.ParsedInterval(), "sections", len(c.sections))
	c.key = c.loadKey(ctx)
	s := newSchedule(c.now(), c.cfg.ParsedInterval(), c.delay)
	for {
		timer := time.NewTimer(s.wake().Sub(c.now()))
		select {
		case <-ctx.Done():
			timer.Stop()
			c.Print(ctx, "security: stopped")
			return
		case <-c.wakeup:
			timer.Stop()
			c.mu.Lock()
			s.pending.merge(c.queued)
			c.queued = triggerSet{}
			c.mu.Unlock()
			continue
		case <-timer.C:
		}
		if t, ok := s.due(c.now()); ok {
			c.finish(ctx, c.pass(ctx, t))
		}
	}
}

// finish records a pass and queues its snapshot for the pusher.
func (c *Collector) finish(ctx context.Context, p inventory.Payload) {
	b, err := json.Marshal(p)
	if err != nil {
		c.Error(ctx, "security: snapshot marshal failed", "error", err)
		return
	}
	d, ok := p.Data.(Data)
	if !ok {
		c.Error(ctx, "security: snapshot without data", "type", fmt.Sprintf("%T", p.Data))
		return
	}
	unknownN := 0
	for _, sec := range d.Sections {
		if sec.Status == StatusUnknown {
			unknownN++
		}
	}
	c.mu.Lock()
	c.lastScan = p.ScannedAt
	c.snapshotBytes = len(b)
	if !c.cfg.DisablePush && c.supported { // nothing to send from a platform without the sources
		c.pending = []inventory.Payload{p}
	}
	c.mu.Unlock()
	c.Print(ctx, "security: snapshot ready", "trigger", d.Trigger, "bytes", len(b), "unknownSections", unknownN)
}

// loadKey loads or creates the token key. When that fails a random key for
// this run keeps the collector going; its new id tells the backend the
// tokens changed with the key, not the secrets.
func (c *Collector) loadKey(ctx context.Context) tokenKey {
	k, err := loadOrCreateKey(c.stateDir)
	if err != nil {
		c.Error(ctx, "security: token key unavailable, using one for this run", "dir", c.stateDir, "error", err)
		return randomKey()
	}
	return k
}

// recordMetrics keeps the duration of the section and counts unknown
// results and gaps by reason.
func (c *Collector) recordMetrics(name string, sec Section) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.durations[name] = float64(sec.DurationMs) / 1000
	if sec.Status == StatusUnknown {
		c.errCounts[[2]string{name, string(sec.Reason)}]++
	}
	for _, g := range sec.Gaps {
		c.errCounts[[2]string{name, string(g.Reason)}]++
	}
}

// DryRun runs one pass of the sections (every enabled one when empty) and
// returns the snapshot as indented JSON, exactly what would be sent. It
// writes nothing: the existing token key is used, or an ephemeral one.
func DryRun(ctx context.Context, logger embedlog.Logger, cfg Config, stateDir string, sections []string) ([]byte, error) {
	c := NewCollector(logger, cfg, stateDir)
	for _, name := range sections {
		switch {
		case !slices.ContainsFunc(allSections, func(d sectionDef) bool { return d.name == name }):
			return nil, fmt.Errorf("security: section %q is not collected by this version", name)
		case !cfg.SectionEnabled(name):
			return nil, fmt.Errorf("security: section %q is disabled in [Security].DisabledSections", name)
		}
	}
	if len(sections) > 0 {
		c.sections = slices.DeleteFunc(c.sections, func(d sectionDef) bool { return !slices.Contains(sections, d.name) })
	}
	c.key = existingOrEphemeralKey(stateDir)
	return json.MarshalIndent(c.pass(ctx, Trigger{Cause: "dry-run"}), "", "  ")
}
