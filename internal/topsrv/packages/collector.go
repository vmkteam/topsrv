package packages

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

// Collector reports installed-package counts and snapshot health on /metrics,
// and ships full inventory snapshots to /v1/inventory.
//
// Mirrors the smart/ pattern: a background goroutine populates `cache` on a
// long interval (default 6h), and scrape-time Collect() just drains it. The
// expensive filesystem walk never blocks /metrics.
type Collector struct {
	embedlog.Logger

	cfg Config

	installed    *prometheus.Desc
	held         *prometheus.Desc
	scanDuration *prometheus.Desc
	scanErrors   *prometheus.Desc
	lastScanTS   *prometheus.Desc
	lastPushTS   *prometheus.Desc
	managerInfo  *prometheus.Desc

	mu      sync.Mutex
	cache   []prometheus.Metric
	scanned bool //nolint:unused // mutated in packages_linux.go (build-tagged)

	// pending holds payloads produced by the last scan, drained by Inventory().
	// One-shot: each scan overwrites the previous pending if the pusher hasn't
	// drained — only the latest snapshot is ever sent.
	pending      []Payload
	lastPushUnix map[string]int64 // kind → last successful push unix sec
	scanErrCount map[string]int   // manager → cumulative scan failure count
}

// NewCollector wires descriptors. Caller must Validate() the config first.
func NewCollector(logger embedlog.Logger, cfg Config) *Collector {
	return &Collector{
		Logger: logger,
		cfg:    cfg,
		installed: prometheus.NewDesc(
			"topsrv_packages_installed",
			"Number of installed packages by manager.",
			[]string{"manager"}, nil),
		held: prometheus.NewDesc(
			"topsrv_packages_held",
			"Packages held back (dpkg hold / dnf versionlock).",
			[]string{"manager"}, nil),
		scanDuration: prometheus.NewDesc(
			"topsrv_packages_scan_duration_seconds",
			"Duration of the last inventory scan.",
			[]string{"manager"}, nil),
		scanErrors: prometheus.NewDesc(
			"topsrv_packages_scan_errors_total",
			"Cumulative scan failures by manager.",
			[]string{"manager"}, nil),
		lastScanTS: prometheus.NewDesc(
			"topsrv_packages_last_scan_timestamp_seconds",
			"Unix ts of last successful inventory scan.",
			[]string{"manager"}, nil),
		lastPushTS: prometheus.NewDesc(
			"topsrv_packages_last_push_timestamp_seconds",
			"Unix ts of last successful inventory push to /v1/inventory, by kind.",
			[]string{"kind"}, nil),
		managerInfo: prometheus.NewDesc(
			"topsrv_packages_manager_info",
			"Package manager and OS info.",
			[]string{"manager", "os_id", "os_version"}, nil),
	}
}

func (c *Collector) Name() string { return "packages" }

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.installed
	ch <- c.held
	ch <- c.scanDuration
	ch <- c.scanErrors
	ch <- c.lastScanTS
	ch <- c.lastPushTS
	ch <- c.managerInfo
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.cache {
		ch <- m
	}
	for kind, ts := range c.lastPushUnix {
		ch <- prometheus.MustNewConstMetric(c.lastPushTS, prometheus.GaugeValue, float64(ts), kind)
	}
	for mgr, n := range c.scanErrCount {
		ch <- prometheus.MustNewConstMetric(c.scanErrors, prometheus.CounterValue, float64(n), mgr)
	}
}

// Inventory drains the pending snapshot buffer. Called by Pusher each tick.
// One-shot: subsequent calls return nil until the next scan finishes.
func (c *Collector) Inventory() []Payload {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.pending
	c.pending = nil
	return out
}

// OnInventoryPushed implements InventoryAckReceiver. Surfaced via
// topsrv_packages_last_push_timestamp_seconds.
func (c *Collector) OnInventoryPushed(kind string) {
	c.mu.Lock()
	if c.lastPushUnix == nil {
		c.lastPushUnix = make(map[string]int64, 4)
	}
	c.lastPushUnix[kind] = time.Now().Unix()
	c.mu.Unlock()
}

// Run starts the background scan loop. Blocks until ctx is cancelled.
// Interval gets ±10% jitter per iteration so co-deployed agents don't
// stampede gatesrv at the same wall-clock instant.
func (c *Collector) Run(ctx context.Context) {
	interval := c.cfg.ParsedInterval()
	c.Print(ctx, "packages: started", "interval", interval)

	c.scan(ctx)

	for {
		timer := time.NewTimer(interval + jitter(interval))
		select {
		case <-ctx.Done():
			timer.Stop()
			c.Print(ctx, "packages: stopped")
			return
		case <-timer.C:
			c.scan(ctx)
		}
	}
}

// jitter returns a uniformly-distributed perturbation in ±10% of base. The
// math/rand/v2 package is auto-seeded per-process from the OS, so two agents
// started together drift apart naturally — no hostname-seeding needed.
func jitter(base time.Duration) time.Duration {
	span := int64(base) / 10
	if span <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(2*span) - span)
}
