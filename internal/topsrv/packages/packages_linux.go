//go:build linux

package packages

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// inventoryKindPackages is the discriminator used in /v1/inventory for the
// installed-packages snapshot. Repos / packageHistory land in Phase 4.
const inventoryKindPackages = "packages"

// scan walks the filesystem package databases and refreshes the cache.
// Called from Run() under a long interval (default 6h).
func (c *Collector) scan(ctx context.Context) {
	host := detectHost("")
	managers := c.resolveManagers()

	limit := c.cfg.MaxPackagesOrDefault()
	now := time.Now().UTC()

	var (
		metrics   []prometheus.Metric
		snapshots []Snapshot
		errBumps  []string
	)
	for _, m := range managers {
		if ctx.Err() != nil {
			return
		}
		snap, mx, ok := c.scanManager(ctx, m, host, limit, now)
		metrics = append(metrics, mx...)
		if !ok {
			errBumps = append(errBumps, m.name)
			continue
		}
		snapshots = append(snapshots, snap)
	}

	pending := buildPendingPayloads(host, snapshots, now, !c.cfg.DisablePush)

	c.mu.Lock()
	c.cache = metrics
	c.pending = pending
	c.scanned = true
	if c.scanErrCount == nil {
		c.scanErrCount = make(map[string]int, len(errBumps))
	}
	for _, name := range errBumps {
		c.scanErrCount[name]++
	}
	c.mu.Unlock()
}

// resolveManagers honours an explicit [Packages].Managers list when set,
// otherwise falls back to filesystem detection. Order is preserved.
func (c *Collector) resolveManagers() []managerFunc {
	if len(c.cfg.Managers) == 0 {
		return detectManagers(c.Logger, "")
	}
	var out []managerFunc
	for _, name := range c.cfg.Managers {
		switch name {
		case ManagerDpkg:
			d := NewDpkg(c.Logger, "")
			out = append(out, managerFunc{name: d.Name(), scan: d.Scan})
		case ManagerRpm:
			r := NewRpm(c.Logger, "")
			out = append(out, managerFunc{name: r.Name(), scan: r.Scan})
		case ManagerApk:
			a := NewApk(c.Logger, "")
			out = append(out, managerFunc{name: a.Name(), scan: a.Scan})
		}
	}
	return out
}

// scanManager runs one manager's Scan(), builds its metric vector, and
// returns ok=false on parse failure. Caller bumps the error counter on !ok.
func (c *Collector) scanManager(ctx context.Context, m managerFunc, host HostMeta, limit int, now time.Time) (Snapshot, []prometheus.Metric, bool) {
	start := time.Now()
	snap, err := m.scan(ctx)
	duration := time.Since(start).Seconds()

	if err != nil {
		c.Error(ctx, "packages: scan failed", "manager", m.name, "error", err)
		return Snapshot{}, nil, false
	}

	total := len(snap.Packages)
	if total > limit {
		snap.Packages = snap.Packages[:limit]
		c.Print(ctx, "packages: snapshot truncated", "manager", m.name, "total", total, "limit", limit)
	}

	held := countHeld(snap.Packages)

	c.mu.Lock()
	firstScan := !c.scanned
	c.mu.Unlock()
	if firstScan {
		c.Print(ctx, "packages: initial scan complete",
			"manager", m.name, "total", total, "held", held, "duration_s", duration)
	}

	return snap, []prometheus.Metric{
		prometheus.MustNewConstMetric(c.installed, prometheus.GaugeValue, float64(total), m.name),
		prometheus.MustNewConstMetric(c.held, prometheus.GaugeValue, float64(held), m.name),
		prometheus.MustNewConstMetric(c.scanDuration, prometheus.GaugeValue, duration, m.name),
		prometheus.MustNewConstMetric(c.lastScanTS, prometheus.GaugeValue, float64(now.Unix()), m.name),
		prometheus.MustNewConstMetric(c.managerInfo, prometheus.GaugeValue, 1, m.name, host.OsID, host.OsVersionID),
	}, true
}

// buildPendingPayloads constructs the /v1/inventory payloads. One payload per
// snapshot keeps gatesrv routing simple (one POST per kind+manager). When
// PushInventory is disabled we still keep metrics but skip the buffer —
// Inventory() returns nil.
func buildPendingPayloads(host HostMeta, snaps []Snapshot, now time.Time, pushEnabled bool) []Payload {
	if !pushEnabled {
		return nil
	}
	out := make([]Payload, 0, len(snaps))
	for _, s := range snaps {
		h := host
		h.PackageManager = s.Manager
		out = append(out, Payload{
			Kind:      inventoryKindPackages,
			ScannedAt: now,
			Host:      h,
			Data:      s,
		})
	}
	return out
}

func countHeld(pkgs []Package) int {
	n := 0
	for _, p := range pkgs {
		if p.Status == StatusHoldInstalled {
			n++
		}
	}
	return n
}
