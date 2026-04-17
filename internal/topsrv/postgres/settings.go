package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// settingsList — GUCs to expose as topsrv_pg_setting. Normalized to bytes or seconds in Go.
var settingsList = []string{
	"shared_buffers",
	"effective_cache_size",
	"work_mem",
	"maintenance_work_mem",
	"max_wal_size",
	"min_wal_size",
	"checkpoint_timeout",
	"wal_buffers",
	"random_page_cost",
}

// convertSetting normalizes a pg_settings row to canonical units: bytes for memory/WAL, seconds for time.
// Unitless settings (cost params) pass through unchanged.
func convertSetting(val, unit string) float64 {
	v, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return 0
	}
	switch unit {
	case "8kB":
		return v * 8 * 1024
	case "16kB":
		return v * 16 * 1024
	case "kB":
		return v * 1024
	case "MB":
		return v * 1024 * 1024
	case "GB":
		return v * 1024 * 1024 * 1024
	case "ms":
		return v / 1000
	case "s":
		return v
	case "min":
		return v * 60
	case "h":
		return v * 3600
	case "d":
		return v * 86400
	default: // "" for unitless (e.g. random_page_cost)
		return v
	}
}

// collectSettings emits selected GUCs (settingsList). Cached for settingRefreshInterval
// because GUCs change only via SIGHUP reload or restart.
func (c *Collector) collectSettings(ctx context.Context, ch chan<- prometheus.Metric) {
	c.settingsMu.Lock()
	if time.Since(c.settingsLastRefresh) > settingRefreshInterval {
		if err := c.refreshSettingsLocked(ctx); err != nil {
			c.queryWarn("settings", err)
		}
	}
	// Copy under lock, emit outside.
	snapshot := make(map[string]float64, len(c.settingsCache))
	for k, v := range c.settingsCache {
		snapshot[k] = v
	}
	c.settingsMu.Unlock()
	for name, val := range snapshot {
		ch <- prometheus.MustNewConstMetric(c.settingGauge, prometheus.GaugeValue, val, name)
	}
}

// refreshSettingsLocked must be called with settingsMu held.
func (c *Collector) refreshSettingsLocked(ctx context.Context) error {
	rows, err := c.pool.Query(ctx, `SELECT name, setting, unit FROM pg_settings WHERE name = ANY($1)`, settingsList)
	if err != nil {
		return err
	}
	defer rows.Close()
	fresh := make(map[string]float64, len(settingsList))
	for rows.Next() {
		var name, val string
		var unit *string
		if rows.Scan(&name, &val, &unit) != nil {
			continue
		}
		u := ""
		if unit != nil {
			u = *unit
		}
		fresh[name] = convertSetting(val, u)
	}
	c.settingsCache = fresh
	c.settingsLastRefresh = time.Now()
	return nil
}

// collectStatsReset emits timestamps of last pg_stat_* reset per scope.
// database: oldest reset across all DBs; bgwriter/wal/archiver: single values where available.
func (c *Collector) collectStatsReset(ctx context.Context, ch chan<- prometheus.Metric) {
	emit := func(scope string, ts *float64) {
		if ts != nil {
			ch <- prometheus.MustNewConstMetric(c.statsResetGauge, prometheus.GaugeValue, *ts, scope)
		}
	}

	var dbTS *float64
	_ = c.pool.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM min(stats_reset)) FROM pg_stat_database WHERE stats_reset IS NOT NULL`).Scan(&dbTS)
	emit("database", dbTS)

	var bgTS *float64
	_ = c.pool.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM stats_reset) FROM pg_stat_bgwriter`).Scan(&bgTS)
	emit("bgwriter", bgTS)

	if c.versionNum >= versionPG17 {
		var walTS *float64
		_ = c.pool.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM stats_reset) FROM pg_stat_wal`).Scan(&walTS)
		emit("wal", walTS)
	}

	if c.archiveEnabled {
		var arcTS *float64
		_ = c.pool.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM stats_reset) FROM pg_stat_archiver`).Scan(&arcTS)
		emit("archiver", arcTS)
	}
}
