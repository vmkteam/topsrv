package postgres

import (
	"context"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// msToSec converts PostgreSQL millisecond durations to Prometheus-canonical seconds.
const msToSec = 1e-3

func (c *Collector) collectConnections(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `SELECT coalesce(state, 'unknown'), count(*) FROM pg_stat_activity WHERE backend_type = 'client backend' GROUP BY state`)
	if err != nil {
		c.queryWarn("connections", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var count int64
		if rows.Scan(&state, &count) == nil {
			ch <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, float64(count), state)
		}
	}

	rows2, err := c.pool.Query(ctx, `SELECT coalesce(client_addr::text, 'local'), coalesce(state, 'unknown'), count(*) FROM pg_stat_activity WHERE backend_type = 'client backend' GROUP BY client_addr, state`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var addr, state string
			var count int64
			if rows2.Scan(&addr, &state, &count) == nil {
				ch <- prometheus.MustNewConstMetric(c.connectionsByAddr, prometheus.GaugeValue, float64(count), addr, state)
			}
		}
	}

	rows3, err := c.pool.Query(ctx, `SELECT coalesce(nullif(application_name, ''), 'unknown'), coalesce(state, 'unknown'), count(*) FROM pg_stat_activity WHERE backend_type = 'client backend' GROUP BY application_name, state`)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var app, state string
			var count int64
			if rows3.Scan(&app, &state, &count) == nil {
				ch <- prometheus.MustNewConstMetric(c.connectionsByApp, prometheus.GaugeValue, float64(count), app, state)
			}
		}
	}

	var bgWorkers int64
	if c.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'background worker'`).Scan(&bgWorkers) == nil {
		ch <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, float64(bgWorkers), "background worker")
	}

	var maxConn int64
	if c.pool.QueryRow(ctx, `SELECT setting::bigint FROM pg_settings WHERE name = 'max_connections'`).Scan(&maxConn) == nil {
		ch <- prometheus.MustNewConstMetric(c.maxConns, prometheus.GaugeValue, float64(maxConn))
	}
}

func (c *Collector) collectTransactions(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `SELECT datname, xact_commit, xact_rollback, deadlocks, temp_files, temp_bytes, blks_hit, blks_read FROM pg_stat_database WHERE datname NOT LIKE 'template%'`)
	if err != nil {
		c.queryWarn("transactions", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var db string
		var commit, rollback, deadlocks, tempFiles, tempBytes, blksHit, blksRead int64
		if rows.Scan(&db, &commit, &rollback, &deadlocks, &tempFiles, &tempBytes, &blksHit, &blksRead) == nil {
			ch <- prometheus.MustNewConstMetric(c.xact, prometheus.CounterValue, float64(commit), db, "commit")
			ch <- prometheus.MustNewConstMetric(c.xact, prometheus.CounterValue, float64(rollback), db, "rollback")
			ch <- prometheus.MustNewConstMetric(c.deadlocks, prometheus.CounterValue, float64(deadlocks), db)
			ch <- prometheus.MustNewConstMetric(c.tempFiles, prometheus.CounterValue, float64(tempFiles), db)
			ch <- prometheus.MustNewConstMetric(c.tempBytes, prometheus.CounterValue, float64(tempBytes), db)
			ch <- prometheus.MustNewConstMetric(c.blks, prometheus.CounterValue, float64(blksHit), db, "hit")
			ch <- prometheus.MustNewConstMetric(c.blks, prometheus.CounterValue, float64(blksRead), db, "read")
		}
	}
}

func (c *Collector) collectBGWriter(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.versionNum >= versionPG17 {
		c.collectCheckpointerPG17(ctx, ch)
		c.collectBGWriterBuffers(ctx, ch)
	} else {
		c.collectBGWriterPG15(ctx, ch)
	}
}

func (c *Collector) collectBGWriterPG15(ctx context.Context, ch chan<- prometheus.Metric) {
	var timed, req, writeTime, syncTime, bufCP, bufClean, bufBackend, bufAlloc int64
	err := c.pool.QueryRow(ctx, `SELECT checkpoints_timed, checkpoints_req, checkpoint_write_time, checkpoint_sync_time, buffers_checkpoint, buffers_clean, buffers_backend, buffers_alloc FROM pg_stat_bgwriter`).
		Scan(&timed, &req, &writeTime, &syncTime, &bufCP, &bufClean, &bufBackend, &bufAlloc)
	if err != nil {
		c.queryWarn("bgwriter_pg15", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.checkpoints, prometheus.CounterValue, float64(timed), "timed")
	ch <- prometheus.MustNewConstMetric(c.checkpoints, prometheus.CounterValue, float64(req), "requested")
	ch <- prometheus.MustNewConstMetric(c.checkpointTime, prometheus.CounterValue, float64(writeTime)*msToSec, "write")
	ch <- prometheus.MustNewConstMetric(c.checkpointTime, prometheus.CounterValue, float64(syncTime)*msToSec, "sync")
	ch <- prometheus.MustNewConstMetric(c.buffers, prometheus.CounterValue, float64(bufCP), "checkpoint")
	ch <- prometheus.MustNewConstMetric(c.buffers, prometheus.CounterValue, float64(bufClean), "clean")
	ch <- prometheus.MustNewConstMetric(c.buffers, prometheus.CounterValue, float64(bufBackend), "backend")
	ch <- prometheus.MustNewConstMetric(c.buffers, prometheus.CounterValue, float64(bufAlloc), "alloc")
}

func (c *Collector) collectCheckpointerPG17(ctx context.Context, ch chan<- prometheus.Metric) {
	var timed, req int64
	var writeTime, syncTime float64
	var bufCP int64
	err := c.pool.QueryRow(ctx, `SELECT num_timed, num_requested, write_time, sync_time, buffers_written FROM pg_stat_checkpointer`).
		Scan(&timed, &req, &writeTime, &syncTime, &bufCP)
	if err != nil {
		c.queryWarn("checkpointer_pg17", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.checkpoints, prometheus.CounterValue, float64(timed), "timed")
	ch <- prometheus.MustNewConstMetric(c.checkpoints, prometheus.CounterValue, float64(req), "requested")
	ch <- prometheus.MustNewConstMetric(c.checkpointTime, prometheus.CounterValue, writeTime*msToSec, "write")
	ch <- prometheus.MustNewConstMetric(c.checkpointTime, prometheus.CounterValue, syncTime*msToSec, "sync")
	ch <- prometheus.MustNewConstMetric(c.buffers, prometheus.CounterValue, float64(bufCP), "checkpoint")
}

func (c *Collector) collectBGWriterBuffers(ctx context.Context, ch chan<- prometheus.Metric) {
	// PG17: pg_stat_bgwriter has only buffers_clean and buffers_alloc (no buffers_backend).
	var bufClean, bufAlloc int64
	err := c.pool.QueryRow(ctx, `SELECT buffers_clean, buffers_alloc FROM pg_stat_bgwriter`).
		Scan(&bufClean, &bufAlloc)
	if err != nil {
		c.queryWarn("bgwriter_buffers", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.buffers, prometheus.CounterValue, float64(bufClean), "clean")
	ch <- prometheus.MustNewConstMetric(c.buffers, prometheus.CounterValue, float64(bufAlloc), "alloc")
}

func (c *Collector) collectAutovacuum(ctx context.Context, ch chan<- prometheus.Metric) {
	var common, wraparound int64
	err := c.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE query NOT LIKE '%wraparound%'), count(*) FILTER (WHERE query LIKE '%wraparound%') FROM pg_stat_activity WHERE backend_type = 'autovacuum worker'`).
		Scan(&common, &wraparound)
	if err != nil {
		c.queryWarn("autovacuum", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.avWorkers, prometheus.GaugeValue, float64(common), "common")
	ch <- prometheus.MustNewConstMetric(c.avWorkers, prometheus.GaugeValue, float64(wraparound), "wraparound")

	var maxW int64
	if c.pool.QueryRow(ctx, `SELECT setting::bigint FROM pg_settings WHERE name = 'autovacuum_max_workers'`).Scan(&maxW) == nil {
		ch <- prometheus.MustNewConstMetric(c.avMaxWorkers, prometheus.GaugeValue, float64(maxW))
	}
}

func (c *Collector) collectLocks(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `SELECT mode, granted, count(*) FROM pg_locks WHERE mode IS NOT NULL GROUP BY mode, granted`)
	if err != nil {
		c.queryWarn("locks", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var mode string
		var granted bool
		var count int64
		if rows.Scan(&mode, &granted, &count) == nil {
			ch <- prometheus.MustNewConstMetric(c.locks, prometheus.GaugeValue, float64(count), mode, strconv.FormatBool(granted))
		}
	}

	// Backends currently waiting on a lock + longest wait duration.
	// wait_event_type='Lock' covers heavyweight locks; tx_start gives wait start since backend was holding.
	var blocked int64
	var waitMax float64
	if c.pool.QueryRow(ctx, `SELECT count(*), COALESCE(max(EXTRACT(EPOCH FROM (now() - xact_start))), 0)
		FROM pg_stat_activity WHERE wait_event_type = 'Lock'`).
		Scan(&blocked, &waitMax) == nil {
		ch <- prometheus.MustNewConstMetric(c.blockedBackends, prometheus.GaugeValue, float64(blocked))
		ch <- prometheus.MustNewConstMetric(c.lockWaitMax, prometheus.GaugeValue, waitMax)
	}
}

func (c *Collector) collectDatabaseSizes(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `SELECT datname, pg_database_size(datname) FROM pg_database WHERE datistemplate = false`)
	if err != nil {
		c.queryWarn("database_sizes", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var db string
		var size int64
		if rows.Scan(&db, &size) == nil {
			ch <- prometheus.MustNewConstMetric(c.dbSize, prometheus.GaugeValue, float64(size), db)
		}
	}
}

func (c *Collector) collectWraparound(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `SELECT datname, age(datfrozenxid) FROM pg_database WHERE datistemplate = false`)
	if err != nil {
		c.queryWarn("wraparound", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var db string
		var age int64
		if rows.Scan(&db, &age) == nil {
			ch <- prometheus.MustNewConstMetric(c.wrapXIDAge, prometheus.GaugeValue, float64(age), db)
		}
	}

	var maxAge int64
	if c.pool.QueryRow(ctx, `SELECT setting::bigint FROM pg_settings WHERE name = 'autovacuum_freeze_max_age'`).Scan(&maxAge) == nil {
		ch <- prometheus.MustNewConstMetric(c.wrapMaxAge, prometheus.GaugeValue, float64(maxAge))
	}
}

func (c *Collector) collectTxAge(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `SELECT datname, usename, max(EXTRACT(EPOCH FROM (now() - xact_start))) FROM pg_stat_activity WHERE xact_start IS NOT NULL AND backend_type = 'client backend' GROUP BY datname, usename ORDER BY 3 DESC LIMIT 5`)
	if err != nil {
		c.queryWarn("tx_age", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var db, user string
		var age float64
		if rows.Scan(&db, &user, &age) == nil {
			ch <- prometheus.MustNewConstMetric(c.txAge, prometheus.GaugeValue, age, db, user)
		}
	}
}

// collectWaitEvents samples pg_stat_activity for wait event distribution (ASH-style).
// NULL wait_event => backend is on-CPU; we label it 'CPU'/'Running' so it's visible.
// Internal bg workers (bgwriter, checkpointer, walwriter, startup, launchers) are excluded —
// they're always waiting on their own internal events and add noise.
// application_name is normalized by first '-' segment (e.g. "backend-worker-1" → "backend").
func (c *Collector) collectWaitEvents(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `SELECT
		backend_type,
		COALESCE(datname, ''),
		COALESCE((string_to_array(NULLIF(application_name, ''), '-'))[1], 'unknown'),
		COALESCE(wait_event_type, 'CPU'),
		COALESCE(wait_event, 'Running'),
		COALESCE(state, 'unknown'),
		count(*)
	FROM pg_stat_activity
	WHERE backend_type IN ('client backend', 'parallel worker', 'autovacuum worker',
		'walsender', 'walreceiver', 'background worker', 'logical replication worker')
	GROUP BY 1, 2, 3, 4, 5, 6`)
	if err != nil {
		c.queryWarn("wait_events", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var backendType, datname, app, weType, we, state string
		var count int64
		if rows.Scan(&backendType, &datname, &app, &weType, &we, &state, &count) == nil {
			ch <- prometheus.MustNewConstMetric(c.waitEvents, prometheus.GaugeValue, float64(count),
				backendType, datname, app, weType, we, state)
		}
	}
}
