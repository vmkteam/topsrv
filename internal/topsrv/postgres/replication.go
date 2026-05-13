package postgres

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

func (c *Collector) collectReplication(ctx context.Context, ch chan<- prometheus.Metric) {
	// write_lag = time for write to reach replica; flush_lag = +fsync on replica; replay_lag = +apply.
	// Each stage is cumulative: replay_lag >= flush_lag >= write_lag. Splitting pinpoints bottleneck.
	rows, err := c.pool.Query(ctx, `SELECT coalesce(client_addr::text, 'local'), state, sync_state,
		coalesce(pg_wal_lsn_diff(sent_lsn, replay_lsn), 0),
		coalesce(extract(epoch from write_lag), 0),
		coalesce(extract(epoch from flush_lag), 0),
		coalesce(extract(epoch from replay_lag), 0)
	FROM pg_stat_replication`)
	if err != nil {
		c.queryWarn("replication", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var addr, state, syncState string
		var lagBytes, writeLag, flushLag, replayLag float64
		if rows.Scan(&addr, &state, &syncState, &lagBytes, &writeLag, &flushLag, &replayLag) != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.replLagBytes, prometheus.GaugeValue, lagBytes, addr)
		ch <- prometheus.MustNewConstMetric(c.replLagSeconds, prometheus.GaugeValue, writeLag, addr, "write")
		ch <- prometheus.MustNewConstMetric(c.replLagSeconds, prometheus.GaugeValue, flushLag, addr, "flush")
		ch <- prometheus.MustNewConstMetric(c.replLagSeconds, prometheus.GaugeValue, replayLag, addr, "replay")
		streaming := 0.0
		if state == "streaming" {
			streaming = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.replStreaming, prometheus.GaugeValue, streaming, addr)
		if syncState != "" {
			ch <- prometheus.MustNewConstMetric(c.replSyncState, prometheus.GaugeValue, 1, addr, syncState)
		}
	}
}

func (c *Collector) collectReplicationSlots(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `SELECT slot_name, coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), 0) FROM pg_replication_slots WHERE active`)
	if err != nil {
		c.queryWarn("replication_slots", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var slot string
		var retained float64
		if rows.Scan(&slot, &retained) == nil {
			ch <- prometheus.MustNewConstMetric(c.replSlotBytes, prometheus.GaugeValue, retained, slot)
		}
	}
}

func (c *Collector) collectWAL(ctx context.Context, ch chan<- prometheus.Metric) {
	var walBytes float64
	if c.pool.QueryRow(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')`).Scan(&walBytes) == nil {
		ch <- prometheus.MustNewConstMetric(c.walBytes, prometheus.CounterValue, walBytes)
	}

	var walFiles int64
	if c.pool.QueryRow(ctx, `SELECT count(*) FROM pg_ls_waldir()`).Scan(&walFiles) == nil {
		ch <- prometheus.MustNewConstMetric(c.walFiles, prometheus.GaugeValue, float64(walFiles))
	}
}

// collectStatWAL emits pg_stat_wal metrics (PG14+). wal_bytes is intentionally
// skipped — it has different semantics than topsrv_pg_wal_bytes (LSN position
// from pg_current_wal_lsn). PG18 removed wal_write_time/wal_sync_time from
// pg_stat_wal (the timings moved to pg_stat_io); on those versions the
// wal_io_time metric is skipped instead of breaking the whole query.
func (c *Collector) collectStatWAL(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.versionNum < versionPG14 {
		return
	}
	var records, fpi, buffersFull int64
	var writeTime, syncTime float64
	q := `SELECT wal_records, wal_fpi, wal_buffers_full`
	scanArgs := []any{&records, &fpi, &buffersFull}
	if c.hasWalIOTime {
		q += `, wal_write_time, wal_sync_time`
		scanArgs = append(scanArgs, &writeTime, &syncTime)
	}
	q += ` FROM pg_stat_wal`
	if err := c.pool.QueryRow(ctx, q).Scan(scanArgs...); err != nil {
		c.queryWarn("stat_wal", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.statWalRecords, prometheus.CounterValue, float64(records))
	ch <- prometheus.MustNewConstMetric(c.statWalFpi, prometheus.CounterValue, float64(fpi))
	ch <- prometheus.MustNewConstMetric(c.statWalBuffersFull, prometheus.CounterValue, float64(buffersFull))
	if c.hasWalIOTime {
		ch <- prometheus.MustNewConstMetric(c.statWalIoTime, prometheus.CounterValue, writeTime*msToSec, "write")
		ch <- prometheus.MustNewConstMetric(c.statWalIoTime, prometheus.CounterValue, syncTime*msToSec, "sync")
	}
}

// collectArchiver emits pg_stat_archiver metrics. NULL last_*_time => metric is not emitted
// (no event yet; emitting 0 would look like "happened at epoch").
func (c *Collector) collectArchiver(ctx context.Context, ch chan<- prometheus.Metric) {
	if !c.archiveEnabled {
		return
	}
	var archived, failed int64
	var lastArchivedTS, lastFailedTS *float64
	err := c.pool.QueryRow(ctx, `SELECT archived_count, failed_count,
		EXTRACT(EPOCH FROM last_archived_time),
		EXTRACT(EPOCH FROM last_failed_time)
		FROM pg_stat_archiver`).
		Scan(&archived, &failed, &lastArchivedTS, &lastFailedTS)
	if err != nil {
		c.queryWarn("archiver", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.archiverTotal, prometheus.CounterValue, float64(archived), "archived")
	ch <- prometheus.MustNewConstMetric(c.archiverTotal, prometheus.CounterValue, float64(failed), "failed")
	if lastArchivedTS != nil {
		ch <- prometheus.MustNewConstMetric(c.archiverLastTime, prometheus.GaugeValue, *lastArchivedTS, "archived")
	}
	if lastFailedTS != nil {
		ch <- prometheus.MustNewConstMetric(c.archiverLastTime, prometheus.GaugeValue, *lastFailedTS, "failed")
	}
}
