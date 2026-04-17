package postgres

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

func (c *Collector) collectTables(ctx context.Context, ch chan<- prometheus.Metric) {
	// Two-step approach: cheap relpages sort over all tables, then pg_total_relation_size only for top 50.
	// last_vacuum/analyze use GREATEST(manual, auto) — we care when the table was last maintained, not who did it.
	rows, err := c.pool.Query(ctx, `WITH top AS (SELECT relid FROM pg_stat_user_tables s JOIN pg_class c ON c.oid = s.relid ORDER BY c.relpages DESC LIMIT 50)
		SELECT s.schemaname, s.relname,
			s.seq_scan, s.seq_tup_read, coalesce(s.idx_scan, 0),
			s.n_tup_ins, s.n_tup_upd, s.n_tup_del,
			s.n_live_tup, s.n_dead_tup,
			pg_total_relation_size(s.relid) AS total_size,
			s.autovacuum_count,
			EXTRACT(EPOCH FROM GREATEST(s.last_vacuum, s.last_autovacuum)),
			EXTRACT(EPOCH FROM GREATEST(s.last_analyze, s.last_autoanalyze)),
			s.n_mod_since_analyze
		FROM pg_stat_user_tables s JOIN top t ON t.relid = s.relid
		ORDER BY total_size DESC`)
	if err != nil {
		c.queryWarn("tables", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var schema, table string
		var seqScan, seqRead, idxScan, ins, upd, del, live, dead, size, avCount, modSinceAnalyze int64
		var lastVacuumTS, lastAnalyzeTS *float64
		if rows.Scan(&schema, &table, &seqScan, &seqRead, &idxScan, &ins, &upd, &del, &live, &dead, &size, &avCount,
			&lastVacuumTS, &lastAnalyzeTS, &modSinceAnalyze) != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.tableSize, prometheus.GaugeValue, float64(size), c.database, schema, table)
		ch <- prometheus.MustNewConstMetric(c.tableSeqScan, prometheus.CounterValue, float64(seqScan), c.database, schema, table)
		ch <- prometheus.MustNewConstMetric(c.tableSeqRead, prometheus.CounterValue, float64(seqRead), c.database, schema, table)
		ch <- prometheus.MustNewConstMetric(c.tableIdxScan, prometheus.CounterValue, float64(idxScan), c.database, schema, table)
		ch <- prometheus.MustNewConstMetric(c.tableTup, prometheus.CounterValue, float64(ins), c.database, schema, table, "insert")
		ch <- prometheus.MustNewConstMetric(c.tableTup, prometheus.CounterValue, float64(upd), c.database, schema, table, "update")
		ch <- prometheus.MustNewConstMetric(c.tableTup, prometheus.CounterValue, float64(del), c.database, schema, table, "delete")
		ch <- prometheus.MustNewConstMetric(c.tableTuples, prometheus.GaugeValue, float64(live), c.database, schema, table, "live")
		ch <- prometheus.MustNewConstMetric(c.tableTuples, prometheus.GaugeValue, float64(dead), c.database, schema, table, "dead")
		ch <- prometheus.MustNewConstMetric(c.tableAutoVacCount, prometheus.CounterValue, float64(avCount), c.database, schema, table)
		ch <- prometheus.MustNewConstMetric(c.tableModSinceAnz, prometheus.GaugeValue, float64(modSinceAnalyze), c.database, schema, table)
		if lastVacuumTS != nil {
			ch <- prometheus.MustNewConstMetric(c.tableLastMaint, prometheus.GaugeValue, *lastVacuumTS, c.database, schema, table, "vacuum")
		}
		if lastAnalyzeTS != nil {
			ch <- prometheus.MustNewConstMetric(c.tableLastMaint, prometheus.GaugeValue, *lastAnalyzeTS, c.database, schema, table, "analyze")
		}
	}
}

// collectIndexes emits index stats (scans + size) for indexes on top-50 tables.
// Only scans (for unused detection) and size (for footprint) — tup_read skipped as low-value.
func (c *Collector) collectIndexes(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `WITH top AS (SELECT relid FROM pg_stat_user_tables s JOIN pg_class c ON c.oid = s.relid ORDER BY c.relpages DESC LIMIT 50)
		SELECT i.schemaname, i.relname, i.indexrelname,
			coalesce(i.idx_scan, 0),
			pg_relation_size(i.indexrelid)
		FROM pg_stat_user_indexes i
		JOIN top t ON t.relid = i.relid`)
	if err != nil {
		c.queryWarn("indexes", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var schema, table, index string
		var scans, size int64
		if rows.Scan(&schema, &table, &index, &scans, &size) != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.indexScans, prometheus.CounterValue, float64(scans), c.database, schema, table, index)
		ch <- prometheus.MustNewConstMetric(c.indexSize, prometheus.GaugeValue, float64(size), c.database, schema, table, index)
	}
}
