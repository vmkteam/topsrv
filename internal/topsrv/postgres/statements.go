package postgres

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	topStatementsN = 20 // top-N per dimension (time, calls, blks_read) for metrics
	topMetaN       = 30 // top-N per dimension for query meta push — wider than metrics to capture queries mercating on the top-N boundary
)

// queryDurationBuckets — histogram buckets for per-query execution time (seconds).
// Covers range from 0.1ms (fast PK lookup) to 10s (heavy analytics / lock wait).
var queryDurationBuckets = []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10}

// QueryMeta holds full query text metadata for push to gatesrv.
type QueryMeta struct {
	QueryID         string `json:"queryid"`
	Database        string `json:"database"`
	Query           string `json:"query"`
	ApplicationName string `json:"application_name,omitempty"`
}

// stmtPrev stores previous pg_stat_statements values for delta computation.
type stmtPrev struct {
	calls        int64
	totalTime    float64 // milliseconds (as reported by PG)
	rows         int64
	blksHit      int64
	blksRead     int64
	blksDirtied  int64
	blkReadTime  float64
	blkWriteTime float64
	tempRead     int64
	tempWritten  int64
	walBytes     int64
	minTime      float64 // cumulative min_exec_time in ms (for outlier-aware histogram)
	maxTime      float64 // cumulative max_exec_time in ms
}

// stmtCurrent holds current snapshot + computed delta for a single pg_stat_statements entry.
type stmtCurrent struct {
	key      string // "dbid:queryid"
	queryID  string
	query    string
	database string
	cur      stmtPrev
	// deltas (current - previous); negative means reset, skip
	deltaTime        float64
	deltaCalls       int64
	deltaBlksRead    int64 // shared_blks_read delta — top by read-heavy
	deltaBlksDirtied int64 // shared_blks_dirtied delta — top by write-heavy (DML pressure)
	deltaWalBytes    int64 // wal_bytes delta — top by WAL generation (replication/archive pressure); 0 if wal_bytes unavailable
}

func newHistBuckets() map[float64]uint64 {
	m := make(map[float64]uint64, len(queryDurationBuckets))
	for _, b := range queryDurationBuckets {
		m[b] = 0
	}
	return m
}

func (c *Collector) collectStatements(ctx context.Context, ch chan<- prometheus.Metric) {
	// appName mapping is maintained by a background ticker (startAppNamesSampler).

	// Extension absent in the current database (or pre-1.8) — emit nothing
	// rather than fire a query that will 42P01/42703 every scrape.
	if c.statementsTimeCol == "" {
		return
	}

	// PG17 (pg_stat_statements 1.11) renamed blk_read_time → shared_blk_read_time, blk_write_time → shared_blk_write_time
	blkReadCol, blkWriteCol := "blk_read_time", "blk_write_time"
	if c.versionNum >= versionPG17 {
		blkReadCol, blkWriteCol = "shared_blk_read_time", "shared_blk_write_time"
	}

	r := strings.NewReplacer(
		"{time_col}", c.statementsTimeCol,
		"{blk_read_col}", blkReadCol,
		"{blk_write_col}", blkWriteCol,
	)

	walBytesCol := ""
	if c.hasWalBytes {
		walBytesCol = `, sum(s.wal_bytes)`
	}

	// Exclude nested statements executed from functions/procedures (PG14+).
	// Without this, counters double-count: outer CALL and inner SELECT both charged.
	toplevelFilter := ""
	if c.hasToplevel {
		toplevelFilter = " AND s.toplevel"
	}

	// Single query: read ALL entries from pg_stat_statements (no LIMIT).
	// GROUP BY (queryid, dbid) aggregates across userids.
	// min/max_exec_time are cumulative — we use them to detect new outliers between scrapes.
	q := r.Replace(`SELECT s.dbid::text || ':' || s.queryid::text,
		s.queryid::text, left(min(s.query), 100), d.datname,
		sum(s.calls), sum(s.{time_col}), sum(s.rows),
		sum(s.shared_blks_hit), sum(s.shared_blks_read), sum(s.shared_blks_dirtied),
		sum(s.{blk_read_col}), sum(s.{blk_write_col}),
		sum(s.temp_blks_read), sum(s.temp_blks_written),
		min(s.min_exec_time), max(s.max_exec_time)` + walBytesCol + `
	FROM pg_stat_statements s
		JOIN pg_database d ON d.oid = s.dbid
	WHERE s.userid != 0` + toplevelFilter + `
	GROUP BY s.dbid, s.queryid, d.datname`)
	rows, err := c.pool.Query(ctx, q)
	if err != nil {
		c.queryWarn("pg_stat_statements", err)
		return
	}
	defer rows.Close()

	all := c.scanStatements(rows)

	if c.histCount > 0 {
		ch <- prometheus.MustNewConstHistogram(c.queryDuration, c.histCount, c.histSum, c.histBuckets)
	}

	topMetrics := c.selectTopStatements(all, topStatementsN)
	for _, sc := range all {
		if topMetrics[sc.key] {
			c.emitStatementMetrics(ch, sc)
		}
	}

	topMeta := c.selectTopStatements(all, topMetaN)
	c.collectQueryMeta(ctx, topMeta)
}

// scanStatements reads all pg_stat_statements rows, computes deltas against previous snapshot,
// feeds histogram buckets, and returns current entries with metadata.
func (c *Collector) scanStatements(rows interface {
	Next() bool
	Scan(...any) error
},
) []stmtCurrent {
	var all []stmtCurrent
	seen := make(map[string]struct{}, len(c.prevStmts))

	for rows.Next() {
		var sc stmtCurrent
		scanArgs := []any{&sc.key, &sc.queryID, &sc.query, &sc.database,
			&sc.cur.calls, &sc.cur.totalTime, &sc.cur.rows,
			&sc.cur.blksHit, &sc.cur.blksRead, &sc.cur.blksDirtied,
			&sc.cur.blkReadTime, &sc.cur.blkWriteTime,
			&sc.cur.tempRead, &sc.cur.tempWritten,
			&sc.cur.minTime, &sc.cur.maxTime}
		if c.hasWalBytes {
			scanArgs = append(scanArgs, &sc.cur.walBytes)
		}
		if err := rows.Scan(scanArgs...); err != nil {
			continue
		}

		seen[sc.key] = struct{}{}

		if prev, ok := c.prevStmts[sc.key]; ok {
			sc.deltaCalls = sc.cur.calls - prev.calls
			sc.deltaTime = sc.cur.totalTime - prev.totalTime
			sc.deltaBlksRead = sc.cur.blksRead - prev.blksRead
			sc.deltaBlksDirtied = sc.cur.blksDirtied - prev.blksDirtied
			sc.deltaWalBytes = sc.cur.walBytes - prev.walBytes

			if sc.deltaCalls > 0 && sc.deltaTime >= 0 {
				c.feedHistogram(sc.cur, prev, sc.deltaCalls, sc.deltaTime)
			}
		}

		c.prevStmts[sc.key] = sc.cur
		all = append(all, sc)
	}

	for key := range c.prevStmts {
		if _, ok := seen[key]; !ok {
			delete(c.prevStmts, key)
		}
	}

	return all
}

// feedHistogram distributes deltaCalls into histogram buckets with outlier awareness.
// When cur.max > prev.max a new slow call happened this scrape — place 1 call at cur.max.
// Same for new min. Remaining calls are placed at an "adjusted mean" so sum-of-times is preserved.
// This gives honest P99 without relying on guessing a distribution from cumulative stats.
func (c *Collector) feedHistogram(cur stmtPrev, prev stmtPrev, deltaCalls int64, deltaTime float64) {
	remainingCalls := deltaCalls
	remainingTime := deltaTime

	if cur.maxTime > prev.maxTime && remainingCalls > 1 {
		c.addToBuckets(cur.maxTime * msToSec)
		remainingCalls--
		remainingTime -= cur.maxTime
	}
	if cur.minTime > 0 && cur.minTime < prev.minTime && remainingCalls > 1 {
		c.addToBuckets(cur.minTime * msToSec)
		remainingCalls--
		remainingTime -= cur.minTime
	}

	if remainingCalls > 0 {
		meanSec := (remainingTime * msToSec) / float64(remainingCalls)
		if meanSec < 0 {
			meanSec = 0
		}
		for _, le := range queryDurationBuckets {
			if meanSec <= le {
				c.histBuckets[le] += uint64(remainingCalls)
			}
		}
	}

	c.histCount += uint64(deltaCalls)
	c.histSum += deltaTime * msToSec
}

// addToBuckets increments cumulative bucket counts for a single call with the given sec latency.
func (c *Collector) addToBuckets(sec float64) {
	for _, le := range queryDurationBuckets {
		if sec <= le {
			c.histBuckets[le]++
		}
	}
}

// collectQueryMeta fetches full query texts for top queries and stores them for push to gatesrv.
func (c *Collector) collectQueryMeta(ctx context.Context, topSet map[string]bool) {
	if len(topSet) == 0 {
		return
	}

	toplevelFilter := ""
	if c.hasToplevel {
		toplevelFilter = " AND s.toplevel"
	}

	q := `SELECT s.dbid::text || ':' || s.queryid::text,
			s.queryid::text, d.datname, s.query
		FROM pg_stat_statements s
			JOIN pg_database d ON d.oid = s.dbid
		WHERE s.userid != 0` + toplevelFilter + `
		ORDER BY s.` + c.statementsTimeCol + ` DESC`
	rows, err := c.pool.Query(ctx, q)
	if err != nil {
		return
	}
	defer rows.Close()

	seen := make(map[string]bool, len(topSet))
	var meta []QueryMeta
	for rows.Next() {
		var key, qid, db, query string
		if rows.Scan(&key, &qid, &db, &query) != nil {
			continue
		}
		if !topSet[key] && !seen[qid] {
			continue
		}
		if seen[qid] {
			continue
		}
		seen[qid] = true
		meta = append(meta, QueryMeta{QueryID: qid, Database: db, Query: query, ApplicationName: c.appNamesByQueryID(qid)})
	}

	c.queryMetaMu.Lock()
	c.queryMeta = meta
	c.queryMetaMu.Unlock()
}

// sampleAppNames samples pg_stat_activity to accumulate queryid → application_name mapping.
// PG14+ exposes query_id in pg_stat_activity when compute_query_id is enabled (default `auto` when pg_stat_statements is loaded).
// Errors here are transient (pool disconnects, compute_query_id temporarily off) — log rate-limited and keep retrying.
func (c *Collector) sampleAppNames(ctx context.Context) {
	rows, err := c.pool.Query(ctx,
		`SELECT query_id, (string_to_array(application_name, '-'))[1] FROM pg_stat_activity WHERE query_id IS NOT NULL AND query_id != 0 AND application_name != ''`)
	if err != nil {
		c.appNamesMu.Lock()
		if time.Since(c.appSampleLastErr) > time.Minute {
			c.appSampleLastErr = time.Now()
			c.Error(ctx, "postgres: app name sampling failed (will retry)", "error", err)
		}
		c.appNamesMu.Unlock()
		return
	}
	defer rows.Close()

	c.appNamesMu.Lock()
	defer c.appNamesMu.Unlock()
	for rows.Next() {
		var qid int64
		var app string
		if rows.Scan(&qid, &app) != nil {
			continue
		}
		if c.appNames[qid] == nil {
			c.appNames[qid] = make(map[string]bool)
		}
		c.appNames[qid][app] = true
	}
}

// startAppNamesSampler runs sampleAppNames on an independent ticker so short-lived queries
// get captured between Prometheus scrapes. Cancelled via Close().
func (c *Collector) startAppNamesSampler(interval time.Duration) {
	var ctx context.Context
	ctx, c.appSampleCancel = context.WithCancel(context.Background())
	c.appSampleDone = make(chan struct{})
	go func() {
		defer close(c.appSampleDone)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sampleCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				c.sampleAppNames(sampleCtx)
				cancel()
			}
		}
	}()
}

// appNamesByQueryID returns comma-separated application names for a queryid string, or empty.
func (c *Collector) appNamesByQueryID(queryID string) string {
	qid, err := strconv.ParseInt(queryID, 10, 64)
	if err != nil {
		return ""
	}
	c.appNamesMu.RLock()
	apps := c.appNames[qid]
	names := make([]string, 0, len(apps))
	for name := range apps {
		names = append(names, name)
	}
	c.appNamesMu.RUnlock()
	if len(names) == 0 {
		return ""
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

func (c *Collector) emitStatementMetrics(ch chan<- prometheus.Metric, sc stmtCurrent) {
	cur := sc.cur
	ch <- prometheus.MustNewConstMetric(c.queryTime, prometheus.CounterValue, cur.totalTime*msToSec, sc.queryID, sc.query, sc.database)
	ch <- prometheus.MustNewConstMetric(c.queryCalls, prometheus.CounterValue, float64(cur.calls), sc.queryID, sc.query, sc.database)
	ch <- prometheus.MustNewConstMetric(c.queryRows, prometheus.CounterValue, float64(cur.rows), sc.queryID, sc.query, sc.database)
	ch <- prometheus.MustNewConstMetric(c.queryBlksHit, prometheus.CounterValue, float64(cur.blksHit), sc.queryID, sc.query, sc.database)
	ch <- prometheus.MustNewConstMetric(c.queryBlksRead, prometheus.CounterValue, float64(cur.blksRead), sc.queryID, sc.query, sc.database)
	ch <- prometheus.MustNewConstMetric(c.queryBlksDirtied, prometheus.CounterValue, float64(cur.blksDirtied), sc.queryID, sc.query, sc.database)
	ch <- prometheus.MustNewConstMetric(c.queryBlkReadTime, prometheus.CounterValue, cur.blkReadTime*msToSec, sc.queryID, sc.query, sc.database)
	ch <- prometheus.MustNewConstMetric(c.queryBlkWriteTime, prometheus.CounterValue, cur.blkWriteTime*msToSec, sc.queryID, sc.query, sc.database)
	ch <- prometheus.MustNewConstMetric(c.queryTempRead, prometheus.CounterValue, float64(cur.tempRead), sc.queryID, sc.query, sc.database)
	ch <- prometheus.MustNewConstMetric(c.queryTempWritten, prometheus.CounterValue, float64(cur.tempWritten), sc.queryID, sc.query, sc.database)
	if c.hasWalBytes {
		ch <- prometheus.MustNewConstMetric(c.queryWalBytes, prometheus.CounterValue, float64(cur.walBytes), sc.queryID, sc.query, sc.database)
	}
}

// selectTopStatements returns a set of keys for the top-N statements by delta time, delta calls, and delta blks_read.
// On the first scrape (no previous snapshot), falls back to cumulative values.
func (c *Collector) selectTopStatements(all []stmtCurrent, topN int) map[string]bool {
	result := make(map[string]bool, topN*5)

	addTopN := func(lessFunc func(a, b stmtCurrent) int) {
		sorted := make([]stmtCurrent, len(all))
		copy(sorted, all)
		slices.SortFunc(sorted, lessFunc)
		for i := range min(topN, len(sorted)) {
			result[sorted[i].key] = true
		}
	}

	addTopN(func(a, b stmtCurrent) int { return cmp.Compare(b.deltaTime, a.deltaTime) })
	addTopN(func(a, b stmtCurrent) int { return cmp.Compare(b.deltaCalls, a.deltaCalls) })
	addTopN(func(a, b stmtCurrent) int { return cmp.Compare(b.deltaBlksRead, a.deltaBlksRead) })
	addTopN(func(a, b stmtCurrent) int { return cmp.Compare(b.deltaBlksDirtied, a.deltaBlksDirtied) })
	if c.hasWalBytes {
		addTopN(func(a, b stmtCurrent) int { return cmp.Compare(b.deltaWalBytes, a.deltaWalBytes) })
	}

	return result
}

// QueryMeta returns the latest collected query metadata (thread-safe).
func (c *Collector) QueryMeta() []QueryMeta {
	c.queryMetaMu.RLock()
	defer c.queryMetaMu.RUnlock()
	return c.queryMeta
}
