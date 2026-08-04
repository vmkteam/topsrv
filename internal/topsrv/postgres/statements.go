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
	topStatementsN = 20 // top-N per dimension for metrics — dimensions listed on selectTopStatements
	topMetaN       = 30 // top-N per dimension for query meta push — wider than metrics to capture queries hovering on the top-N boundary
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

	// One statements phase at a time: prevStmts and histBuckets are plain maps, and
	// a concurrent map write is a fatal error that instrumentedCollector's recover()
	// cannot catch. Skip rather than wait — the loser would recompute deltas over a
	// near-zero window, which produces no top-set and wipes the debounce state.
	if !c.stmtMu.TryLock() {
		return
	}
	defer c.stmtMu.Unlock()

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

	topMetrics, topMeta := c.selectTopStatements(all)

	emit := c.debounceTop(topMetrics)
	for _, sc := range all {
		if emit[sc.key] {
			c.emitStatementMetrics(ch, sc)
		}
	}

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

	now := time.Now()
	c.appNamesMu.Lock()
	defer c.appNamesMu.Unlock()
	for rows.Next() {
		var qid int64
		var app string
		if rows.Scan(&qid, &app) != nil {
			continue
		}
		if c.appNames[qid] == nil {
			c.appNames[qid] = make(map[string]time.Time)
		}
		c.appNames[qid][app] = now
	}
}

// pruneAppNames drops (queryid, application_name) pairs older than
// appNamesTTL. Runs on its own ticker (appNamesSweepPeriod) so a quiet
// queryid can't pin app_names in memory forever.
func (c *Collector) pruneAppNames(now time.Time) {
	cutoff := now.Add(-appNamesTTL)
	c.appNamesMu.Lock()
	defer c.appNamesMu.Unlock()
	for qid, apps := range c.appNames {
		for app, seen := range apps {
			if seen.Before(cutoff) {
				delete(apps, app)
			}
		}
		if len(apps) == 0 {
			delete(c.appNames, qid)
		}
	}
}

// startAppNamesSampler runs sampleAppNames on an independent ticker so short-lived queries
// get captured between Prometheus scrapes, and a slower ticker prunes
// (queryid, application_name) pairs whose lastSeen is older than appNamesTTL.
// Cancelled via Close().
func (c *Collector) startAppNamesSampler(interval time.Duration) {
	var ctx context.Context
	ctx, c.appSampleCancel = context.WithCancel(context.Background())
	c.appSampleDone = make(chan struct{})
	go func() {
		defer close(c.appSampleDone)
		sampleT := time.NewTicker(interval)
		defer sampleT.Stop()
		pruneT := time.NewTicker(appNamesSweepPeriod)
		defer pruneT.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sampleT.C:
				sampleCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				c.sampleAppNames(sampleCtx)
				cancel()
			case <-pruneT.C:
				c.pruneAppNames(time.Now())
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

// debounceTop returns the subset of top that was also in the previous scrape's
// top-set and remembers top for the next scrape. Emitting a statement only after
// it holds a top spot on two consecutive scrapes keeps one-off statements
// (migrations, tests, ad-hoc queries) out of the TSDB: every unique queryid
// creates one series per topsrv_pg_query_* metric in the per-day index, and
// top-set flapping multiplied that ~10x against the live series count.
func (c *Collector) debounceTop(top map[string]bool) map[string]bool {
	emit := make(map[string]bool, len(top))
	for key := range top {
		if c.prevTopKeys[key] {
			emit[key] = true
		}
	}
	c.prevTopKeys = top
	return emit
}

// selectTopStatements ranks statements by each dimension — delta time, delta calls,
// delta blks_read, delta blks_dirtied, delta wal_bytes — and returns the union of the
// per-dimension leaders in two widths: topStatementsN for metrics and topMetaN for the
// meta push. The metrics set is a subset of the meta set, so one ranking fills both.
// Entries with a non-positive delta never qualify: among all-zero deltas (first
// scrape, idle database, stats reset) sort order is arbitrary and used to pull
// random queryids into the top-set.
func (c *Collector) selectTopStatements(all []stmtCurrent) (metrics, meta map[string]bool) {
	metrics = make(map[string]bool, topStatementsN*5)
	meta = make(map[string]bool, topMetaN*5)

	// Rank an index slice rather than copies of stmtCurrent: the struct is ~200 bytes,
	// and sorting it five times per scrape allocated megabytes of short-lived garbage.
	idx := make([]int32, len(all))

	addTopN := func(value func(sc *stmtCurrent) float64) {
		for i := range idx {
			idx[i] = int32(i)
		}
		slices.SortFunc(idx, func(a, b int32) int { return cmp.Compare(value(&all[b]), value(&all[a])) })
		for rank := range min(topMetaN, len(idx)) {
			sc := &all[idx[rank]]
			if value(sc) <= 0 {
				break
			}
			meta[sc.key] = true
			if rank < topStatementsN {
				metrics[sc.key] = true
			}
		}
	}

	addTopN(func(sc *stmtCurrent) float64 { return sc.deltaTime })
	addTopN(func(sc *stmtCurrent) float64 { return float64(sc.deltaCalls) })
	addTopN(func(sc *stmtCurrent) float64 { return float64(sc.deltaBlksRead) })
	addTopN(func(sc *stmtCurrent) float64 { return float64(sc.deltaBlksDirtied) })
	if c.hasWalBytes {
		addTopN(func(sc *stmtCurrent) float64 { return float64(sc.deltaWalBytes) })
	}

	return metrics, meta
}

// QueryMeta returns the latest collected query metadata (thread-safe).
func (c *Collector) QueryMeta() []QueryMeta {
	c.queryMetaMu.RLock()
	defer c.queryMetaMu.RUnlock()
	return c.queryMeta
}
