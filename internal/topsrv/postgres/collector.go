// Package postgres collects PostgreSQL metrics via SQL queries.
// Minimum supported version: PG15. Extensions: pg_stat_statements (optional).
package postgres

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

const (
	collectTimeout         = 10 * time.Second
	versionPG14            = 140000 // pg_stat_wal introduced
	versionPG17            = 170000 // pg_stat_checkpointer, pg_stat_wal.stats_reset introduced
	versionPG18            = 180000 // pg_stat_wal.wal_write_time/wal_sync_time removed (moved into pg_stat_io)
	settingRefreshInterval = time.Minute

	// appNamesTTL bounds how long a (queryid, application_name) pair stays
	// in memory after it was last seen in pg_stat_activity. Long enough
	// (1h) that a query absent from a few scrapes still has its caller
	// resolved; short enough that one-shot pids/uuids don't accumulate.
	appNamesTTL         = time.Hour
	appNamesSweepPeriod = 5 * time.Minute

	// Relation names probed by relHasColumn. Kept as named constants so a
	// rename or typo can't silently disable feature detection.
	relPgStatStmts    = "pg_stat_statements"
	relPgStatWal      = "pg_stat_wal"
	relPgStatActivity = "pg_stat_activity"
)

// Collector collects PostgreSQL metrics via SQL queries.
type Collector struct {
	embedlog.Logger

	cfg                *pgxpool.Config // saved for lazy pool creation on first Collect
	initMu             sync.Mutex      // guards lazy pool creation + one-shot feature detection
	initDone           bool            // feature detection done (version, pg_stat_statements, archive_mode, ...); gates sampler start too
	ensureReadyLastErr time.Time       // rate-limit ensureReady error logs to 1/minute
	pool               *pgxpool.Pool   // nil until first successful ensureReady
	versionNum         int             // server_version_num, cached
	database           string          // current_database() — scope for per-DB views (pg_stat_user_tables/indexes)
	statementsTimeCol  string          // "total_exec_time" (PG13+); empty iff pg_stat_statements unavailable
	hasWalBytes        bool            // pg_stat_statements has wal_bytes column
	hasToplevel        bool            // pg_stat_statements has toplevel column (PG14+)
	hasWalIOTime       bool            // pg_stat_wal has wal_write_time/wal_sync_time (PG14..PG17)
	archiveEnabled     bool            // archive_mode is 'on' or 'always'
	hasActivityQID     bool            // pg_stat_activity.query_id column present (PG14+)

	// query metadata for push to gatesrv (full query texts + database names)
	queryMetaMu sync.RWMutex
	queryMeta   []QueryMeta

	// queryid → application_name → last-seen time. Sampled by a background
	// ticker independent of Prometheus scrape to catch short-lived queries.
	// Entries older than appNamesTTL are pruned by a separate sweeper so a
	// rotating app_name (pid/uuid suffix per process restart) does not turn
	// the map into a slow memory leak.
	appNamesMu       sync.RWMutex
	appNames         map[int64]map[string]time.Time
	appSampleLastErr time.Time // rate-limit sampler error logs to 1/minute
	appSampleCancel  context.CancelFunc
	appSampleDone    chan struct{}

	// histogram state — cumulative counters for query duration distribution
	prevStmts   map[string]stmtPrev
	histCount   uint64
	histSum     float64
	histBuckets map[float64]uint64

	up *prometheus.Desc
	// connections
	connections       *prometheus.Desc
	connectionsByAddr *prometheus.Desc
	connectionsByApp  *prometheus.Desc
	maxConns          *prometheus.Desc
	// transactions
	xact      *prometheus.Desc
	deadlocks *prometheus.Desc
	tempFiles *prometheus.Desc
	tempBytes *prometheus.Desc
	blks      *prometheus.Desc
	// bgwriter / checkpoints
	checkpoints    *prometheus.Desc
	checkpointTime *prometheus.Desc
	buffers        *prometheus.Desc
	// autovacuum
	avWorkers    *prometheus.Desc
	avMaxWorkers *prometheus.Desc
	// locks
	locks           *prometheus.Desc
	blockedBackends *prometheus.Desc
	lockWaitMax     *prometheus.Desc
	// wait events
	waitEvents *prometheus.Desc
	// replication
	replLagBytes   *prometheus.Desc
	replLagSeconds *prometheus.Desc
	replSlotBytes  *prometheus.Desc
	replStreaming  *prometheus.Desc
	replSyncState  *prometheus.Desc
	// database
	dbSize *prometheus.Desc
	// WAL
	walBytes           *prometheus.Desc
	walFiles           *prometheus.Desc
	statWalRecords     *prometheus.Desc
	statWalFpi         *prometheus.Desc
	statWalBuffersFull *prometheus.Desc
	statWalIoTime      *prometheus.Desc
	// wraparound
	wrapXIDAge *prometheus.Desc
	wrapMaxAge *prometheus.Desc
	// archiver
	archiverTotal    *prometheus.Desc
	archiverLastTime *prometheus.Desc
	// pg_stat_statements
	queryTime         *prometheus.Desc
	queryCalls        *prometheus.Desc
	queryRows         *prometheus.Desc
	queryBlksHit      *prometheus.Desc
	queryBlksRead     *prometheus.Desc
	queryBlksDirtied  *prometheus.Desc
	queryBlkReadTime  *prometheus.Desc
	queryBlkWriteTime *prometheus.Desc
	queryTempRead     *prometheus.Desc
	queryTempWritten  *prometheus.Desc
	queryWalBytes     *prometheus.Desc
	queryDuration     *prometheus.Desc
	// transaction age
	txAge *prometheus.Desc
	// tables
	tableSize         *prometheus.Desc
	tableSeqScan      *prometheus.Desc
	tableSeqRead      *prometheus.Desc
	tableIdxScan      *prometheus.Desc
	tableTup          *prometheus.Desc
	tableTuples       *prometheus.Desc
	tableAutoVacCount *prometheus.Desc
	tableLastMaint    *prometheus.Desc
	tableModSinceAnz  *prometheus.Desc
	// indexes
	indexScans *prometheus.Desc
	indexSize  *prometheus.Desc
	// bloat (ioguix heuristic, refreshed every bloatRefreshInterval)
	tableBloatSize   *prometheus.Desc
	tableBloatPct    *prometheus.Desc
	indexBloatSize   *prometheus.Desc
	indexBloatPct    *prometheus.Desc
	bloatMu          sync.RWMutex
	bloatLastRefresh time.Time
	bloatTables      []tableBloatEntry
	bloatIndexes     []indexBloatEntry
	// settings + stats_reset
	settingGauge        *prometheus.Desc
	statsResetGauge     *prometheus.Desc
	settingsMu          sync.Mutex
	settingsCache       map[string]float64
	settingsLastRefresh time.Time
}

// NewCollector creates a PostgreSQL metrics collector. It never performs network I/O —
// the connection pool is created lazily on first Collect(). This ensures topsrv stays
// useful when PG is temporarily unreachable at startup (e.g. boot-time ordering with
// systemd). Only a malformed DSN causes an error here.
//
// Sets application_name=topsrv so DBAs can distinguish monitoring from app traffic.
func NewCollector(logger embedlog.Logger, dsn string) (*Collector, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 3 // 1 for scrape queries + 1 for concurrent Ping + 1 for appNames ticker
	cfg.MinConns = 0
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "topsrv"

	c := &Collector{
		Logger: logger,
		cfg:    cfg,
		// statementsTimeCol stays "" until detectFeatures confirms pg_stat_statements
		// is present with total_exec_time (PG13+/extension 1.8+).
		appNames:      make(map[int64]map[string]time.Time),
		prevStmts:     make(map[string]stmtPrev),
		histBuckets:   newHistBuckets(),
		settingsCache: map[string]float64{},
	}
	c.initDescriptors()
	return c, nil
}

// ensureReady lazily creates the connection pool and probes server features on first call.
// Subsequent calls only Ping to detect runtime connection loss; pgxpool reconnects itself.
// Returns error if the pool cannot be created or the server is unreachable.
func (c *Collector) ensureReady(ctx context.Context) error {
	c.initMu.Lock()
	defer c.initMu.Unlock()

	if c.pool == nil {
		pool, err := pgxpool.NewWithConfig(ctx, c.cfg)
		if err != nil {
			return fmt.Errorf("connect: %w", err)
		}
		c.pool = pool
	}

	if err := c.pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}

	if !c.initDone {
		if err := c.detectFeatures(ctx); err != nil {
			return fmt.Errorf("detect features: %w", err)
		}
		c.initDone = true
	}
	return nil
}

// detectFeatures runs once after the first successful Ping: resolves version,
// switches to the largest database for per-table metrics, and probes optional
// columns (pg_stat_statements, pg_stat_activity.query_id, archive_mode).
func (c *Collector) detectFeatures(ctx context.Context) error {
	var versionStr string
	if err := c.pool.QueryRow(ctx, "SHOW server_version_num").Scan(&versionStr); err == nil {
		c.versionNum, _ = strconv.Atoi(versionStr)
		c.Print(ctx, "postgres: connected", "version", c.versionNum)
	} else {
		c.Error(ctx, "postgres: failed to detect version", "error", err)
	}

	// Auto-switch to the largest non-template database for table-level metrics.
	// On failure c.pool is left intact, so retrying detectFeatures is safe.
	newPool, err := switchToLargestDB(ctx, c.Logger, c.pool, c.cfg)
	if err != nil {
		return err
	}
	c.pool = newPool

	_ = c.pool.QueryRow(ctx, "SELECT current_database()").Scan(&c.database)

	// pg_stat_statements: probe the canonical column. relHasColumn returns
	// false both when the relation is absent (switchToLargestDB landed in a
	// DB without CREATE EXTENSION) and when it exists but is pre-1.8 (no
	// total_exec_time — pre-PG13, unsupported). statementsTimeCol == ""
	// thereafter signals "skip collectStatements" everywhere.
	if c.relHasColumn(ctx, relPgStatStmts, "total_exec_time") {
		c.statementsTimeCol = "total_exec_time"
		c.hasWalBytes = c.relHasColumn(ctx, relPgStatStmts, "wal_bytes")
		c.hasToplevel = c.relHasColumn(ctx, relPgStatStmts, "toplevel")
		c.Print(ctx, "postgres: pg_stat_statements detected", "database", c.database, "wal_bytes", c.hasWalBytes, "toplevel", c.hasToplevel)
	} else {
		c.Print(ctx, "postgres: pg_stat_statements disabled", "database", c.database, "reason", "relation or total_exec_time column missing")
	}

	// pg_stat_wal.wal_write_time / wal_sync_time removed in PG18 (moved to
	// pg_stat_io). Probe instead of version-gating — survives backports.
	if c.versionNum >= versionPG14 {
		c.hasWalIOTime = c.relHasColumn(ctx, relPgStatWal, "wal_write_time")
		if !c.hasWalIOTime {
			c.Print(ctx, "postgres: pg_stat_wal write/sync timing columns absent — wal_io_time metric will not be emitted", "version", c.versionNum)
		}
	}

	// archive_mode ('on' and 'always' both produce archiver stats).
	var archiveMode string
	if err := c.pool.QueryRow(ctx, "SHOW archive_mode").Scan(&archiveMode); err == nil {
		c.archiveEnabled = archiveMode == "on" || archiveMode == "always"
		if c.archiveEnabled {
			c.Print(ctx, "postgres: pg_stat_archiver collection enabled", "archive_mode", archiveMode)
		}
	}

	// pg_stat_activity.query_id (PG14+) — required for the app-name sampler.
	c.hasActivityQID = c.relHasColumn(ctx, relPgStatActivity, "query_id")

	if c.hasActivityQID {
		c.startAppNamesSampler(1 * time.Second)
	} else {
		c.Print(ctx, "postgres: app-name sampling disabled", "reason", "pg_stat_activity.query_id not present (PG<14)")
	}
	return nil
}

// relHasColumn reports whether the given relation has the given column. It
// uses to_regclass so a missing relation simply yields false instead of an
// SQL exception — callers can probe extensions/views that may or may not
// exist in the current database.
func (c *Collector) relHasColumn(ctx context.Context, rel, col string) bool {
	var ok int
	err := c.pool.QueryRow(ctx,
		"SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass($1) AND attname = $2",
		rel, col).Scan(&ok)
	return err == nil
}

// Name returns a human-readable collector name.
func (c *Collector) Name() string { return "postgres" }

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.allDescs() {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()

	if err := c.ensureReady(ctx); err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		// Rate-limit to 1/min so a down PG doesn't spam the log every scrape.
		c.initMu.Lock()
		if time.Since(c.ensureReadyLastErr) > time.Minute {
			c.ensureReadyLastErr = time.Now()
			c.Error(ctx, "postgres: not ready", "error", err)
		}
		c.initMu.Unlock()
		return
	}
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1)

	c.collectConnections(ctx, ch)
	c.collectTransactions(ctx, ch)
	c.collectBGWriter(ctx, ch)
	c.collectAutovacuum(ctx, ch)
	c.collectLocks(ctx, ch)
	c.collectReplication(ctx, ch)
	c.collectReplicationSlots(ctx, ch)
	c.collectDatabaseSizes(ctx, ch)
	c.collectWAL(ctx, ch)
	c.collectWraparound(ctx, ch)
	c.collectTxAge(ctx, ch)
	c.collectStatements(ctx, ch)
	c.collectTables(ctx, ch)
	c.collectArchiver(ctx, ch)
	c.collectStatWAL(ctx, ch)
	c.collectWaitEvents(ctx, ch)
	c.collectIndexes(ctx, ch)
	c.collectSettings(ctx, ch)
	c.collectStatsReset(ctx, ch)
	c.collectBloat(ctx, ch)
}

// Close stops the background sampler and closes the connection pool. Implements io.Closer.
func (c *Collector) Close() error {
	if c.appSampleCancel != nil {
		c.appSampleCancel()
		<-c.appSampleDone
	}
	if c.pool != nil {
		c.pool.Close()
		c.Print(context.Background(), "postgres: connection pool closed")
	}
	return nil
}

func (c *Collector) queryWarn(query string, err error) {
	c.Error(context.Background(), "postgres: query failed", "query", query, "error", err)
}

// switchToLargestDB reconnects to the largest non-template database if it differs from current.
// This allows table-level metrics (pg_stat_user_tables) to see application tables.
// On failure the original pool is returned untouched so the caller can retry on the next scrape.
func switchToLargestDB(ctx context.Context, logger embedlog.Logger, pool *pgxpool.Pool, cfg *pgxpool.Config) (*pgxpool.Pool, error) {
	var largestDB string
	_ = pool.QueryRow(ctx,
		"SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY pg_database_size(datname) DESC LIMIT 1",
	).Scan(&largestDB)
	if largestDB == "" || largestDB == cfg.ConnConfig.Database {
		return pool, nil
	}

	logger.Print(ctx, "postgres: reconnecting to largest database", "largest", largestDB, "previous", cfg.ConnConfig.Database)

	// Build the new pool first; only close the old one once the new one is up.
	// Keeps the collector usable if the reconnect fails (e.g. the target DB was dropped mid-scrape).
	previousDB := cfg.ConnConfig.Database
	cfg.ConnConfig.Database = largestDB
	newPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		cfg.ConnConfig.Database = previousDB // restore cfg for next retry
		return pool, fmt.Errorf("reconnect to %s: %w", largestDB, err)
	}
	pool.Close()
	return newPool, nil
}
