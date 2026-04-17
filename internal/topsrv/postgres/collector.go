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
	settingRefreshInterval = time.Minute
)

// Collector collects PostgreSQL metrics via SQL queries.
type Collector struct {
	embedlog.Logger

	pool              *pgxpool.Pool
	versionNum        int    // server_version_num, cached
	database          string // current_database() — scope for per-DB views (pg_stat_user_tables/indexes)
	statementsTimeCol string // "total_exec_time" (PG13+) or "total_time" (PG12-)
	hasWalBytes       bool   // pg_stat_statements has wal_bytes column
	hasToplevel       bool   // pg_stat_statements has toplevel column (PG14+)
	archiveEnabled    bool   // archive_mode is 'on' or 'always'

	// query metadata for push to gatesrv (full query texts + database names)
	queryMetaMu sync.RWMutex
	queryMeta   []QueryMeta

	// queryid → set of application_names (accumulated from pg_stat_activity samples).
	// Sampled by a background ticker independent of Prometheus scrape to capture short queries.
	appNamesMu      sync.RWMutex
	appNames        map[int64]map[string]bool
	appNamesAvail   bool // false after first query failure (compute_query_id off)
	appSampleCancel context.CancelFunc
	appSampleDone   chan struct{}

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
	// settings + stats_reset
	settingGauge        *prometheus.Desc
	statsResetGauge     *prometheus.Desc
	settingsMu          sync.Mutex
	settingsCache       map[string]float64
	settingsLastRefresh time.Time
}

// NewCollector creates a PostgreSQL metrics collector connected via the given DSN.
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	// Detect PG version (SHOW returns text, not int).
	var versionStr string
	var versionNum int
	if vErr := pool.QueryRow(ctx, "SHOW server_version_num").Scan(&versionStr); vErr != nil {
		logger.Printf("postgres: failed to detect version: %v", vErr)
	} else {
		versionNum, _ = strconv.Atoi(versionStr)
		logger.Printf("postgres: connected, version=%d", versionNum)
	}

	// Auto-switch to the largest non-template database for table-level metrics.
	pool, err = switchToLargestDB(ctx, logger, pool, cfg)
	if err != nil {
		return nil, err
	}

	// Resolve current database name for per-DB metric labels.
	var database string
	_ = pool.QueryRow(ctx, "SELECT current_database()").Scan(&database)

	// pg_stat_statements: detect columns via pg_attribute (information_schema doesn't show extension views).
	hasCol := func(col string) bool {
		var ok int
		return pool.QueryRow(ctx,
			"SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid WHERE c.relname = 'pg_stat_statements' AND a.attname = $1", col).Scan(&ok) == nil
	}

	statementsTimeCol := "total_exec_time"
	if !hasCol("total_exec_time") {
		statementsTimeCol = "total_time"
	}

	hasWalBytes := hasCol("wal_bytes")
	hasToplevel := hasCol("toplevel")
	if hasToplevel {
		logger.Printf("postgres: pg_stat_statements toplevel filter enabled")
	}

	// Detect archive_mode once at startup. 'on' and 'always' both produce archiver stats.
	var archiveMode string
	archiveEnabled := false
	if err := pool.QueryRow(ctx, "SHOW archive_mode").Scan(&archiveMode); err == nil {
		archiveEnabled = archiveMode == "on" || archiveMode == "always"
		if archiveEnabled {
			logger.Printf("postgres: archive_mode=%s, pg_stat_archiver collection enabled", archiveMode)
		}
	}

	c := &Collector{
		Logger:            logger,
		pool:              pool,
		versionNum:        versionNum,
		database:          database,
		statementsTimeCol: statementsTimeCol,
		hasWalBytes:       hasWalBytes,
		hasToplevel:       hasToplevel,
		archiveEnabled:    archiveEnabled,
		appNames:          make(map[int64]map[string]bool),
		appNamesAvail:     true,
		prevStmts:         make(map[string]stmtPrev),
		histBuckets:       newHistBuckets(),
		settingsCache:     map[string]float64{},
	}
	c.initDescriptors()
	c.startAppNamesSampler(1 * time.Second)
	return c, nil
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

	if err := c.pool.Ping(ctx); err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		c.Errorf("postgres: ping failed: %v", err)
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
}

// Close stops the background sampler and closes the connection pool. Implements io.Closer.
func (c *Collector) Close() error {
	if c.appSampleCancel != nil {
		c.appSampleCancel()
		<-c.appSampleDone
	}
	if c.pool != nil {
		c.pool.Close()
		c.Printf("postgres: connection pool closed")
	}
	return nil
}

func (c *Collector) queryWarn(query string, err error) {
	c.Printf("postgres: query failed: %s: %v", query, err)
}

// switchToLargestDB reconnects to the largest non-template database if it differs from current.
// This allows table-level metrics (pg_stat_user_tables) to see application tables.
func switchToLargestDB(ctx context.Context, logger embedlog.Logger, pool *pgxpool.Pool, cfg *pgxpool.Config) (*pgxpool.Pool, error) {
	var largestDB string
	_ = pool.QueryRow(ctx,
		"SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY pg_database_size(datname) DESC LIMIT 1",
	).Scan(&largestDB)
	if largestDB == "" || largestDB == cfg.ConnConfig.Database {
		return pool, nil
	}

	logger.Printf("postgres: largest database is %q, reconnecting (was %q)", largestDB, cfg.ConnConfig.Database)
	pool.Close()

	cfg.ConnConfig.Database = largestDB
	newPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("reconnect to %s: %w", largestDB, err)
	}
	return newPool, nil
}
