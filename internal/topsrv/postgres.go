package topsrv

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
	pgCollectTimeout = 10 * time.Second
	pgVersionPG17    = 170000 // pg_stat_checkpointer introduced
)

// queryDurationBuckets — histogram buckets for per-query mean execution time (seconds).
// Covers range from 0.1ms (fast PK lookup) to 10s (heavy analytics / lock wait).
var queryDurationBuckets = []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10}

// stmtPrev stores previous pg_stat_statements values for delta computation.
type stmtPrev struct {
	calls     int64
	totalTime float64 // milliseconds (as reported by PG)
}

// QueryMeta holds full query text metadata for push to gatesrv.
type QueryMeta struct {
	QueryID  string `json:"queryid"`
	Database string `json:"database"`
	Query    string `json:"query"`
}

// PostgresCollector collects PostgreSQL metrics via SQL queries.
// Minimum version: PG15. Extensions: pg_stat_statements (optional).
type PostgresCollector struct {
	embedlog.Logger

	pool              *pgxpool.Pool
	versionNum        int    // server_version_num, cached
	statementsTimeCol string // "total_exec_time" (PG13+) or "total_time" (PG12-)

	// query metadata for push to gatesrv (full query texts + database names)
	queryMetaMu sync.RWMutex
	queryMeta   []QueryMeta

	// histogram state — cumulative counters for query duration distribution
	prevStmts   map[string]stmtPrev
	histCount   uint64
	histSum     float64
	histBuckets map[float64]uint64

	up *prometheus.Desc
	// connections
	connections       *prometheus.Desc
	connectionsByAddr *prometheus.Desc
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
	locks *prometheus.Desc
	// replication
	replLagBytes   *prometheus.Desc
	replLagSeconds *prometheus.Desc
	replSlotBytes  *prometheus.Desc
	replStreaming  *prometheus.Desc
	// database
	dbSize *prometheus.Desc
	// WAL
	walBytes *prometheus.Desc
	walFiles *prometheus.Desc
	// wraparound
	wrapXIDAge *prometheus.Desc
	wrapMaxAge *prometheus.Desc
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
	// tables
	tableSize         *prometheus.Desc
	tableSeqScan      *prometheus.Desc
	tableSeqRead      *prometheus.Desc
	tableIdxScan      *prometheus.Desc
	tableTup          *prometheus.Desc
	tableTuples       *prometheus.Desc
	tableAutoVacCount *prometheus.Desc
}

func NewPostgresCollector(logger embedlog.Logger, dsn string) (*PostgresCollector, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 2 // 1 for scrape queries + 1 for concurrent Ping
	cfg.MinConns = 0

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	// Detect PG version (SHOW returns text, not int).
	var versionStr string
	var versionNum int
	if err := pool.QueryRow(ctx, "SHOW server_version_num").Scan(&versionStr); err != nil {
		logger.Printf("postgres: failed to detect version: %v", err)
	} else {
		versionNum, _ = strconv.Atoi(versionStr)
		logger.Printf("postgres: connected, version=%d", versionNum)
	}

	// pg_stat_statements: detect column name for total time
	statementsTimeCol := "total_exec_time" // PG13+ (pg_stat_statements 1.8+)
	var colCheck int
	if err := pool.QueryRow(ctx, "SELECT 1 FROM information_schema.columns WHERE table_name='pg_stat_statements' AND column_name='total_exec_time'").Scan(&colCheck); err != nil {
		statementsTimeCol = "total_time" // PG12- (pg_stat_statements ≤1.7)
	}

	histBuckets := make(map[float64]uint64, len(queryDurationBuckets))
	for _, b := range queryDurationBuckets {
		histBuckets[b] = 0
	}

	return &PostgresCollector{
		Logger:            logger,
		pool:              pool,
		versionNum:        versionNum,
		statementsTimeCol: statementsTimeCol,
		prevStmts:         make(map[string]stmtPrev),
		histBuckets:       histBuckets,

		up:                prometheus.NewDesc("topsrv_pg_up", "PostgreSQL is reachable (1=yes, 0=no).", nil, nil),
		connections:       prometheus.NewDesc("topsrv_pg_connections", "PostgreSQL connections by state.", []string{"state"}, nil),
		connectionsByAddr: prometheus.NewDesc("topsrv_pg_connections_by_addr", "PostgreSQL connections by client address and state.", []string{"client_addr", "state"}, nil),
		maxConns:          prometheus.NewDesc("topsrv_pg_max_connections", "PostgreSQL max_connections setting.", nil, nil),
		xact:              prometheus.NewDesc("topsrv_pg_xact_total", "Transactions by type.", []string{"database", "type"}, nil),
		deadlocks:         prometheus.NewDesc("topsrv_pg_deadlocks_total", "Deadlocks per database.", []string{"database"}, nil),
		tempFiles:         prometheus.NewDesc("topsrv_pg_temp_files_total", "Temporary files per database.", []string{"database"}, nil),
		tempBytes:         prometheus.NewDesc("topsrv_pg_temp_bytes_total", "Temporary bytes per database.", []string{"database"}, nil),
		blks:              prometheus.NewDesc("topsrv_pg_blks_total", "Blocks hit/read per database.", []string{"database", "type"}, nil),
		checkpoints:       prometheus.NewDesc("topsrv_pg_checkpoints_total", "Checkpoints by type.", []string{"type"}, nil),
		checkpointTime:    prometheus.NewDesc("topsrv_pg_checkpoint_time_seconds_total", "Checkpoint time.", []string{"type"}, nil),
		buffers:           prometheus.NewDesc("topsrv_pg_buffers_total", "Buffers by source.", []string{"source"}, nil),
		avWorkers:         prometheus.NewDesc("topsrv_pg_autovacuum_workers", "Active autovacuum workers.", []string{"type"}, nil),
		avMaxWorkers:      prometheus.NewDesc("topsrv_pg_autovacuum_max_workers", "Max autovacuum workers.", nil, nil),
		locks:             prometheus.NewDesc("topsrv_pg_locks", "Granted locks by mode.", []string{"mode"}, nil),
		replLagBytes:      prometheus.NewDesc("topsrv_pg_replication_lag_bytes", "Replication lag in bytes.", []string{"client_addr"}, nil),
		replLagSeconds:    prometheus.NewDesc("topsrv_pg_replication_lag_seconds", "Replication lag in seconds.", []string{"client_addr"}, nil),
		replSlotBytes:     prometheus.NewDesc("topsrv_pg_replication_slot_retained_bytes", "WAL retained by slot.", []string{"slot"}, nil),
		replStreaming:     prometheus.NewDesc("topsrv_pg_replication_streaming", "Replication session is streaming (1=yes).", []string{"client_addr"}, nil),
		dbSize:            prometheus.NewDesc("topsrv_pg_database_size_bytes", "Database size in bytes.", []string{"database"}, nil),
		walBytes:          prometheus.NewDesc("topsrv_pg_wal_bytes", "WAL position in bytes.", nil, nil),
		walFiles:          prometheus.NewDesc("topsrv_pg_wal_files", "WAL files count.", nil, nil),
		wrapXIDAge:        prometheus.NewDesc("topsrv_pg_wraparound_xid_age", "Transaction ID age per database.", []string{"database"}, nil),
		wrapMaxAge:        prometheus.NewDesc("topsrv_pg_wraparound_max_age", "Autovacuum freeze max age.", nil, nil),
		queryTime:         prometheus.NewDesc("topsrv_pg_query_time_seconds_total", "Total query execution time.", []string{"queryid", "query"}, nil),
		queryCalls:        prometheus.NewDesc("topsrv_pg_query_calls_total", "Total query calls.", []string{"queryid", "query"}, nil),
		queryRows:         prometheus.NewDesc("topsrv_pg_query_rows_total", "Total rows returned by query.", []string{"queryid", "query"}, nil),
		queryBlksHit:      prometheus.NewDesc("topsrv_pg_query_blks_hit_total", "Shared blocks hit by query.", []string{"queryid", "query"}, nil),
		queryBlksRead:     prometheus.NewDesc("topsrv_pg_query_blks_read_total", "Shared blocks read by query.", []string{"queryid", "query"}, nil),
		queryBlksDirtied:  prometheus.NewDesc("topsrv_pg_query_blks_dirtied_total", "Shared blocks dirtied by query.", []string{"queryid", "query"}, nil),
		queryBlkReadTime:  prometheus.NewDesc("topsrv_pg_query_blk_read_time_seconds_total", "Block read time by query.", []string{"queryid", "query"}, nil),
		queryBlkWriteTime: prometheus.NewDesc("topsrv_pg_query_blk_write_time_seconds_total", "Block write time by query.", []string{"queryid", "query"}, nil),
		queryTempRead:     prometheus.NewDesc("topsrv_pg_query_temp_blks_read_total", "Temp blocks read by query.", []string{"queryid", "query"}, nil),
		queryTempWritten:  prometheus.NewDesc("topsrv_pg_query_temp_blks_written_total", "Temp blocks written by query.", []string{"queryid", "query"}, nil),
		queryWalBytes:     prometheus.NewDesc("topsrv_pg_query_wal_bytes_total", "WAL bytes generated by query.", []string{"queryid", "query"}, nil),
		queryDuration:     prometheus.NewDesc("topsrv_pg_query_duration_seconds", "Histogram of per-query mean execution time from pg_stat_statements.", nil, nil),
		tableSize:         prometheus.NewDesc("topsrv_pg_table_size_bytes", "Total table size.", []string{"schema", "table"}, nil),
		tableSeqScan:      prometheus.NewDesc("topsrv_pg_table_seq_scan_total", "Sequential scans.", []string{"schema", "table"}, nil),
		tableSeqRead:      prometheus.NewDesc("topsrv_pg_table_seq_tup_read_total", "Sequential tuples read.", []string{"schema", "table"}, nil),
		tableIdxScan:      prometheus.NewDesc("topsrv_pg_table_idx_scan_total", "Index scans.", []string{"schema", "table"}, nil),
		tableTup:          prometheus.NewDesc("topsrv_pg_table_tup_total", "Tuple operations.", []string{"schema", "table", "op"}, nil),
		tableTuples:       prometheus.NewDesc("topsrv_pg_table_tuples", "Tuples by state.", []string{"schema", "table", "state"}, nil),
		tableAutoVacCount: prometheus.NewDesc("topsrv_pg_table_autovacuum_count_total", "Autovacuum runs per table.", []string{"schema", "table"}, nil),
	}, nil
}

func (c *PostgresCollector) Name() string { return "postgres" }

func (c *PostgresCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.connections
	ch <- c.connectionsByAddr
	ch <- c.maxConns
	ch <- c.xact
	ch <- c.deadlocks
	ch <- c.tempFiles
	ch <- c.tempBytes
	ch <- c.blks
	ch <- c.checkpoints
	ch <- c.checkpointTime
	ch <- c.buffers
	ch <- c.avWorkers
	ch <- c.avMaxWorkers
	ch <- c.locks
	ch <- c.replLagBytes
	ch <- c.replLagSeconds
	ch <- c.replSlotBytes
	ch <- c.replStreaming
	ch <- c.dbSize
	ch <- c.walBytes
	ch <- c.walFiles
	ch <- c.wrapXIDAge
	ch <- c.wrapMaxAge
	ch <- c.queryTime
	ch <- c.queryCalls
	ch <- c.queryRows
	ch <- c.queryBlksHit
	ch <- c.queryBlksRead
	ch <- c.queryBlksDirtied
	ch <- c.queryBlkReadTime
	ch <- c.queryBlkWriteTime
	ch <- c.queryTempRead
	ch <- c.queryTempWritten
	ch <- c.queryWalBytes
	ch <- c.queryDuration
	ch <- c.tableSize
	ch <- c.tableSeqScan
	ch <- c.tableSeqRead
	ch <- c.tableIdxScan
	ch <- c.tableTup
	ch <- c.tableTuples
	ch <- c.tableAutoVacCount
}

func (c *PostgresCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), pgCollectTimeout)
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
	c.collectStatements(ctx, ch)
	c.collectTables(ctx, ch)
}

func (c *PostgresCollector) collectConnections(ctx context.Context, ch chan<- prometheus.Metric) {
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

	// connections by client_addr + state
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

	var maxConn int64
	if c.pool.QueryRow(ctx, `SELECT setting::bigint FROM pg_settings WHERE name = 'max_connections'`).Scan(&maxConn) == nil {
		ch <- prometheus.MustNewConstMetric(c.maxConns, prometheus.GaugeValue, float64(maxConn))
	}
}

func (c *PostgresCollector) collectTransactions(ctx context.Context, ch chan<- prometheus.Metric) {
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

func (c *PostgresCollector) collectBGWriter(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.versionNum >= pgVersionPG17 {
		c.collectCheckpointerPG17(ctx, ch)
		c.collectBGWriterBuffers(ctx, ch) // PG17: only buffers_clean + buffers_alloc
	} else {
		c.collectBGWriterPG15(ctx, ch) // PG15-16: all in one view
	}
}

func (c *PostgresCollector) collectBGWriterPG15(ctx context.Context, ch chan<- prometheus.Metric) {
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

func (c *PostgresCollector) collectCheckpointerPG17(ctx context.Context, ch chan<- prometheus.Metric) {
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

func (c *PostgresCollector) collectBGWriterBuffers(ctx context.Context, ch chan<- prometheus.Metric) {
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

func (c *PostgresCollector) collectAutovacuum(ctx context.Context, ch chan<- prometheus.Metric) {
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

func (c *PostgresCollector) collectLocks(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `SELECT mode, count(*) FROM pg_locks WHERE granted GROUP BY mode`)
	if err != nil {
		c.queryWarn("locks", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var mode string
		var count int64
		if rows.Scan(&mode, &count) == nil {
			ch <- prometheus.MustNewConstMetric(c.locks, prometheus.GaugeValue, float64(count), mode)
		}
	}
}

func (c *PostgresCollector) collectReplication(ctx context.Context, ch chan<- prometheus.Metric) {
	rows, err := c.pool.Query(ctx, `SELECT coalesce(client_addr::text, 'local'), state, coalesce(pg_wal_lsn_diff(sent_lsn, replay_lsn), 0), coalesce(extract(epoch from replay_lag), 0) FROM pg_stat_replication`)
	if err != nil {
		c.queryWarn("replication", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var addr, state string
		var lagBytes, lagSeconds float64
		if rows.Scan(&addr, &state, &lagBytes, &lagSeconds) == nil {
			ch <- prometheus.MustNewConstMetric(c.replLagBytes, prometheus.GaugeValue, lagBytes, addr)
			ch <- prometheus.MustNewConstMetric(c.replLagSeconds, prometheus.GaugeValue, lagSeconds, addr)
			streaming := 0.0
			if state == "streaming" {
				streaming = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.replStreaming, prometheus.GaugeValue, streaming, addr)
		}
	}
}

func (c *PostgresCollector) collectReplicationSlots(ctx context.Context, ch chan<- prometheus.Metric) {
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

func (c *PostgresCollector) collectDatabaseSizes(ctx context.Context, ch chan<- prometheus.Metric) {
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

func (c *PostgresCollector) collectWAL(ctx context.Context, ch chan<- prometheus.Metric) {
	var walBytes float64
	if c.pool.QueryRow(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')`).Scan(&walBytes) == nil {
		ch <- prometheus.MustNewConstMetric(c.walBytes, prometheus.CounterValue, walBytes)
	}

	var walFiles int64
	if c.pool.QueryRow(ctx, `SELECT count(*) FROM pg_ls_waldir()`).Scan(&walFiles) == nil {
		ch <- prometheus.MustNewConstMetric(c.walFiles, prometheus.GaugeValue, float64(walFiles))
	}
}

func (c *PostgresCollector) collectWraparound(ctx context.Context, ch chan<- prometheus.Metric) {
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

func (c *PostgresCollector) collectStatements(ctx context.Context, ch chan<- prometheus.Metric) {
	// pg_stat_statements 1.8+ (PG13+) renamed total_time → total_exec_time
	timeCol := "total_exec_time"
	if c.statementsTimeCol != "" {
		timeCol = c.statementsTimeCol
	}

	// PG17 (pg_stat_statements 1.11) renamed blk_read_time → shared_blk_read_time, blk_write_time → shared_blk_write_time
	blkReadCol, blkWriteCol := "blk_read_time", "blk_write_time"
	if c.versionNum >= pgVersionPG17 {
		blkReadCol, blkWriteCol = "shared_blk_read_time", "shared_blk_write_time"
	}

	// Per-query metrics: union of top 20 by time, top 20 by calls, top 20 by blocks read.
	// This ensures sorting by any dimension on the frontend shows the real top queries.
	// timeCol, blkReadCol, blkWriteCol are set from code, not from user input — safe to concatenate.
	cols := `queryid::text, left(query, 100), calls, ` + timeCol + `, rows, shared_blks_hit, shared_blks_read, shared_blks_dirtied, ` + blkReadCol + `, ` + blkWriteCol + `, temp_blks_read, temp_blks_written, wal_bytes`
	q := `WITH top_ids AS (` +
		`(SELECT queryid FROM pg_stat_statements WHERE userid != 0 ORDER BY ` + timeCol + ` DESC LIMIT 20) ` +
		`UNION (SELECT queryid FROM pg_stat_statements WHERE userid != 0 ORDER BY calls DESC LIMIT 20) ` +
		`UNION (SELECT queryid FROM pg_stat_statements WHERE userid != 0 ORDER BY shared_blks_read DESC LIMIT 20)` +
		`) SELECT ` + cols + ` FROM pg_stat_statements WHERE userid != 0 AND queryid IN (SELECT queryid FROM top_ids) ORDER BY ` + timeCol + ` DESC`
	rows, err := c.pool.Query(ctx, q)
	if err != nil {
		c.queryWarn("pg_stat_statements", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var qid, query string
		var calls, rowsN, blksHit, blksRead, blksDirtied, tempRead, tempWritten, walBytes int64
		var totalTime, blkReadTime, blkWriteTime float64
		if err := rows.Scan(&qid, &query, &calls, &totalTime, &rowsN, &blksHit, &blksRead, &blksDirtied, &blkReadTime, &blkWriteTime, &tempRead, &tempWritten, &walBytes); err != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.queryTime, prometheus.CounterValue, totalTime*msToSec, qid, query)
		ch <- prometheus.MustNewConstMetric(c.queryCalls, prometheus.CounterValue, float64(calls), qid, query)
		ch <- prometheus.MustNewConstMetric(c.queryRows, prometheus.CounterValue, float64(rowsN), qid, query)
		ch <- prometheus.MustNewConstMetric(c.queryBlksHit, prometheus.CounterValue, float64(blksHit), qid, query)
		ch <- prometheus.MustNewConstMetric(c.queryBlksRead, prometheus.CounterValue, float64(blksRead), qid, query)
		ch <- prometheus.MustNewConstMetric(c.queryBlksDirtied, prometheus.CounterValue, float64(blksDirtied), qid, query)
		ch <- prometheus.MustNewConstMetric(c.queryBlkReadTime, prometheus.CounterValue, blkReadTime*msToSec, qid, query)
		ch <- prometheus.MustNewConstMetric(c.queryBlkWriteTime, prometheus.CounterValue, blkWriteTime*msToSec, qid, query)
		ch <- prometheus.MustNewConstMetric(c.queryTempRead, prometheus.CounterValue, float64(tempRead), qid, query)
		ch <- prometheus.MustNewConstMetric(c.queryTempWritten, prometheus.CounterValue, float64(tempWritten), qid, query)
		ch <- prometheus.MustNewConstMetric(c.queryWalBytes, prometheus.CounterValue, float64(walBytes), qid, query)
	}

	// Collect full query texts for metadata push.
	c.collectQueryMeta(ctx, timeCol)

	// Histogram: ALL queries (no LIMIT) — aggregated into buckets without per-query labels
	c.collectStatementsHistogram(ctx, ch, timeCol)
}

// collectQueryMeta fetches full query texts and database names for metadata push to gatesrv.
func (c *PostgresCollector) collectQueryMeta(ctx context.Context, timeCol string) {
	q := `SELECT s.queryid::text, d.datname, s.query FROM pg_stat_statements s JOIN pg_database d ON d.oid = s.dbid WHERE s.userid != 0 ORDER BY s.` + timeCol + ` DESC LIMIT 100`
	rows, err := c.pool.Query(ctx, q)
	if err != nil {
		// Silently skip — metadata is best-effort.
		return
	}
	defer rows.Close()

	var meta []QueryMeta
	for rows.Next() {
		var qid, db, query string
		if err := rows.Scan(&qid, &db, &query); err != nil {
			continue
		}
		meta = append(meta, QueryMeta{QueryID: qid, Database: db, Query: query})
	}

	c.queryMetaMu.Lock()
	c.queryMeta = meta
	c.queryMetaMu.Unlock()
}

// QueryMeta returns the latest collected query metadata (thread-safe).
func (c *PostgresCollector) QueryMeta() []QueryMeta {
	c.queryMetaMu.RLock()
	defer c.queryMetaMu.RUnlock()
	return c.queryMeta
}

func (c *PostgresCollector) collectStatementsHistogram(ctx context.Context, ch chan<- prometheus.Metric, timeCol string) {
	q := `SELECT dbid::text || ':' || queryid::text, calls, ` + timeCol + ` FROM pg_stat_statements WHERE userid != 0`
	rows, err := c.pool.Query(ctx, q)
	if err != nil {
		return
	}
	defer rows.Close()

	seen := make(map[string]struct{}, 64)
	for rows.Next() {
		var qid string
		var calls int64
		var totalTime float64
		if rows.Scan(&qid, &calls, &totalTime) != nil {
			continue
		}

		seen[qid] = struct{}{}
		if prev, ok := c.prevStmts[qid]; ok {
			deltaCalls := calls - prev.calls
			deltaTime := totalTime - prev.totalTime
			if deltaCalls > 0 && deltaTime >= 0 {
				meanSec := (deltaTime * msToSec) / float64(deltaCalls)
				for _, le := range queryDurationBuckets {
					if meanSec <= le {
						c.histBuckets[le] += uint64(deltaCalls)
					}
				}
				c.histCount += uint64(deltaCalls)
				c.histSum += deltaTime * msToSec
			}
		}
		c.prevStmts[qid] = stmtPrev{calls: calls, totalTime: totalTime}
	}

	// Clean up prevStmts for queries no longer in pg_stat_statements
	for qid := range c.prevStmts {
		if _, ok := seen[qid]; !ok {
			delete(c.prevStmts, qid)
		}
	}

	if c.histCount > 0 {
		ch <- prometheus.MustNewConstHistogram(c.queryDuration, c.histCount, c.histSum, c.histBuckets)
	}
}

func (c *PostgresCollector) collectTables(ctx context.Context, ch chan<- prometheus.Metric) {
	// Two-step approach: cheap relpages sort over all tables, then pg_total_relation_size only for top 50.
	rows, err := c.pool.Query(ctx, `WITH top AS (SELECT relid FROM pg_stat_user_tables s JOIN pg_class c ON c.oid = s.relid ORDER BY c.relpages DESC LIMIT 50) SELECT s.schemaname, s.relname, s.seq_scan, s.seq_tup_read, coalesce(s.idx_scan, 0), s.n_tup_ins, s.n_tup_upd, s.n_tup_del, s.n_live_tup, s.n_dead_tup, pg_total_relation_size(s.relid) AS total_size, s.autovacuum_count FROM pg_stat_user_tables s JOIN top t ON t.relid = s.relid ORDER BY total_size DESC`)
	if err != nil {
		c.queryWarn("tables", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var schema, table string
		var seqScan, seqRead, idxScan, ins, upd, del, live, dead, size, avCount int64
		if rows.Scan(&schema, &table, &seqScan, &seqRead, &idxScan, &ins, &upd, &del, &live, &dead, &size, &avCount) != nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.tableSize, prometheus.GaugeValue, float64(size), schema, table)
		ch <- prometheus.MustNewConstMetric(c.tableSeqScan, prometheus.CounterValue, float64(seqScan), schema, table)
		ch <- prometheus.MustNewConstMetric(c.tableSeqRead, prometheus.CounterValue, float64(seqRead), schema, table)
		ch <- prometheus.MustNewConstMetric(c.tableIdxScan, prometheus.CounterValue, float64(idxScan), schema, table)
		ch <- prometheus.MustNewConstMetric(c.tableTup, prometheus.CounterValue, float64(ins), schema, table, "insert")
		ch <- prometheus.MustNewConstMetric(c.tableTup, prometheus.CounterValue, float64(upd), schema, table, "update")
		ch <- prometheus.MustNewConstMetric(c.tableTup, prometheus.CounterValue, float64(del), schema, table, "delete")
		ch <- prometheus.MustNewConstMetric(c.tableTuples, prometheus.GaugeValue, float64(live), schema, table, "live")
		ch <- prometheus.MustNewConstMetric(c.tableTuples, prometheus.GaugeValue, float64(dead), schema, table, "dead")
		ch <- prometheus.MustNewConstMetric(c.tableAutoVacCount, prometheus.CounterValue, float64(avCount), schema, table)
	}
}

func (c *PostgresCollector) queryWarn(query string, err error) {
	c.Printf("postgres: query failed: %s: %v", query, err)
}

// Close closes the connection pool. Implements io.Closer.
func (c *PostgresCollector) Close() error {
	if c.pool != nil {
		c.pool.Close()
		c.Printf("postgres: connection pool closed")
	}
	return nil
}

// compile-time check
var _ Collector = (*PostgresCollector)(nil)
