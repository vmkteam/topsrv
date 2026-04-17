package postgres

import "github.com/prometheus/client_golang/prometheus"

// initDescriptors initializes all Prometheus metric descriptors on the collector.
func (c *Collector) initDescriptors() {
	c.initClusterDescs()
	c.initReplicationDescs()
	c.initStatementDescs()
	c.initTableIndexDescs()
}

func (c *Collector) initClusterDescs() {
	c.up = prometheus.NewDesc("topsrv_pg_up", "PostgreSQL is reachable (1=yes, 0=no).", nil, nil)
	c.connections = prometheus.NewDesc("topsrv_pg_connections", "PostgreSQL connections by state.", []string{"state"}, nil)
	c.connectionsByAddr = prometheus.NewDesc("topsrv_pg_connections_by_addr", "PostgreSQL connections by client address and state.", []string{"client_addr", "state"}, nil)
	c.connectionsByApp = prometheus.NewDesc("topsrv_pg_connections_by_app", "PostgreSQL connections by application name and state.", []string{"application_name", "state"}, nil)
	c.maxConns = prometheus.NewDesc("topsrv_pg_max_connections", "PostgreSQL max_connections setting.", nil, nil)
	c.xact = prometheus.NewDesc("topsrv_pg_xact_total", "Transactions by type.", []string{"database", "type"}, nil)
	c.deadlocks = prometheus.NewDesc("topsrv_pg_deadlocks_total", "Deadlocks per database.", []string{"database"}, nil)
	c.tempFiles = prometheus.NewDesc("topsrv_pg_temp_files_total", "Temporary files per database.", []string{"database"}, nil)
	c.tempBytes = prometheus.NewDesc("topsrv_pg_temp_bytes_total", "Temporary bytes per database.", []string{"database"}, nil)
	c.blks = prometheus.NewDesc("topsrv_pg_blks_total", "Blocks hit/read per database.", []string{"database", "type"}, nil)
	c.checkpoints = prometheus.NewDesc("topsrv_pg_checkpoints_total", "Checkpoints by type.", []string{"type"}, nil)
	c.checkpointTime = prometheus.NewDesc("topsrv_pg_checkpoint_time_seconds_total", "Checkpoint time.", []string{"type"}, nil)
	c.buffers = prometheus.NewDesc("topsrv_pg_buffers_total", "Buffers by source.", []string{"source"}, nil)
	c.avWorkers = prometheus.NewDesc("topsrv_pg_autovacuum_workers", "Active autovacuum workers.", []string{"type"}, nil)
	c.avMaxWorkers = prometheus.NewDesc("topsrv_pg_autovacuum_max_workers", "Max autovacuum workers.", nil, nil)
	c.locks = prometheus.NewDesc("topsrv_pg_locks", "Locks by mode and grant status.", []string{"mode", "granted"}, nil)
	c.blockedBackends = prometheus.NewDesc("topsrv_pg_blocked_backends", "Backends waiting on a lock.", nil, nil)
	c.lockWaitMax = prometheus.NewDesc("topsrv_pg_lock_wait_seconds_max", "Longest current lock wait across backends.", nil, nil)
	c.waitEvents = prometheus.NewDesc("topsrv_pg_wait_events", "Backend count by wait event (sampled from pg_stat_activity).", []string{"backend_type", "datname", "application_name", "wait_event_type", "wait_event", "state"}, nil)
	c.wrapXIDAge = prometheus.NewDesc("topsrv_pg_wraparound_xid_age", "Transaction ID age per database.", []string{"database"}, nil)
	c.wrapMaxAge = prometheus.NewDesc("topsrv_pg_wraparound_max_age", "Autovacuum freeze max age.", nil, nil)
	c.dbSize = prometheus.NewDesc("topsrv_pg_database_size_bytes", "Database size in bytes.", []string{"database"}, nil)
	c.txAge = prometheus.NewDesc("topsrv_pg_longest_transaction_seconds", "Age of longest running transactions.", []string{"database", "usename"}, nil)
	c.settingGauge = prometheus.NewDesc("topsrv_pg_setting", "Selected PostgreSQL GUC settings. Memory/WAL in bytes, time in seconds, random_page_cost unitless.", []string{"name"}, nil)
	c.statsResetGauge = prometheus.NewDesc("topsrv_pg_stats_reset_timestamp_seconds", "Unix timestamp of last pg_stat_* reset. scope=database|bgwriter|wal|archiver.", []string{"scope"}, nil)
}

func (c *Collector) initReplicationDescs() {
	c.replLagBytes = prometheus.NewDesc("topsrv_pg_replication_lag_bytes", "Replication lag in bytes.", []string{"client_addr"}, nil)
	c.replLagSeconds = prometheus.NewDesc("topsrv_pg_replication_lag_seconds", "Replication lag in seconds by stage (write/flush/replay).", []string{"client_addr", "stage"}, nil)
	c.replSlotBytes = prometheus.NewDesc("topsrv_pg_replication_slot_retained_bytes", "WAL retained by slot.", []string{"slot"}, nil)
	c.replStreaming = prometheus.NewDesc("topsrv_pg_replication_streaming", "Replication session is streaming (1=yes).", []string{"client_addr"}, nil)
	c.replSyncState = prometheus.NewDesc("topsrv_pg_replication_sync_state", "Current sync_state per standby (async/sync/potential/quorum), value always 1.", []string{"client_addr", "sync_state"}, nil)
	c.walBytes = prometheus.NewDesc("topsrv_pg_wal_bytes", "WAL position in bytes.", nil, nil)
	c.walFiles = prometheus.NewDesc("topsrv_pg_wal_files", "WAL files count.", nil, nil)
	c.statWalRecords = prometheus.NewDesc("topsrv_pg_wal_records_total", "Total WAL records generated.", nil, nil)
	c.statWalFpi = prometheus.NewDesc("topsrv_pg_wal_fpi_total", "Total WAL full-page images generated.", nil, nil)
	c.statWalBuffersFull = prometheus.NewDesc("topsrv_pg_wal_buffers_full_total", "Times WAL data was written because wal_buffers were full.", nil, nil)
	c.statWalIoTime = prometheus.NewDesc("topsrv_pg_wal_io_time_seconds_total", "WAL I/O time by stage (write/sync).", []string{"op"}, nil)
	c.archiverTotal = prometheus.NewDesc("topsrv_pg_archiver_total", "WAL files processed by archiver.", []string{"result"}, nil)
	c.archiverLastTime = prometheus.NewDesc("topsrv_pg_archiver_last_timestamp_seconds", "Unix timestamp of last archiver event. Use time() - metric for age.", []string{"result"}, nil)
}

func (c *Collector) initStatementDescs() {
	c.queryTime = prometheus.NewDesc("topsrv_pg_query_time_seconds_total", "Total query execution time.", []string{"queryid", "query", "database"}, nil)
	c.queryCalls = prometheus.NewDesc("topsrv_pg_query_calls_total", "Total query calls.", []string{"queryid", "query", "database"}, nil)
	c.queryRows = prometheus.NewDesc("topsrv_pg_query_rows_total", "Total rows returned by query.", []string{"queryid", "query", "database"}, nil)
	c.queryBlksHit = prometheus.NewDesc("topsrv_pg_query_blks_hit_total", "Shared blocks hit by query.", []string{"queryid", "query", "database"}, nil)
	c.queryBlksRead = prometheus.NewDesc("topsrv_pg_query_blks_read_total", "Shared blocks read by query.", []string{"queryid", "query", "database"}, nil)
	c.queryBlksDirtied = prometheus.NewDesc("topsrv_pg_query_blks_dirtied_total", "Shared blocks dirtied by query.", []string{"queryid", "query", "database"}, nil)
	c.queryBlkReadTime = prometheus.NewDesc("topsrv_pg_query_blk_read_time_seconds_total", "Block read time by query.", []string{"queryid", "query", "database"}, nil)
	c.queryBlkWriteTime = prometheus.NewDesc("topsrv_pg_query_blk_write_time_seconds_total", "Block write time by query.", []string{"queryid", "query", "database"}, nil)
	c.queryTempRead = prometheus.NewDesc("topsrv_pg_query_temp_blks_read_total", "Temp blocks read by query.", []string{"queryid", "query", "database"}, nil)
	c.queryTempWritten = prometheus.NewDesc("topsrv_pg_query_temp_blks_written_total", "Temp blocks written by query.", []string{"queryid", "query", "database"}, nil)
	c.queryWalBytes = prometheus.NewDesc("topsrv_pg_query_wal_bytes_total", "WAL bytes generated by query.", []string{"queryid", "query", "database"}, nil)
	c.queryDuration = prometheus.NewDesc("topsrv_pg_query_duration_seconds", "Histogram of per-query execution time. Outlier-aware: new max/min timings are placed exactly in their buckets.", nil, nil)
}

func (c *Collector) initTableIndexDescs() {
	c.tableSize = prometheus.NewDesc("topsrv_pg_table_size_bytes", "Total table size.", []string{"database", "schema", "table"}, nil)
	c.tableSeqScan = prometheus.NewDesc("topsrv_pg_table_seq_scan_total", "Sequential scans.", []string{"database", "schema", "table"}, nil)
	c.tableSeqRead = prometheus.NewDesc("topsrv_pg_table_seq_tup_read_total", "Sequential tuples read.", []string{"database", "schema", "table"}, nil)
	c.tableIdxScan = prometheus.NewDesc("topsrv_pg_table_idx_scan_total", "Index scans.", []string{"database", "schema", "table"}, nil)
	c.tableTup = prometheus.NewDesc("topsrv_pg_table_tup_total", "Tuple operations.", []string{"database", "schema", "table", "op"}, nil)
	c.tableTuples = prometheus.NewDesc("topsrv_pg_table_tuples", "Tuples by state.", []string{"database", "schema", "table", "state"}, nil)
	c.tableAutoVacCount = prometheus.NewDesc("topsrv_pg_table_autovacuum_count_total", "Autovacuum runs per table.", []string{"database", "schema", "table"}, nil)
	c.tableLastMaint = prometheus.NewDesc("topsrv_pg_table_last_maintenance_timestamp_seconds", "Unix timestamp of last VACUUM/ANALYZE (manual or auto). Use time() - metric for age.", []string{"database", "schema", "table", "op"}, nil)
	c.tableModSinceAnz = prometheus.NewDesc("topsrv_pg_table_mod_since_analyze", "Rows modified since last ANALYZE.", []string{"database", "schema", "table"}, nil)
	c.indexScans = prometheus.NewDesc("topsrv_pg_index_scans_total", "Index scans (pg_stat_user_indexes). idx_scan=0 over long period = unused index.", []string{"database", "schema", "table", "index"}, nil)
	c.indexSize = prometheus.NewDesc("topsrv_pg_index_size_bytes", "Index size in bytes.", []string{"database", "schema", "table", "index"}, nil)
	c.tableBloatSize = prometheus.NewDesc("topsrv_pg_table_bloat_size_bytes", "Estimated wasted bytes in table heap (ioguix heuristic). Top 50 by bloat_size. Refreshed every 15 min.", []string{"database", "schema", "table"}, nil)
	c.tableBloatPct = prometheus.NewDesc("topsrv_pg_table_bloat_pct", "Estimated table bloat percentage (0-100). >30% typically worth pg_repack / CLUSTER.", []string{"database", "schema", "table"}, nil)
	c.indexBloatSize = prometheus.NewDesc("topsrv_pg_index_bloat_size_bytes", "Estimated wasted bytes in btree index (ioguix heuristic). Top 50 by bloat_size. Refreshed every 15 min.", []string{"database", "schema", "table", "index"}, nil)
	c.indexBloatPct = prometheus.NewDesc("topsrv_pg_index_bloat_pct", "Estimated index bloat percentage (0-100). >50% worth REINDEX CONCURRENTLY.", []string{"database", "schema", "table", "index"}, nil)
}

// allDescs returns every descriptor in a deterministic order. Used by Describe.
func (c *Collector) allDescs() []*prometheus.Desc {
	return []*prometheus.Desc{
		c.up,
		c.connections, c.connectionsByAddr, c.connectionsByApp, c.maxConns,
		c.xact, c.deadlocks, c.tempFiles, c.tempBytes, c.blks,
		c.checkpoints, c.checkpointTime, c.buffers,
		c.avWorkers, c.avMaxWorkers,
		c.locks, c.blockedBackends, c.lockWaitMax,
		c.waitEvents,
		c.replLagBytes, c.replLagSeconds, c.replSlotBytes, c.replStreaming, c.replSyncState,
		c.dbSize,
		c.walBytes, c.walFiles,
		c.statWalRecords, c.statWalFpi, c.statWalBuffersFull, c.statWalIoTime,
		c.wrapXIDAge, c.wrapMaxAge,
		c.archiverTotal, c.archiverLastTime,
		c.queryTime, c.queryCalls, c.queryRows,
		c.queryBlksHit, c.queryBlksRead, c.queryBlksDirtied,
		c.queryBlkReadTime, c.queryBlkWriteTime,
		c.queryTempRead, c.queryTempWritten, c.queryWalBytes,
		c.queryDuration,
		c.txAge,
		c.tableSize, c.tableSeqScan, c.tableSeqRead, c.tableIdxScan,
		c.tableTup, c.tableTuples, c.tableAutoVacCount,
		c.tableLastMaint, c.tableModSinceAnz,
		c.tableBloatSize, c.tableBloatPct,
		c.indexScans, c.indexSize,
		c.indexBloatSize, c.indexBloatPct,
		c.settingGauge, c.statsResetGauge,
	}
}
