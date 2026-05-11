# Metrics reference

## System (`topsrv_cpu_*`, `topsrv_memory_*`, `topsrv_load_*`, `topsrv_swap_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_cpu_seconds_total` | counter | cpu, mode | CPU time per core per mode (user/system/idle/iowait/steal/irq/softirq/nice) |
| `topsrv_cpu_cores` | gauge | — | Logical CPU count |
| `topsrv_load_average` | gauge | interval | Load average (1m/5m/15m) |
| `topsrv_memory_bytes` | gauge | type | Memory (total/used/free/buffers/cached/available) |
| `topsrv_swap_bytes` | gauge | type | Swap (total/used/free) |
| `topsrv_swap_io_bytes_total` | counter | direction | Swap I/O (in/out) |
| `topsrv_uptime_seconds` | gauge | — | System uptime |
| `topsrv_boot_time_seconds` | gauge | — | Boot time as Unix timestamp |
| `topsrv_host_info` | gauge | hostname, os, platform, platform_version, kernel_version, kernel_arch, version | Host metadata + agent version |
| `topsrv_context_switches_total` | counter | — | Context switches (Linux) |
| `topsrv_procs` | gauge | state | Processes by state (running/blocked) |

## Disk (`topsrv_disk_*`, `topsrv_filesystem_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_disk_read_bytes_total` | counter | device | Bytes read |
| `topsrv_disk_write_bytes_total` | counter | device | Bytes written |
| `topsrv_disk_read_ops_total` | counter | device | Read operations |
| `topsrv_disk_write_ops_total` | counter | device | Write operations |
| `topsrv_disk_read_time_seconds_total` | counter | device | Read time |
| `topsrv_disk_write_time_seconds_total` | counter | device | Write time |
| `topsrv_disk_io_time_seconds_total` | counter | device | Total I/O time |
| `topsrv_disk_io_time_weighted_seconds_total` | counter | device | Weighted I/O time (queue depth) |
| `topsrv_filesystem_bytes` | gauge | mountpoint, device, fstype, type | Filesystem space (total/used/free) |
| `topsrv_filesystem_inodes` | gauge | mountpoint, type | Filesystem inodes (total/used/free) |

## Network (`topsrv_network_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_network_bytes_total` | counter | interface, direction | Bytes (rx/tx) |
| `topsrv_network_packets_total` | counter | interface, direction | Packets (rx/tx) |
| `topsrv_network_errors_total` | counter | interface, direction | Errors (rx/tx) |
| `topsrv_network_drops_total` | counter | interface, direction | Drops (rx/tx) |
| `topsrv_network_speed_bytes` | gauge | interface | Link speed in bytes/sec (from `/sys/class/net/*/speed`) |
| `topsrv_network_info` | gauge | interface, mac, address, mtu, operstate | Interface metadata |

## Netstat (`topsrv_netstat_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_netstat_tcp_connections` | gauge | state, direction | TCP connections by state and direction (inbound/outbound) |
| `topsrv_netstat_tcp_connections_by_port` | gauge | port | TCP connections per listen port |
| `topsrv_netstat_tcp_retransmits_total` | counter | — | TCP retransmitted segments |
| `topsrv_netstat_tcp_in_errs_total` | counter | — | TCP segments received in error |
| `topsrv_netstat_tcp_out_rsts_total` | counter | — | TCP RST segments sent |
| `topsrv_netstat_udp_no_ports_total` | counter | — | UDP datagrams to unknown port |
| `topsrv_netstat_udp_in_errors_total` | counter | — | UDP receive errors |
| `topsrv_netstat_udp_sndbuf_errors_total` | counter | — | UDP send buffer errors |
| `topsrv_netstat_ip_unknown_protos_total` | counter | — | IP datagrams with unknown protocol |

## Process (`topsrv_process_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_process_cpu_seconds_total` | counter | group | CPU time per process group |
| `topsrv_process_memory_bytes` | gauge | group, type | Memory (rss/vms/swap) per process group |
| `topsrv_process_disk_read_bytes_total` | counter | group | Disk bytes read (Linux) |
| `topsrv_process_disk_write_bytes_total` | counter | group | Disk bytes written (Linux) |
| `topsrv_process_disk_read_ops_total` | counter | group | Disk read ops (Linux) |
| `topsrv_process_disk_write_ops_total` | counter | group | Disk write ops (Linux) |
| `topsrv_process_num_procs` | gauge | group | Process count per group |
| `topsrv_process_threads` | gauge | group | Thread count per group |
| `topsrv_process_open_fds` | gauge | group | Open file descriptors per group (Linux) |
| `topsrv_process_worst_fd_ratio` | gauge | group | Worst fd/limit ratio per group (Linux) |
| `topsrv_process_major_page_faults_total` | counter | group | Major page faults per group |

## PostgreSQL (`topsrv_pg_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_pg_up` | gauge | — | PostgreSQL is reachable (0/1) |
| `topsrv_pg_connections` | gauge | state | Connections by state |
| `topsrv_pg_connections_by_addr` | gauge | client_addr, state | Connections by client address and state |
| `topsrv_pg_connections_by_app` | gauge | application_name, state | Connections by application name and state |
| `topsrv_pg_max_connections` | gauge | — | max_connections setting |
| `topsrv_pg_xact_total` | counter | database, type | Commits/rollbacks per database |
| `topsrv_pg_deadlocks_total` | counter | database | Deadlocks per database |
| `topsrv_pg_temp_files_total` | counter | database | Temp files per database |
| `topsrv_pg_temp_bytes_total` | counter | database | Temp file bytes per database |
| `topsrv_pg_blks_total` | counter | database, type | Blocks hit/read per database |
| `topsrv_pg_checkpoints_total` | counter | type | Checkpoints (timed/requested) |
| `topsrv_pg_checkpoint_time_seconds_total` | counter | type | Checkpoint write/sync time |
| `topsrv_pg_buffers_total` | counter | source | Buffers (checkpoint/clean/backend/alloc) |
| `topsrv_pg_autovacuum_workers` | gauge | type | Autovacuum workers (common/wraparound) |
| `topsrv_pg_autovacuum_max_workers` | gauge | — | Max autovacuum workers |
| `topsrv_pg_locks` | gauge | mode, granted | Locks by mode and grant status. `granted="false"` = waiting locks |
| `topsrv_pg_blocked_backends` | gauge | — | Backends currently waiting on a heavyweight lock |
| `topsrv_pg_lock_wait_seconds_max` | gauge | — | Longest current lock wait across all backends |
| `topsrv_pg_wait_events` | gauge | backend_type, datname, application_name, wait_event_type, wait_event, state | ASH-style sample from `pg_stat_activity`. `wait_event_type="CPU"` means on-CPU |
| `topsrv_pg_replication_lag_bytes` | gauge | client_addr | Replication lag in bytes |
| `topsrv_pg_replication_lag_seconds` | gauge | client_addr, stage | Replication lag by stage: `write` (network), `flush` (fsync on replica), `replay` (apply). Splits bottleneck |
| `topsrv_pg_replication_slot_retained_bytes` | gauge | slot | WAL retained by slot |
| `topsrv_pg_replication_streaming` | gauge | client_addr | Streaming status (0/1) |
| `topsrv_pg_replication_sync_state` | gauge | client_addr, sync_state | Current sync_state per standby (`async`/`sync`/`potential`/`quorum`). Value = 1 |
| `topsrv_pg_database_size_bytes` | gauge | database | Database size |
| `topsrv_pg_wal_bytes` | counter | — | WAL position in bytes (from `pg_current_wal_lsn`) |
| `topsrv_pg_wal_files` | gauge | — | WAL file count |
| `topsrv_pg_wal_records_total` | counter | — | WAL records generated (PG14+, `pg_stat_wal`) |
| `topsrv_pg_wal_fpi_total` | counter | — | WAL full-page images generated (PG14+) |
| `topsrv_pg_wal_buffers_full_total` | counter | — | Times WAL was written because `wal_buffers` were full (PG14+) |
| `topsrv_pg_wal_io_time_seconds_total` | counter | op | WAL I/O time by stage (`write`/`sync`, PG14+) |
| `topsrv_pg_archiver_total` | counter | result | WAL archiver events by outcome (`archived`/`failed`). Only when `archive_mode=on` |
| `topsrv_pg_archiver_last_timestamp_seconds` | gauge | result | Unix time of last archiver event. Alert: `time() - metric > 300` |
| `topsrv_pg_wraparound_xid_age` | gauge | database | Transaction ID age |
| `topsrv_pg_wraparound_max_age` | gauge | — | Autovacuum freeze max age |
| `topsrv_pg_longest_transaction_seconds` | gauge | database, usename | Age of longest running transactions (top 5) |
| `topsrv_pg_query_time_seconds_total` | counter | queryid, query, database | Total query execution time. Union of top-20 by `total_time`, `calls`, `blks_read`, `blks_dirtied`, and `wal_bytes` (PG13+) — covers both read-heavy and write-heavy workloads |
| `topsrv_pg_query_calls_total` | counter | queryid, query, database | Query call count |
| `topsrv_pg_query_rows_total` | counter | queryid, query, database | Rows returned by query |
| `topsrv_pg_query_blks_hit_total` | counter | queryid, query, database | Shared blocks hit |
| `topsrv_pg_query_blks_read_total` | counter | queryid, query, database | Shared blocks read |
| `topsrv_pg_query_blks_dirtied_total` | counter | queryid, query, database | Shared blocks dirtied |
| `topsrv_pg_query_blk_read_time_seconds_total` | counter | queryid, query, database | Block read time |
| `topsrv_pg_query_blk_write_time_seconds_total` | counter | queryid, query, database | Block write time |
| `topsrv_pg_query_temp_blks_read_total` | counter | queryid, query, database | Temp blocks read |
| `topsrv_pg_query_temp_blks_written_total` | counter | queryid, query, database | Temp blocks written |
| `topsrv_pg_query_wal_bytes_total` | counter | queryid, query, database | WAL bytes generated |
| `topsrv_pg_query_duration_seconds` | histogram | — | Per-query mean execution time distribution |
| `topsrv_pg_table_size_bytes` | gauge | database, schema, table | Total table size |
| `topsrv_pg_table_seq_scan_total` | counter | database, schema, table | Sequential scans |
| `topsrv_pg_table_seq_tup_read_total` | counter | database, schema, table | Sequential tuples read |
| `topsrv_pg_table_idx_scan_total` | counter | database, schema, table | Index scans |
| `topsrv_pg_table_tup_total` | counter | database, schema, table, op | Tuple operations (insert/update/delete) |
| `topsrv_pg_table_tuples` | gauge | database, schema, table, state | Tuples by state (live/dead) |
| `topsrv_pg_table_autovacuum_count_total` | counter | database, schema, table | Autovacuum runs per table |
| `topsrv_pg_table_last_maintenance_timestamp_seconds` | gauge | database, schema, table, op | Unix time of last VACUUM/ANALYZE (manual or auto). `op="vacuum\|analyze"`. Alert: `time() - metric > 86400` |
| `topsrv_pg_table_mod_since_analyze` | gauge | database, schema, table | Rows modified since last ANALYZE. Growing value = planner stats getting stale |
| `topsrv_pg_index_scans_total` | counter | database, schema, table, index | Index scans (pg_stat_user_indexes). `idx_scan=0` over long period = unused index |
| `topsrv_pg_index_size_bytes` | gauge | database, schema, table, index | Index size in bytes |
| `topsrv_pg_table_bloat_size_bytes` | gauge | database, schema, table | Estimated wasted bytes in table heap (ioguix heuristic). Top 50 by bloat size. Refreshed every 15 min. `>30%` typically worth `pg_repack` / `CLUSTER` |
| `topsrv_pg_table_bloat_pct` | gauge | database, schema, table | Estimated table bloat percentage (0–100) |
| `topsrv_pg_index_bloat_size_bytes` | gauge | database, schema, table, index | Estimated wasted bytes in btree index (ioguix heuristic). Top 50. Refreshed every 15 min |
| `topsrv_pg_index_bloat_pct` | gauge | database, schema, table, index | Estimated index bloat percentage (0–100). `>50%` worth `REINDEX CONCURRENTLY` |
| `topsrv_pg_setting` | gauge | name | Selected GUCs (shared_buffers, effective_cache_size, work_mem, maintenance_work_mem, max_wal_size, min_wal_size, checkpoint_timeout, wal_buffers, random_page_cost). Normalized: memory/WAL in bytes, time in seconds |
| `topsrv_pg_stats_reset_timestamp_seconds` | gauge | scope | Unix time of last pg_stat_* reset. `scope=database` (oldest across DBs), `bgwriter`, `wal` (PG17+), `archiver` (if `archive_mode=on`) |

## Nginx (`topsrv_nginx_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_nginx_up` | gauge | — | Nginx reachable (0/1) |
| `topsrv_nginx_connections` | gauge | state | Connections (active/reading/writing/waiting) |
| `topsrv_nginx_connections_accepted_total` | counter | — | Total accepted connections |
| `topsrv_nginx_connections_handled_total` | counter | — | Total handled connections |
| `topsrv_nginx_requests_total` | counter | — | Total requests (stub_status) |
| `topsrv_nginx_request_duration_seconds` | histogram | — | Request duration |
| `topsrv_nginx_upstream_duration_seconds` | histogram | — | Upstream response time |
| `topsrv_nginx_http_requests_total` | counter | status, +extra_labels | Requests by status code |
| `topsrv_nginx_cache_requests_total` | counter | status | Cache status (HIT/MISS/EXPIRED) |
| `topsrv_nginx_5xx_requests_total` | counter | status, uri | 5xx errors with normalized URI |
| `topsrv_nginx_4xx_requests_total` | counter | status, uri | 4xx errors with normalized URI |
| `topsrv_nginx_response_bytes_total` | counter | — | Total response bytes |
| `topsrv_nginx_response_bytes_by_uri_total` | counter | uri | Response bytes by normalized URI |

## S.M.A.R.T. (`topsrv_smart_*`)

Always enabled. Requires `CAP_SYS_RAWIO` + `CAP_SYS_ADMIN` or root. Devices auto-discovered from `/sys/block/`. Default polling interval: 5 minutes. Disable with `[Smart] Disabled = true`.

### Common (all device types)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_smart_device_info` | gauge | device, type, model, serial, firmware | Device metadata (value=1) |
| `topsrv_smart_device_healthy` | gauge | device | Overall health: 1=healthy, 0=unhealthy |
| `topsrv_smart_device_temperature_celsius` | gauge | device | Device temperature |
| `topsrv_smart_device_power_on_hours` | gauge | device | Total power-on hours |
| `topsrv_smart_device_bytes_written_total` | gauge | device | Total bytes written |

### ATA/SATA critical attributes

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_smart_attr_raw_value` | gauge | device, id, name | Critical attribute raw value |

Only critical attribute IDs are exported: 5 (Reallocated Sectors), 187 (Reported Uncorrectable), 188 (Command Timeout), 197 (Pending Sector), 198 (Offline Uncorrectable), 171 (Program Fail), 172 (Erase Fail), 173/177 (Wear Leveling), 202/233 (Lifetime Remain / Media Wearout).

### NVMe

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_smart_nvme_critical_warning` | gauge | device | Critical warning bitmask |
| `topsrv_smart_nvme_available_spare_percent` | gauge | device | Available spare capacity % |
| `topsrv_smart_nvme_available_spare_threshold_percent` | gauge | device | Available spare threshold % |
| `topsrv_smart_nvme_percentage_used` | gauge | device | Estimated % of life used (can exceed 100) |
| `topsrv_smart_nvme_media_errors_total` | gauge | device | Media and data integrity errors |
| `topsrv_smart_nvme_unsafe_shutdowns_total` | gauge | device | Unsafe shutdown count |
| `topsrv_smart_nvme_warning_temp_time_minutes` | gauge | device | Minutes above warning temp |
| `topsrv_smart_nvme_critical_temp_time_minutes` | gauge | device | Minutes above critical temp |

## SSL Certificates (`topsrv_ssl_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_ssl_certificate_expiry_seconds` | gauge | path, cn, issuer | Certificate NotAfter as Unix timestamp |

Auto-discovered from `ssl_certificate` directives in nginx/angie config. Re-read every 5 minutes.

## Angie (`topsrv_angie_*`)

Metrics from Angie JSON API (`/status/`). Requires `api /status/;` directive in Angie config.

### Connections

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_angie_up` | gauge | — | Angie API reachable (0/1) |
| `topsrv_angie_connections_accepted_total` | counter | — | Total accepted connections |
| `topsrv_angie_connections_dropped_total` | counter | — | Total dropped connections |
| `topsrv_angie_connections_active` | gauge | — | Active connections |
| `topsrv_angie_connections_idle` | gauge | — | Idle connections |

### HTTP Server Zones

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_angie_server_zone_requests_total` | counter | zone | Total requests |
| `topsrv_angie_server_zone_requests_processing` | gauge | zone | Requests in processing |
| `topsrv_angie_server_zone_requests_discarded_total` | counter | zone | Discarded requests |
| `topsrv_angie_server_zone_responses_total` | counter | zone, code | Responses by HTTP status code |
| `topsrv_angie_server_zone_received_bytes_total` | counter | zone | Bytes received |
| `topsrv_angie_server_zone_sent_bytes_total` | counter | zone | Bytes sent |
| `topsrv_angie_server_zone_ssl_handshakes_total` | counter | zone | Successful SSL handshakes |
| `topsrv_angie_server_zone_ssl_failed_total` | counter | zone | Failed SSL handshakes |

### HTTP Upstreams

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_angie_upstream_peer_state` | gauge | upstream, peer | Peer state (1=up, 2=down, 3=unavailable, 4=recovering, 5=busy) |
| `topsrv_angie_upstream_peer_requests_total` | counter | upstream, peer | Total requests to peer |
| `topsrv_angie_upstream_peer_requests_current` | gauge | upstream, peer | Current requests to peer |
| `topsrv_angie_upstream_peer_responses_total` | counter | upstream, peer, code | Responses by HTTP status code |
| `topsrv_angie_upstream_peer_sent_bytes_total` | counter | upstream, peer | Bytes sent to peer |
| `topsrv_angie_upstream_peer_received_bytes_total` | counter | upstream, peer | Bytes received from peer |
| `topsrv_angie_upstream_peer_health_fails_total` | counter | upstream, peer | Health check failures |
| `topsrv_angie_upstream_peer_health_downtime_seconds_total` | counter | upstream, peer | Total downtime |
| `topsrv_angie_upstream_keepalive` | gauge | upstream | Keepalive connections |

### HTTP Caches

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_angie_cache_size_bytes` | gauge | zone | Current cache size |
| `topsrv_angie_cache_responses_total` | counter | zone, status | Cache responses (hit/stale/updating/revalidated/miss/expired/bypass) |
| `topsrv_angie_cache_bytes_total` | counter | zone, status | Cache bytes (hit/stale/updating/revalidated/miss/expired/bypass) |

### Rate Limiting

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_angie_limit_conns_total` | counter | zone, status | Connection limiting (passed/skipped/rejected/exhausted) |
| `topsrv_angie_limit_reqs_total` | counter | zone, status | Request limiting (passed/skipped/delayed/rejected/exhausted) |

### Shared Memory

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_angie_slab_pages` | gauge | zone, state | Slab pages (used/free) |

## Bot-logs (`topsrv_botlog_*`)

Opt-in. Emitted when `[BotLogs].Enabled = true`. The agent matches every parsed nginx access-log line against a built-in UA fingerprint table (38 families) and ships matched events as gzipped ndjson to the topsrv.io `/v1/bot-logs` endpoint, with disk-backed WAL spool for retry on transient send failures.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_botlog_events_total` | counter | state, reason | Event lifecycle counts. `state=enqueued` (entered queue), `sent` (acked by ingest), `spooled` (written to WAL after transient failure), `dropped` (`reason` splits cause). For non-dropped states `reason=""`. For `state=dropped` the `reason` label is one of `queue_full` (Enqueue while queue full → raise `BatchSize`), `permanent` (4xx, payload bad), `spool_write` (mkdir/write/missing SpoolDir), `spool_evict` (trim by `MaxSpoolMB` or foreign-owned file). |
| `topsrv_botlog_match_total` | counter | family | UA matches by family (`google`, `yandex`, `mailru`, `bing`, `openai`, `anthropic`, `ahrefs`, `semrush`, `bytespider`, ...). Use rate to spot crawl bursts per vendor |
| `topsrv_botlog_send_errors_total` | counter | kind | Failed ingest requests by kind: `connect` (dial/DNS), `timeout` (request timeout), `status` (HTTP ≥ 400) |
| `topsrv_botlog_batch_duration_seconds` | histogram | — | End-to-end batch flush latency (encode + HTTP send) |
| `topsrv_botlog_queue_depth` | gauge | — | Events currently buffered in the send queue. Capacity is `BatchSize*2`. |
| `topsrv_botlog_spool_files` | gauge | — | Pending spool files awaiting retry |
| `topsrv_botlog_spool_bytes` | gauge | — | Disk bytes used by the spool subdir. Alert when approaching `MaxSpoolMB` |

Alerting guidance:
- `rate(topsrv_botlog_send_errors_total{kind="connect"}[5m]) > 0` — ingest endpoint unreachable
- `topsrv_botlog_spool_bytes > 0.8 * MaxSpoolMB * 1048576` — spool filling up, retries failing
- `topsrv_botlog_queue_depth > 0.7 * (2 * <BatchSize>)` for 5 m — backpressure approaching; raise `BatchSize` or shorten `BatchInterval` before drops start
- Split the `dropped` alert by `reason` — each maps to a different fix:
  - `rate(topsrv_botlog_events_total{state="dropped", reason="queue_full"}[5m]) > 0` — agent can't keep up; raise `BatchSize` or shorten `BatchInterval`
  - `rate(topsrv_botlog_events_total{state="dropped", reason="permanent"}[5m]) > 0` — receiver returning 4xx; inspect payload/auth
  - `rate(topsrv_botlog_events_total{state="dropped", reason="spool_write"}[5m]) > 0` — `SpoolDir` unwritable or full; check disk and permissions
  - `rate(topsrv_botlog_events_total{state="dropped", reason="spool_evict"}[5m]) > 0` — WAL budget exceeded; raise `MaxSpoolMB` or investigate why receiver isn't catching up
- `rate(topsrv_botlog_events_total{state="sent"}[5m]) == 0` while `match_total` grows — pipeline stuck between observer and ingest

## Self-monitoring (`topsrv_collector_*`)

Per-collector instrumentation. Any collector registered via `addCollector` is wrapped to record its last scrape duration and recover from panics without breaking `/metrics`.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `topsrv_collector_scrape_duration_seconds` | gauge | collector | Last scrape duration. Alert: `> 5s` = monitoring is adding overhead to the target |
| `topsrv_collector_scrape_panics_total` | counter | collector | Panics recovered during Collect. Any non-zero rate = bug, page immediately |
