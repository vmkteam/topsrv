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
| `topsrv_host_info` | gauge | hostname, os, platform, platform_version, kernel_version, kernel_arch | Host metadata |
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
| `topsrv_pg_locks` | gauge | mode | Locks by mode |
| `topsrv_pg_replication_lag_bytes` | gauge | client_addr | Replication lag in bytes |
| `topsrv_pg_replication_lag_seconds` | gauge | client_addr | Replication lag in seconds |
| `topsrv_pg_replication_slot_retained_bytes` | gauge | slot | WAL retained by slot |
| `topsrv_pg_replication_streaming` | gauge | client_addr | Streaming status (0/1) |
| `topsrv_pg_database_size_bytes` | gauge | database | Database size |
| `topsrv_pg_wal_bytes` | counter | — | WAL position in bytes |
| `topsrv_pg_wal_files` | gauge | — | WAL file count |
| `topsrv_pg_wraparound_xid_age` | gauge | database | Transaction ID age |
| `topsrv_pg_wraparound_max_age` | gauge | — | Autovacuum freeze max age |
| `topsrv_pg_query_time_seconds_total` | counter | queryid, query | Total query execution time |
| `topsrv_pg_query_calls_total` | counter | queryid, query | Query call count |
| `topsrv_pg_query_rows_total` | counter | queryid, query | Rows returned by query |
| `topsrv_pg_query_blks_hit_total` | counter | queryid, query | Shared blocks hit |
| `topsrv_pg_query_blks_read_total` | counter | queryid, query | Shared blocks read |
| `topsrv_pg_query_blks_dirtied_total` | counter | queryid, query | Shared blocks dirtied |
| `topsrv_pg_query_blk_read_time_seconds_total` | counter | queryid, query | Block read time |
| `topsrv_pg_query_blk_write_time_seconds_total` | counter | queryid, query | Block write time |
| `topsrv_pg_query_temp_blks_read_total` | counter | queryid, query | Temp blocks read |
| `topsrv_pg_query_temp_blks_written_total` | counter | queryid, query | Temp blocks written |
| `topsrv_pg_query_duration_seconds` | histogram | — | Per-query mean execution time distribution |
| `topsrv_pg_table_size_bytes` | gauge | schema, table | Total table size |
| `topsrv_pg_table_seq_scan_total` | counter | schema, table | Sequential scans |
| `topsrv_pg_table_seq_tup_read_total` | counter | schema, table | Sequential tuples read |
| `topsrv_pg_table_idx_scan_total` | counter | schema, table | Index scans |
| `topsrv_pg_table_tup_total` | counter | schema, table, op | Tuple operations (insert/update/delete) |
| `topsrv_pg_table_tuples` | gauge | schema, table, state | Tuples by state (live/dead) |
| `topsrv_pg_table_autovacuum_count_total` | counter | schema, table | Autovacuum runs per table |

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
