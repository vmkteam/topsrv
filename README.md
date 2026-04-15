# topsrv

Server monitoring agent. Single binary replaces node_exporter + postgres_exporter + process-exporter + nginx-exporter. Auto-discovery, Prometheus-compatible metrics.

## Install

```bash
curl -fsSL https://topsrv.io/install.sh | TOPSRV_TOKEN=xxx sudo -E bash
```

Options via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TOPSRV_TOKEN` | — | Push token |
| `TOPSRV_ENDPOINT` | `https://push.topsrv.io/v1/write` | Push endpoint |
| `VERSION` | latest | Specific version to install |
| `INSTALL_DIR` | `/usr/local/bin` | Binary install path |

**Manual install:**

```bash
# Download from https://github.com/vmkteam/topsrv/releases
tar -xzf topsrv_*_linux_amd64.tar.gz
sudo install -m 0755 topsrv /usr/local/bin/
```

## Quick start

**Run:**

```bash
# Scrape mode — Prometheus pulls /metrics
topsrv -config /etc/topsrv/topsrv.toml -verbose

curl localhost:9100/metrics
```

**Minimal config** (`/etc/topsrv/topsrv.toml`):

```toml
[Server]
Listen = ":9100"
```

That's it. System, disk, network, netstat, process, and S.M.A.R.T. metrics are collected automatically. PostgreSQL and Nginx are auto-discovered if running.

## Features

| Collector | Metrics | Replaces |
|-----------|---------|----------|
| **System** | CPU per-core, memory, load, swap, uptime, host info, context switches | node_exporter |
| **Disk** | IO (read/write bytes/ops/time), filesystem (space/inodes) | node_exporter |
| **Network** | IO per interface, interface info (MAC/IP/MTU/status) | node_exporter |
| **Netstat** | TCP connections by state/direction/port, TCP retransmits, UDP/IP errors | node_exporter |
| **Process** | CPU, memory, disk IO, threads, FDs, worst_fd_ratio per process group | process-exporter |
| **PostgreSQL** | Connections (by state/addr/app), transactions, longest transaction age, checkpoints, bgwriter, locks, replication, WAL, wraparound, pg_stat_statements, tables (top 50) | postgres_exporter |
| **Nginx** | stub_status, access log parsing (text & JSON log_format, response time histogram, status codes, cache, 4xx/5xx URIs, bytes by URI) | nginx-exporter + mtail |
| **Angie** | JSON API (server zones, upstreams, SSL, caches, rate limiting, slabs) + access log parsing | — |
| **S.M.A.R.T.** | Disk health (ATA attributes, NVMe health log, temperature, wear, errors) | smartctl_exporter |
| **SSL Certificates** | Certificate expiry monitoring (auto-discovered from nginx/angie config) | — |

## Auto-discovery

On startup topsrv scans running processes and detects known services — no configuration needed:

| Process | Type | Action |
|---------|------|--------|
| `postgres` / `postmaster` | postgresql | Logs hint to add DSN |
| `nginx` | nginx | Parses nginx.conf → finds log_format + access_log |
| `angie` | angie | Parses angie.conf → finds api /status/, log_format + access_log |
| `redis-server` | redis | Detected |
| `pgbouncer` | pgbouncer | Detected |
| `php-fpm` | php-fpm | Detected |

For Nginx, auto-discovery parses `nginx.conf` including `include` directives, extracts `log_format` and `access_log` paths with `$request_time`. Both text and JSON (`escape=json`) log formats are auto-detected.

## Configuration

### Operating modes

**Pull mode** (default) — Prometheus scrapes `/metrics`:

```toml
[Server]
Listen = ":9100"
```

**Push mode** — agent pushes metrics to [topsrv.io](https://topsrv.io), VictoriaMetrics, or any compatible remote-write endpoint:

```toml
[Push]
Endpoint = "https://push.topsrv.io/v1/write"   # or your VictoriaMetrics URL
Token    = "ts_xxx"         # get your token at https://topsrv.io
Interval = "30s"
SpoolDir = "/var/lib/topsrv/spool"   # disk buffer for retries on network failure
```

**Push-only mode** — no HTTP server, only push. Omit `[Server]` or set `Listen = ""`.

Both modes can work simultaneously.

### Full reference

```toml
[Server]
Listen = ":9100"            # Prometheus /metrics endpoint

[Push]
Endpoint = ""               # Push URL
Token    = ""               # Bearer token for push auth
Interval = "30s"            # Push interval
SpoolDir = ""               # Disk buffer for retries

[Update]
Enabled  = false            # Auto-update via control plane
Interval = "15m"            # Check interval
Channel  = "stable"         # stable / beta

# PostgreSQL (optional — auto-discovery detects the process, DSN needed for connection)
# [Postgres]
# DSN = "postgres://topsrv:pass@localhost:5432/postgres?sslmode=disable"

# Nginx (optional — auto-discovery parses nginx.conf automatically)
# [Nginx]
# StubStatusURL = "http://127.0.0.1/stub_status"
# LogFormat     = '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time $upstream_response_time'
# ExtraLabels   = ["server_name"]
# AccessLogs    = ["/var/log/nginx/access.log"]

# Angie (optional — auto-discovery parses angie.conf automatically)
# [Angie]
# StatusURL     = "http://127.0.0.1:8080/status/"
# StubStatusURL = "http://127.0.0.1/stub_status"
# LogFormat     = '$remote_addr ...'
# ExtraLabels   = ["server_name"]
# AccessLogs    = ["/var/log/angie/access.log"]

# S.M.A.R.T. disk health (always enabled, requires CAP_SYS_RAWIO + CAP_SYS_ADMIN)
# [Smart]
# Disabled = true    # set to disable
# Interval = "5m"
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `Server.Listen` | `:9100` | HTTP listen address for /metrics |
| `Push.Endpoint` | — | Remote write URL |
| `Push.Token` | — | Bearer token |
| `Push.Interval` | `30s` | Push frequency |
| `Push.SpoolDir` | — | Disk spool path (retries on network failure) |
| `Update.Enabled` | `false` | Enable auto-update |
| `Update.Interval` | `15m` | Update check interval |
| `Update.Channel` | `stable` | Update channel (stable/beta) |
| `Postgres.DSN` | — | PostgreSQL connection string |
| `Nginx.StubStatusURL` | — | nginx stub_status URL |
| `Nginx.LogFormat` | — | nginx log_format string (gonx format) |
| `Nginx.ExtraLabels` | `[]` | Log fields to add as metric labels |
| `Nginx.AccessLogs` | `[]` | Paths to access log files |
| `Angie.StatusURL` | — | Angie JSON API URL (e.g. `http://127.0.0.1:8080/status/`) |
| `Angie.StubStatusURL` | — | Fallback stub_status URL |
| `Angie.LogFormat` | — | angie log_format string (gonx format) |
| `Angie.ExtraLabels` | `[]` | Log fields to add as metric labels |
| `Angie.AccessLogs` | `[]` | Paths to access log files |
| `Smart.Disabled` | `false` | Disable S.M.A.R.T. collector |
| `Smart.Interval` | `5m` | S.M.A.R.T. polling interval |

### Environment variables

All config flags can be set via environment variables with `TOPSRV_` prefix:

```bash
TOPSRV_CONFIG=/etc/topsrv/topsrv.toml topsrv
```

## PostgreSQL

Supports **PG15+** (PG17: `pg_stat_checkpointer`).

14 SQL queries cover all monitoring needs:
- Connections (by state, by client_addr, max)
- Transactions, deadlocks, temp files per database
- Checkpoints, bgwriter, buffers
- Autovacuum workers (common vs wraparound)
- Locks by mode
- Replication (lag bytes/seconds, slots, streaming status)
- Database sizes
- WAL (position, files count via `pg_ls_waldir()`)
- Wraparound (xid_age vs freeze_max_age)
- pg_stat_statements — union of top 20 by time, calls, and blocks read (~40-60 unique queries), duration histogram, WAL bytes (optional, skipped if extension absent)
- Tables — top 50 by size (seq/idx scans, tuple ops, dead tuples, autovacuum count)

### Setup

**1. Create a monitoring role.** The built-in `pg_monitor` role (PG10+) grants read access to all statistics views and functions including `pg_ls_waldir()` — no custom functions or schemas needed:

```sql
sudo -u postgres psql -d postgres

CREATE ROLE topsrv LOGIN PASSWORD 'CHANGE_ME';
GRANT pg_monitor TO topsrv;
```

**2. Allow connections** in `pg_hba.conf`:

```
# local agent (typical setup)
host all topsrv 127.0.0.1/32 scram-sha-256
local all topsrv scram-sha-256
```

Reload config:

```sql
SELECT pg_reload_conf();
```

**3. Configure topsrv** — add DSN to config:

```toml
[Postgres]
DSN = "postgres://topsrv:CHANGE_ME@localhost:5432/postgres?sslmode=disable"
```

**4. (Optional) Enable pg_stat_statements** for query-level metrics (top 20 queries, duration histogram):

Add to `postgresql.conf`:

```ini
shared_preload_libraries = 'pg_stat_statements'   # requires restart
pg_stat_statements.max = 500
pg_stat_statements.track = top
track_io_timing = on                               # recommended for block read/write time
```

Restart PostgreSQL, then create the extension **in the same database** that topsrv connects to (the one specified in `Postgres.DSN`):

```sql
-- connect to the database from DSN (e.g. postgres)
\c postgres
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
GRANT SELECT ON pg_stat_statements TO topsrv;
```

> **Note:** `pg_stat_statements` view is only visible in the database where the extension is created. If your DSN points to `mydb`, run `CREATE EXTENSION` in `mydb`, not in `postgres`. The `topsrv` role also needs an explicit `SELECT` grant on the view — `pg_monitor` alone is not sufficient.

If `pg_stat_statements` is not installed, topsrv silently skips query metrics — everything else works.


## Nginx

Two collectors:

**stub_status** — connections, requests, `nginx_up` (0/1).

**access log** — tail + parsing via configurable `LogFormat`. Supports both text (gonx) and JSON (`escape=json`) formats:
- `topsrv_nginx_request_duration_seconds` — histogram (buckets: 5ms…10s)
- `topsrv_nginx_upstream_duration_seconds` — upstream histogram
- `topsrv_nginx_http_requests_total{status}` — by status code
- `topsrv_nginx_cache_requests_total{status}` — HIT/MISS/EXPIRED
- `topsrv_nginx_5xx_requests_total{status,uri}` — 5xx with URL normalization (`/users/123` → `/users/:id`)
- `topsrv_nginx_4xx_requests_total{status,uri}` — 4xx with URL normalization
- `topsrv_nginx_response_bytes_total` — total response bytes
- `topsrv_nginx_response_bytes_by_uri_total{uri}` — response bytes by normalized URI
- **Custom labels** — `ExtraLabels` adds log fields as metric labels (server_name, http_platform, etc.)

**SSL certificates** — auto-discovered `ssl_certificate` paths from config, expiry as Unix timestamp gauge. Re-reads every 5 minutes to detect Let's Encrypt renewals.

## Angie

Angie (nginx fork) is supported with a dedicated JSON API collector providing detailed per-zone, per-upstream, SSL, cache, and rate limiting metrics — features not available in nginx free.

Three collectors:

**JSON API** (`/status/`) — connections, server zones, upstreams (per-peer state, health, requests), caches, rate limiting, shared memory slabs. Requires `api /status/;` directive in Angie config.

**stub_status** — fallback when API is not configured (same 7 metrics as nginx).

**access log** — same as nginx: request duration histogram, status codes, cache status, 4xx/5xx by URI, bytes by URI.

Auto-discovery parses `angie.conf` and detects both `api /status/;` and `stub_status` directives. If Angie API is available, it takes priority over stub_status.

### Angie config for monitoring

```nginx
http {
    server {
        listen 80;
        server_name example.com;
        status_zone http_main;        # enable per-zone metrics

        location / {
            proxy_pass http://backend;
        }
    }

    upstream backend {
        zone backend_zone 64k;        # required for upstream metrics
        server 10.0.0.1:8080;
    }

    server {
        listen 127.0.0.1:8080;
        location /status/ {
            api /status/;
            allow 127.0.0.1;
            deny all;
        }
    }
}
```

## Metrics reference

Full list of all metrics: [docs/metrics.md](docs/metrics.md)

## Development

Requires `GOEXPERIMENT=jsonv2` (set automatically by Makefile and goreleaser).

```bash
make build              # Build binary
make test               # Unit tests
make test-integration   # Integration tests (requires Docker)
make fmt                # Format code (golangci-lint fmt)
make lint               # Lint (golangci-lint run)
make run                # Run with local config
make demo               # Start demo (VictoriaMetrics + topsrv)
```

**From source**:

```bash
git clone https://github.com/vmkteam/topsrv.git
cd topsrv
make build
sudo install -m 0755 bin/topsrv /usr/local/bin/
```

## License

Apache-2.0
