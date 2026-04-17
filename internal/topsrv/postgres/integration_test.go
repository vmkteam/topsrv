//go:build integration

package postgres

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func pgDSN() string {
	if v := os.Getenv("TEST_PG_DSN"); v != "" {
		return v
	}
	return "postgres://topsrv:topsrv@127.0.0.1:15432/testdb?sslmode=disable"
}

func TestIntegrationPostgres(t *testing.T) {
	dsn := pgDSN()
	logger := embedlog.Logger{}

	// Seed pg_stat_statements: run the same query from different users and databases
	// so that (userid, dbid, queryid) produces duplicate queryids that must be aggregated.
	seedStatStatements(t)

	c, err := NewCollector(logger, dsn)
	require.NoError(t, err, "failed to create postgres collector with DSN: %s", dsn)

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	_, err = reg.Gather()
	require.NoError(t, err)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, mfs, "postgres collector returned no metrics")

	names := map[string]bool{}
	mfMap := map[string]*io_prometheus_client.MetricFamily{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
		mfMap[mf.GetName()] = mf
	}

	for _, name := range []string{
		"topsrv_pg_connections",
		"topsrv_pg_connections_by_app",
		"topsrv_pg_longest_transaction_seconds",
		"topsrv_pg_database_size_bytes",
		"topsrv_pg_xact_total",
		"topsrv_pg_locks",
	} {
		assert.True(t, names[name], "missing metric: %s", name)
	}

	if mf, ok := mfMap["topsrv_pg_connections_by_app"]; ok {
		for _, m := range mf.GetMetric() {
			labelNames := map[string]bool{}
			for _, lp := range m.GetLabel() {
				labelNames[lp.GetName()] = true
			}
			assert.True(t, labelNames["application_name"], "connections_by_app missing 'application_name' label")
			assert.True(t, labelNames["state"], "connections_by_app missing 'state' label")
		}
	}

	if mf, ok := mfMap["topsrv_pg_longest_transaction_seconds"]; ok {
		for _, m := range mf.GetMetric() {
			labelNames := map[string]bool{}
			for _, lp := range m.GetLabel() {
				labelNames[lp.GetName()] = true
			}
			assert.True(t, labelNames["database"], "longest_transaction_seconds missing 'database' label")
			assert.True(t, labelNames["usename"], "longest_transaction_seconds missing 'usename' label")
		}
	}

	if mf, ok := mfMap["topsrv_pg_connections"]; ok {
		hasBgWorker := false
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "state" && lp.GetValue() == "background worker" {
					hasBgWorker = true
				}
			}
		}
		assert.True(t, hasBgWorker, "connections missing 'background worker' state")
	}

	stmtMetrics := []string{
		"topsrv_pg_query_time_seconds_total",
		"topsrv_pg_query_calls_total",
		"topsrv_pg_query_rows_total",
		"topsrv_pg_query_blk_read_time_seconds_total",
		"topsrv_pg_query_blk_write_time_seconds_total",
	}
	for _, name := range append(stmtMetrics, "topsrv_pg_query_duration_seconds") {
		assert.True(t, names[name], "missing pg_stat_statements metric: %s", name)
	}

	for _, name := range stmtMetrics {
		mf, ok := mfMap[name]
		if !ok {
			continue
		}
		for _, m := range mf.GetMetric() {
			labelNames := map[string]bool{}
			for _, lp := range m.GetLabel() {
				labelNames[lp.GetName()] = true
			}
			assert.True(t, labelNames["database"], "%s metric missing 'database' label", name)
			assert.True(t, labelNames["queryid"], "%s metric missing 'queryid' label", name)
			assert.True(t, labelNames["query"], "%s metric missing 'query' label", name)
		}
	}

	if mf, ok := mfMap["topsrv_pg_locks"]; ok {
		for _, m := range mf.GetMetric() {
			labelNames := map[string]bool{}
			for _, lp := range m.GetLabel() {
				labelNames[lp.GetName()] = true
			}
			assert.True(t, labelNames["mode"], "locks missing 'mode' label")
			assert.True(t, labelNames["granted"], "locks missing 'granted' label")
		}
	}

	for _, name := range []string{"topsrv_pg_blocked_backends", "topsrv_pg_lock_wait_seconds_max"} {
		assert.True(t, names[name], "missing lock-wait metric: %s", name)
	}

	for _, name := range []string{
		"topsrv_pg_wal_records_total",
		"topsrv_pg_wal_fpi_total",
		"topsrv_pg_wal_buffers_full_total",
		"topsrv_pg_wal_io_time_seconds_total",
	} {
		assert.True(t, names[name], "missing pg_stat_wal metric: %s", name)
	}
	if mf, ok := mfMap["topsrv_pg_wal_io_time_seconds_total"]; ok {
		ops := map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "op" {
					ops[lp.GetValue()] = true
				}
			}
		}
		assert.True(t, ops["write"], "wal_io_time missing op=write")
		assert.True(t, ops["sync"], "wal_io_time missing op=sync")
	}

	assert.True(t, names["topsrv_pg_wait_events"], "missing topsrv_pg_wait_events")
	if mf, ok := mfMap["topsrv_pg_wait_events"]; ok {
		required := []string{"backend_type", "datname", "application_name", "wait_event_type", "wait_event", "state"}
		for _, m := range mf.GetMetric() {
			labelNames := map[string]bool{}
			for _, lp := range m.GetLabel() {
				labelNames[lp.GetName()] = true
			}
			for _, lbl := range required {
				assert.True(t, labelNames[lbl], "wait_events missing %q label", lbl)
			}
		}
	}

	assert.True(t, c.hasToplevel, "hasToplevel should be true on PG14+ with modern pg_stat_statements")

	if mf, ok := mfMap["topsrv_pg_replication_lag_seconds"]; ok {
		for _, m := range mf.GetMetric() {
			labelNames := map[string]bool{}
			for _, lp := range m.GetLabel() {
				labelNames[lp.GetName()] = true
			}
			assert.True(t, labelNames["stage"], "replication_lag_seconds missing 'stage' label")
		}
	}

	for _, name := range []string{"topsrv_pg_index_scans_total", "topsrv_pg_index_size_bytes"} {
		assert.True(t, names[name], "missing index metric: %s", name)
		if mf, ok := mfMap[name]; ok {
			for _, m := range mf.GetMetric() {
				labelNames := map[string]bool{}
				for _, lp := range m.GetLabel() {
					labelNames[lp.GetName()] = true
				}
				assert.True(t, labelNames["database"], "%s missing database label", name)
				assert.True(t, labelNames["schema"], "%s missing schema label", name)
				assert.True(t, labelNames["table"], "%s missing table label", name)
				assert.True(t, labelNames["index"], "%s missing index label", name)
			}
		}
	}

	assert.True(t, names["topsrv_pg_setting"], "missing topsrv_pg_setting")
	if mf, ok := mfMap["topsrv_pg_setting"]; ok {
		seen := map[string]float64{}
		for _, m := range mf.GetMetric() {
			var name string
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "name" {
					name = lp.GetValue()
				}
			}
			seen[name] = m.GetGauge().GetValue()
		}
		for _, g := range settingsList {
			_, ok := seen[g]
			assert.True(t, ok, "settings missing %q", g)
		}
		assert.Greater(t, seen["shared_buffers"], 1024*1024.0, "shared_buffers should be >1MB in bytes")
	}

	if mf, ok := mfMap["topsrv_pg_stats_reset_timestamp_seconds"]; ok {
		scopes := map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "scope" {
					scopes[lp.GetValue()] = true
				}
			}
		}
		assert.True(t, scopes["bgwriter"], "stats_reset missing scope=bgwriter")
	}

	if mf, ok := mfMap["topsrv_pg_table_size_bytes"]; ok {
		for _, m := range mf.GetMetric() {
			hasDB := false
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "database" {
					hasDB = true
					assert.NotEmpty(t, lp.GetValue(), "database label is empty")
				}
			}
			assert.True(t, hasDB, "table_size_bytes missing database label")
		}
	}

	assert.True(t, names["topsrv_pg_table_mod_since_analyze"], "missing mod_since_analyze")
	if mf, ok := mfMap["topsrv_pg_table_last_maintenance_timestamp_seconds"]; ok {
		ops := map[string]bool{}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "op" {
					ops[lp.GetValue()] = true
				}
			}
		}
		assert.True(t, ops["vacuum"] || ops["analyze"], "last_maintenance has neither vacuum nor analyze op")
	}

	assert.False(t, c.archiveEnabled, "archive_mode should be off in test env")
	assert.False(t, names["topsrv_pg_archiver_total"], "archiver_total should not be emitted when archive_mode=off")

	t.Logf("postgres integration: %d metric families", len(mfs))

	meta := c.QueryMeta()
	require.NotEmpty(t, meta, "QueryMeta returned no entries")

	for _, m := range meta {
		assert.NotEmpty(t, m.QueryID, "QueryMeta entry has empty queryid")
		assert.NotEmpty(t, m.Database, "QueryMeta entry has empty database")
		assert.NotEmpty(t, m.Query, "QueryMeta entry has empty query")
	}

	t.Logf("QueryMeta: %d entries, first db=%s queryid=%s query_len=%d", len(meta), meta[0].Database, meta[0].QueryID, len(meta[0].Query))

	testAppName(t, c, reg)
}

// testAppName verifies that application_name from pg_stat_activity is captured in QueryMeta.
func testAppName(t *testing.T, c *Collector, reg *prometheus.Registry) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	appDSN := pgDSN() + "&application_name=test_app_ci"
	appPool, err := pgxpool.New(ctx, appDSN)
	require.NoError(t, err)
	defer appPool.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = appPool.Exec(ctx, "SELECT pg_sleep(2)")
	}()

	time.Sleep(200 * time.Millisecond)

	_, err = reg.Gather()
	require.NoError(t, err)

	<-done

	c.appNamesMu.RLock()
	var foundQid int64
	var found bool
	mapSize := len(c.appNames)
	for qid, apps := range c.appNames {
		if apps["test_app_ci"] {
			found = true
			foundQid = qid
			break
		}
	}
	c.appNamesMu.RUnlock()
	assert.True(t, found, "expected appNames to contain 'test_app_ci'")
	t.Logf("appNames map: %d queryids sampled", mapSize)

	if found {
		result := c.appNamesByQueryID(fmt.Sprintf("%d", foundQid))
		assert.Contains(t, result, "test_app_ci")
		t.Logf("appNamesByQueryID(%d) = %q", foundQid, result)
	}
}

// seedStatStatements runs identical queries from different PG users and in different databases
// to populate pg_stat_statements with rows sharing the same queryid but different (userid, dbid).
func seedStatStatements(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, dsn := range []string{
		"postgres://postgres:test@127.0.0.1:15432/testdb?sslmode=disable",
		"postgres://appuser:appuser@127.0.0.1:15432/testdb?sslmode=disable",
	} {
		pool, err := pgxpool.NewWithConfig(ctx, must(pgxpool.ParseConfig(dsn)))
		require.NoError(t, err, "connect %s", dsn)
		for range 5 {
			_, _ = pool.Exec(ctx, "SELECT count(*) FROM test_table WHERE id > $1", 0)
		}
		pool.Close()
	}

	pool, err := pgxpool.NewWithConfig(ctx, must(pgxpool.ParseConfig("postgres://postgres:test@127.0.0.1:15432/testdb2?sslmode=disable")))
	require.NoError(t, err)
	for range 5 {
		_, _ = pool.Exec(ctx, "SELECT count(*) FROM test_table WHERE id > $1", 0)
	}
	pool.Close()

	t.Log("seeded pg_stat_statements with multi-user/multi-db entries")
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// TestIntegrationBuildDSN verifies that BuildDSN with a token produces a working DSN.
func TestIntegrationBuildDSN(t *testing.T) {
	const testToken = "test_token_for_ci"

	dsn := BuildDSN("127.0.0.1:15432", testToken)
	// BuildDSN uses "topsrv" as login, but our test role is "topsrv_auto".
	dsn = strings.Replace(dsn, "://topsrv:", "://topsrv_auto:", 1)

	c, err := NewCollector(embedlog.Logger{}, dsn)
	require.NoError(t, err, "BuildDSN should produce a valid DSN that connects; dsn=%s", dsn)
	defer c.Close()

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, mfs, "auto-discovered collector should return metrics")

	t.Logf("BuildDSN auto-connect: OK, %d metric families", len(mfs))
}

// TestIntegrationBuildDSNNoToken verifies that BuildDSN without a token (trust/peer auth) builds a valid DSN format.
func TestIntegrationBuildDSNNoToken(t *testing.T) {
	dsn := BuildDSN("127.0.0.1:15432", "")

	assert.Contains(t, dsn, "://topsrv@", "DSN without token should have no password")
	assert.NotContains(t, dsn, "://topsrv:", "DSN without token should not have colon after user")
	assert.Contains(t, dsn, "sslmode=disable")

	t.Logf("BuildDSN no-token: %s", dsn)
}

// TestIntegrationDerivePassword verifies the derived password matches the one stored in PostgreSQL.
func TestIntegrationDerivePassword(t *testing.T) {
	const testToken = "test_token_for_ci"
	derived := DerivePassword(testToken)

	dsn := fmt.Sprintf("postgres://topsrv_auto:%s@127.0.0.1:15432/testdb?sslmode=disable", derived)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, must(pgxpool.ParseConfig(dsn)))
	require.NoError(t, err, "derived password should authenticate; derived=%s", derived)
	defer pool.Close()

	var result int
	err = pool.QueryRow(ctx, "SELECT 1").Scan(&result)
	require.NoError(t, err)
	assert.Equal(t, 1, result)

	t.Logf("DerivePassword auth: OK (password=%s)", derived)
}

// TestIntegrationParsePostgresPort reads postgresql.conf from the running container
// and verifies parsePostgresPort extracts the correct port.
func TestIntegrationParsePostgresPort(t *testing.T) {
	container := "vmkteam-topsrv-postgres-1"
	if v := os.Getenv("TEST_PG_CONTAINER"); v != "" {
		container = v
	}

	out, err := exec.Command("docker", "exec", container, "cat", "/var/lib/postgresql/data/postgresql.conf").Output()
	if err != nil {
		t.Skipf("cannot read postgresql.conf from container %s: %v", container, err)
	}

	dir := t.TempDir()
	confPath := dir + "/postgresql.conf"
	require.NoError(t, os.WriteFile(confPath, out, 0644))

	port := parsePostgresPort(confPath)
	if port != 0 {
		assert.Equal(t, 5432, port, "postgresql.conf explicit port should be 5432")
	}

	instance := UpdateInstance("127.0.0.1:5432", confPath)
	assert.Equal(t, "127.0.0.1:5432", instance, "instance should stay default when port is commented out")

	t.Logf("parsePostgresPort from container: %d, instance: %s", port, instance)
}
