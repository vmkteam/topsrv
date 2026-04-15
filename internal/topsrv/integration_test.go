//go:build integration

package topsrv

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
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

func nginxStubURL() string {
	if v := os.Getenv("TEST_NGINX_STUB"); v != "" {
		return v
	}
	return "http://127.0.0.1:18080/stub_status"
}

func vmURL() string {
	if v := os.Getenv("TEST_VM_URL"); v != "" {
		return v
	}
	return "http://127.0.0.1:18428"
}

func TestIntegrationPostgres(t *testing.T) {
	dsn := pgDSN()
	logger := embedlog.Logger{}

	// Seed pg_stat_statements: run the same query from different users and databases
	// so that (userid, dbid, queryid) produces duplicate queryids that must be aggregated.
	seedStatStatements(t)

	c, err := NewPostgresCollector(logger, dsn)
	require.NoError(t, err, "failed to create postgres collector with DSN: %s", dsn)

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	// First gather seeds prevStmts for histogram delta computation.
	_, err = reg.Gather()
	require.NoError(t, err)

	// Second gather produces histogram (needs prev values for deltas).
	mfs, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, mfs, "postgres collector returned no metrics")

	names := map[string]bool{}
	mfMap := map[string]*io_prometheus_client.MetricFamily{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
		mfMap[mf.GetName()] = mf
	}

	// Core PG metrics must be present.
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

	// Verify connections_by_app has application_name and state labels.
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

	// Verify longest_transaction_seconds has database and usename labels.
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

	// Verify connections includes background worker state.
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

	// pg_stat_statements metrics (PG17 uses shared_blk_read_time/shared_blk_write_time).
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

	// Verify that per-query metrics have the "database" label.
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

	t.Logf("postgres integration: %d metric families", len(mfs))

	// QueryMeta must return full query texts with database names.
	meta := c.QueryMeta()
	require.NotEmpty(t, meta, "QueryMeta returned no entries")

	for _, m := range meta {
		assert.NotEmpty(t, m.QueryID, "QueryMeta entry has empty queryid")
		assert.NotEmpty(t, m.Database, "QueryMeta entry has empty database")
		assert.NotEmpty(t, m.Query, "QueryMeta entry has empty query")
	}

	t.Logf("QueryMeta: %d entries, first db=%s queryid=%s query_len=%d", len(meta), meta[0].Database, meta[0].QueryID, len(meta[0].Query))
}

// seedStatStatements runs identical queries from different PG users and in different databases
// to populate pg_stat_statements with rows sharing the same queryid but different (userid, dbid).
// This exercises the GROUP BY (queryid, dbid) aggregation that prevents Prometheus duplicate errors.
func seedStatStatements(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Identical query run by different users on testdb.
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

	// Same query in a second database.
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
// The test token "test_token_for_ci" derives password = SHA256("test_token_for_ci")[:32]
// which matches the topsrv_auto role created in testdata/init.sql.
func TestIntegrationBuildDSN(t *testing.T) {
	const testToken = "test_token_for_ci"

	dsn := BuildDSN("127.0.0.1:15432", testToken)
	// BuildDSN uses "topsrv" as login, but our test role is "topsrv_auto".
	// Replace to match the test role.
	dsn = strings.Replace(dsn, "://topsrv:", "://topsrv_auto:", 1)

	c, err := NewPostgresCollector(embedlog.Logger{}, dsn)
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

	// DSN should not contain a password.
	assert.Contains(t, dsn, "://topsrv@", "DSN without token should have no password")
	assert.NotContains(t, dsn, "://topsrv:", "DSN without token should not have colon after user")
	assert.Contains(t, dsn, "sslmode=disable")

	t.Logf("BuildDSN no-token: %s", dsn)
}

// TestIntegrationDerivePassword verifies the derived password matches the one stored in PostgreSQL.
func TestIntegrationDerivePassword(t *testing.T) {
	const testToken = "test_token_for_ci"
	derived := DerivePassword(testToken)

	// Connect as topsrv_auto using the derived password directly via pgx.
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

	// Read postgresql.conf from the container.
	out, err := exec.Command("docker", "exec", container, "cat", "/var/lib/postgresql/data/postgresql.conf").Output()
	if err != nil {
		t.Skipf("cannot read postgresql.conf from container %s: %v", container, err)
	}

	dir := t.TempDir()
	confPath := dir + "/postgresql.conf"
	require.NoError(t, os.WriteFile(confPath, out, 0644))

	port := parsePostgresPort(confPath)
	// Default postgresql.conf has port commented out — parsePostgresPort returns 0.
	// If port is explicitly set, it should be 5432.
	if port != 0 {
		assert.Equal(t, 5432, port, "postgresql.conf explicit port should be 5432")
	}

	// Verify updatePostgresInstance keeps default when port is 0.
	instance := updatePostgresInstance("127.0.0.1:5432", confPath)
	assert.Equal(t, "127.0.0.1:5432", instance, "instance should stay default when port is commented out")

	t.Logf("parsePostgresPort from container: %d, instance: %s", port, instance)
}

func TestIntegrationNginxStub(t *testing.T) {
	// Verify nginx is reachable.
	resp, err := http.Get(nginxStubURL())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	// Test stub collector via HTTP (using the existing nginx stub package).
	t.Log("nginx stub_status reachable")
}

func TestIntegrationPushToVM(t *testing.T) {
	vm := vmURL()

	// Verify VM is healthy.
	resp, err := http.Get(vm + "/health")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	// Collect system metrics and push to VM.
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewSystemCollector(embedlog.Logger{}, "test"))

	mfs, err := reg.Gather()
	require.NoError(t, err)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := expfmt.NewEncoder(gz, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		require.NoError(t, enc.Encode(mf))
	}
	gz.Close()

	// Push via import/prometheus.
	req, _ := http.NewRequestWithContext(context.Background(), "POST", vm+"/api/v1/import/prometheus", &buf)
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "text/plain")

	pushResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(pushResp.Body)
	pushResp.Body.Close()
	require.Equal(t, 204, pushResp.StatusCode, "push failed: %s", string(body))

	// Force flush and poll until metric appears (VM needs time to index).
	queryURL := fmt.Sprintf("%s/api/v1/query?query=topsrv_uptime_seconds", vm)

	var qBody []byte
	found := false
	for range 10 {
		forceResp, _ := http.Get(vm + "/internal/force_flush")
		if forceResp != nil {
			forceResp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)

		qResp, err := http.Get(queryURL)
		require.NoError(t, err)
		qBody, _ = io.ReadAll(qResp.Body)
		qResp.Body.Close()

		require.Equal(t, 200, qResp.StatusCode)
		if bytes.Contains(qBody, []byte("topsrv_uptime_seconds")) {
			found = true
			break
		}
	}

	assert.True(t, found, "metric not found in VM after push: %s", string(qBody))
	t.Logf("push → VM → query: OK (%d bytes response)", len(qBody))
}
