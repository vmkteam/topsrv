package postgres

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// unreachableDSN returns a DSN pointing at a TCP port that is guaranteed to refuse
// connections for the duration of the test. We bind a listener on :0 (kernel picks
// a free port), then close it before handing the port out — any connect attempt
// hits ECONNREFUSED immediately. Safer than hard-coding a port that might become busy.
func unreachableDSN(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return fmt.Sprintf("postgres://nobody@127.0.0.1:%d/nothing?sslmode=disable&connect_timeout=1", port)
}

func TestFeedHistogramOutliers(t *testing.T) {
	// Simulate: 1000 calls, total 11000ms. 999 at 1ms + 1 at 10s scenario.
	// prev: cumulative max was 5ms (no outliers yet).
	// cur:  cumulative max 10000ms → new outlier this scrape.
	c := &Collector{histBuckets: newHistBuckets()}
	prev := stmtPrev{calls: 0, totalTime: 0, minTime: 1, maxTime: 5}
	cur := stmtPrev{calls: 1000, totalTime: 11000, minTime: 1, maxTime: 10000}

	c.feedHistogram(cur, prev, 1000, 11000)

	// histCount must equal deltaCalls.
	assert.EqualValues(t, 1000, c.histCount)
	// histSum must equal deltaTime in seconds (11000ms = 11s).
	assert.InDelta(t, 11.0, c.histSum, 1e-9)

	// 10s bucket must contain the outlier: count including it.
	// Previous impl would put all 1000 calls into bucket for mean=11ms → bucket[0.05] = 1000.
	// New impl: 1 call at max (10s) + 999 at adjusted mean (1ms/call).
	assert.EqualValues(t, 1000, c.histBuckets[10.0], "bucket 10s should have all calls (outlier + 999 below)")
	// Adjusted mean = (11000 - 10000) / 999 ≈ 1.001ms. So bucket 0.005 catches the 999.
	assert.EqualValues(t, 999, c.histBuckets[0.005], "bucket 5ms should have 999 fast calls")
}

func TestFeedHistogramNoOutlier(t *testing.T) {
	// Normal scrape: 100 calls at ~1ms each, no new max.
	c := &Collector{histBuckets: newHistBuckets()}
	prev := stmtPrev{calls: 0, totalTime: 0, minTime: 1, maxTime: 5}
	cur := stmtPrev{calls: 100, totalTime: 100, minTime: 1, maxTime: 5} // same min/max as prev

	c.feedHistogram(cur, prev, 100, 100)

	assert.EqualValues(t, 100, c.histCount)
	assert.InDelta(t, 0.1, c.histSum, 1e-9)
	assert.EqualValues(t, 100, c.histBuckets[0.001])
}

func TestConvertSetting(t *testing.T) {
	cases := []struct {
		val, unit string
		want      float64
	}{
		{"16", "8kB", 16 * 8 * 1024},
		{"1024", "kB", 1024 * 1024},
		{"64", "MB", 64 * 1024 * 1024},
		{"300", "s", 300},
		{"500", "ms", 0.5},
		{"5", "min", 300},
		{"1.1", "", 1.1},
		{"bad", "kB", 0},
	}
	for _, tc := range cases {
		got := convertSetting(tc.val, tc.unit)
		assert.InDelta(t, tc.want, got, 1e-9, "convertSetting(%q,%q)", tc.val, tc.unit)
	}
}

// TestNewCollectorNoNetworkIO verifies the core promise of the lazy init refactor:
// NewCollector does not attempt to connect to Postgres. A collector created against
// an unreachable DSN must return successfully so topsrv keeps serving the non-PG
// collectors; connection errors surface only on Collect().
func TestNewCollectorNoNetworkIO(t *testing.T) {
	dsn := unreachableDSN(t)
	start := time.Now()
	pg, err := NewCollector(embedlog.Logger{}, dsn)
	elapsed := time.Since(start)

	require.NoError(t, err, "NewCollector must succeed for any syntactically valid DSN")
	require.NotNil(t, pg)
	defer pg.Close()

	assert.Nil(t, pg.pool, "pool must stay nil until first ensureReady")
	assert.False(t, pg.initDone, "feature detection must not have run")
	assert.Less(t, elapsed, 500*time.Millisecond, "NewCollector must not do network I/O (observed %s)", elapsed)
}

func TestNewCollectorInvalidDSN(t *testing.T) {
	pg, err := NewCollector(embedlog.Logger{}, "not-a-valid-dsn://")
	require.Error(t, err, "malformed DSN must be rejected synchronously")
	assert.Nil(t, pg)
}

// TestEnsureReadyRetryable verifies that a failed ensureReady leaves the collector
// in a clean state so the next Collect can retry. Without this guarantee topsrv
// would permanently mark PG down after one transient failure.
func TestEnsureReadyRetryable(t *testing.T) {
	pg, err := NewCollector(embedlog.Logger{}, unreachableDSN(t))
	require.NoError(t, err)
	defer pg.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Two consecutive failures must both return errors without panicking or corrupting state.
	err1 := pg.ensureReady(ctx)
	require.Error(t, err1, "first ensureReady must surface the connect/ping error")

	err2 := pg.ensureReady(ctx)
	require.Error(t, err2, "second ensureReady must also fail — retry is expected, not a permanent disable")

	assert.False(t, pg.initDone, "initDone must stay false after failures so detectFeatures runs on recovery")
}

// TestPruneAppNamesEvictsStale is the regression test for the slow memory
// leak that grew RSS by ~70MB/day on busy Postgres hosts: a never-cleared
// map[queryid][application_name] accumulated forever as processes restarted
// with new pid-suffixed app_names. pruneAppNames must drop entries older
// than appNamesTTL and clean up newly-empty queryid sub-maps.
func TestPruneAppNamesEvictsStale(t *testing.T) {
	c := &Collector{appNames: make(map[int64]map[string]time.Time)}
	now := time.Now()

	c.appNames[1] = map[string]time.Time{
		"fresh-app": now.Add(-time.Minute),
		"stale-app": now.Add(-2 * appNamesTTL),
	}
	c.appNames[2] = map[string]time.Time{
		"only-stale": now.Add(-2 * appNamesTTL),
	}
	c.appNames[3] = map[string]time.Time{
		"only-fresh": now,
	}

	c.pruneAppNames(now)

	assert.Len(t, c.appNames[1], 1, "qid=1 keeps the fresh app_name only")
	_, hasStale := c.appNames[1]["stale-app"]
	assert.False(t, hasStale, "stale entry must be dropped")
	_, hasFresh := c.appNames[1]["fresh-app"]
	assert.True(t, hasFresh, "fresh entry must survive")

	_, qid2Present := c.appNames[2]
	assert.False(t, qid2Present, "qid=2 had only stale entries — sub-map dropped entirely")

	assert.Len(t, c.appNames[3], 1, "qid=3 untouched")
}
