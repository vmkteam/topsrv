package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vmkteam/embedlog"
)

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

func TestCollectorConnectFailure(t *testing.T) {
	dsn := "postgres://invalid:invalid@localhost:59999/invalid?connect_timeout=1"
	pg, err := NewCollector(embedlog.Logger{}, dsn)
	if err == nil {
		pg.Close()
		t.Skip("unexpectedly connected to postgres")
	}
	t.Logf("expected error creating collector: %v", err)
}
