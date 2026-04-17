package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// TestBloatCacheEmitsFromCache verifies the cache serves metrics between
// refreshes. The cache contract is what keeps the scrape budget predictable —
// refresh costs ~400 ms warm, but that's absorbed once per bloatRefreshInterval
// instead of every scrape.
func TestBloatCacheEmitsFromCache(t *testing.T) {
	c := &Collector{Logger: embedlog.Logger{}, database: "testdb"}
	c.initDescriptors()

	c.bloatLastRefresh = time.Now()
	c.bloatTables = []tableBloatEntry{
		{schema: "public", table: "movies", size: 17_000_000_000, pct: 94.1},
		{schema: "push", table: "messages", size: 4_000_000_000, pct: 13.0},
	}
	c.bloatIndexes = []indexBloatEntry{
		{schema: "push", table: "messages", index: "newMessages_messageId_idx", size: 330_000_000, pct: 99.88},
	}

	ch := make(chan prometheus.Metric, 16)
	// Safe to call with nil pool — fresh cache means no refresh path runs.
	c.collectBloat(t.Context(), ch)
	close(ch)

	metrics := map[string]float64{}
	for m := range ch {
		var dm dto.Metric
		require.NoError(t, m.Write(&dm))
		labels := map[string]string{}
		for _, lp := range dm.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		key := m.Desc().String() + "|" + labels["schema"] + "." + labels["table"]
		if idx := labels["index"]; idx != "" {
			key += "." + idx
		}
		metrics[key] = dm.GetGauge().GetValue()
	}

	// 2 tables × 2 metrics + 1 index × 2 metrics = 6 series.
	assert.Len(t, metrics, 6)

	// Spot-check a few values to confirm cache entries survive the emit path
	// unmodified (bytes as float, percentages as-is).
	var sizeSum, pctCount float64
	for key, val := range metrics {
		switch {
		case strings.Contains(key, "table_bloat_size_bytes") && strings.Contains(key, "movies"):
			assert.InDelta(t, 17_000_000_000.0, val, 0.5)
		case strings.Contains(key, "table_bloat_pct") && strings.Contains(key, "movies"):
			assert.InDelta(t, 94.1, val, 0.01)
		case strings.Contains(key, "index_bloat_size_bytes"):
			assert.InDelta(t, 330_000_000.0, val, 0.5)
		case strings.Contains(key, "index_bloat_pct"):
			assert.InDelta(t, 99.88, val, 0.01)
		}
		if strings.Contains(key, "_bytes") {
			sizeSum += val
		}
		if strings.Contains(key, "_pct") {
			pctCount++
		}
	}
	assert.InDelta(t, 21_330_000_000.0, sizeSum, 0.5, "sum of all size metrics")
	assert.InDelta(t, 3.0, pctCount, 0.01, "expected 3 pct metrics (2 table + 1 index)")
}

// TestTryBeginBloatRefreshBarrier guarantees the single-flight property:
// only the first caller past the staleness deadline owns the refresh, and
// concurrent scrapes see a fresh cache (no SQL stampede on a cold start).
func TestTryBeginBloatRefreshBarrier(t *testing.T) {
	c := &Collector{}
	c.bloatLastRefresh = time.Now().Add(-2 * bloatRefreshInterval)

	now := time.Now()
	assert.True(t, c.tryBeginBloatRefresh(now), "stale cache → first caller owns refresh")
	assert.False(t, c.tryBeginBloatRefresh(now), "after barrier bump, next caller sees fresh cache")

	// After a full interval the barrier opens again.
	assert.True(t, c.tryBeginBloatRefresh(now.Add(bloatRefreshInterval+time.Second)))

	// bloatRetryNow sentinel should immediately admit the next caller.
	c.bloatLastRefresh = bloatRetryNow
	assert.True(t, c.tryBeginBloatRefresh(time.Now()), "bloatRetryNow sentinel forces immediate retry")
}
