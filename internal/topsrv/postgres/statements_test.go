package postgres

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectTopStatementsSkipsNonPositiveDeltas(t *testing.T) {
	c := &Collector{hasWalBytes: true}
	all := []stmtCurrent{
		{key: "1:a", deltaTime: 5, deltaCalls: 10},
		{key: "1:b"}, // first scrape / idle database — all deltas zero
		{key: "1:c", deltaTime: -3, deltaCalls: -1}, // pg_stat_statements reset
		{key: "1:d", deltaBlksDirtied: 7},
		{key: "1:e", deltaWalBytes: 9},
	}

	metrics, meta := c.selectTopStatements(all)

	want := map[string]bool{"1:a": true, "1:d": true, "1:e": true}
	assert.Equal(t, want, metrics)
	assert.Equal(t, want, meta, "under topStatementsN entries both widths hold the same set")
}

func TestSelectTopStatementsIgnoresWalBytesWhenUnavailable(t *testing.T) {
	c := &Collector{hasWalBytes: false}
	all := []stmtCurrent{
		{key: "1:a", deltaWalBytes: 100},
		{key: "1:b", deltaCalls: 1},
	}

	metrics, _ := c.selectTopStatements(all)

	assert.Equal(t, map[string]bool{"1:b": true}, metrics)
}

// The metrics set is capped at topStatementsN per dimension while meta reaches topMetaN,
// so a statement ranked between the two widths reaches the meta push only.
func TestSelectTopStatementsMetaIsWiderThanMetrics(t *testing.T) {
	c := &Collector{}
	all := make([]stmtCurrent, topMetaN+5)
	for i := range all {
		// Descending delta: index i lands at rank i in every dimension.
		all[i] = stmtCurrent{key: strconv.Itoa(i), deltaCalls: int64(len(all) - i)}
	}

	metrics, meta := c.selectTopStatements(all)

	assert.Len(t, metrics, topStatementsN)
	assert.Len(t, meta, topMetaN)
	assert.False(t, metrics[strconv.Itoa(topStatementsN)], "rank topStatementsN is out of the metrics width")
	assert.True(t, meta[strconv.Itoa(topStatementsN)], "rank topStatementsN is still within the meta width")
	assert.False(t, meta[strconv.Itoa(topMetaN)], "rank topMetaN is out of both widths")
}

func TestDebounceTopRequiresTwoConsecutiveScrapes(t *testing.T) {
	c := &Collector{}

	first := c.debounceTop(map[string]bool{"a": true, "b": true})
	require.Empty(t, first, "nothing may emit on first top appearance")

	second := c.debounceTop(map[string]bool{"b": true, "c": true})
	assert.Equal(t, map[string]bool{"b": true}, second, "only the repeated key emits")

	third := c.debounceTop(map[string]bool{"c": true})
	assert.Equal(t, map[string]bool{"c": true}, third, "key kept from previous top emits")

	fourth := c.debounceTop(map[string]bool{})
	assert.Empty(t, fourth)
}

// A statement that alternates in and out of the top-set never emits: a one-scrape
// memory has nothing to carry it across the gap. Deliberate — a query this marginal
// is not worth a permanent series — and documented in docs/metrics.md, so pin it
// rather than let a future rewrite change it silently.
func TestDebounceTopNeverEmitsAlternatingStatement(t *testing.T) {
	c := &Collector{}

	for range 5 {
		assert.Empty(t, c.debounceTop(map[string]bool{"flapping": true}))
		assert.Empty(t, c.debounceTop(map[string]bool{}))
	}
}
