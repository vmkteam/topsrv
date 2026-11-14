package nginx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURICounters_EvictsIdleKeysWhenFull(t *testing.T) {
	u := newURICounters[string](2, 100)
	u.add("/a", overflowMarker, 1, 0)
	u.add("/b", overflowMarker, 1, 0)

	u.add("/c", overflowMarker, 1, uriIdleTTL+1) // /a and /b have been idle longer than the TTL

	require.Len(t, u.m, 1)
	assert.EqualValues(t, 1, u.m["/c"].count)
	_, hasOther := u.m[overflowMarker]
	assert.False(t, hasOther, "a slot was freed — no bucket needed")
}

func TestURICounters_HotMapOverflowsIntoBucket(t *testing.T) {
	u := newURICounters[string](2, 100)
	u.add("/a", overflowMarker, 1, 0)
	u.add("/b", overflowMarker, 1, 0)

	u.add("/c", overflowMarker, 1, 10) // every key is live — /c goes to the bucket
	u.add("/d", overflowMarker, 5, 20)
	u.add("/a", overflowMarker, 1, 30) // a known key is counted even when the map is full

	assert.EqualValues(t, 6, u.m[overflowMarker].count)
	assert.EqualValues(t, 2, u.m["/a"].count)
	_, hasC := u.m["/c"]
	assert.False(t, hasC)
	assert.Len(t, u.m, 3, "the bucket is the only key above the limit")
}

func TestURICounters_SweepIsThrottled(t *testing.T) {
	u := newURICounters[string](2, 100)
	u.add("/a", overflowMarker, 1, 0)
	u.add("/b", overflowMarker, 1, 0)

	u.add("/c", overflowMarker, 1, uriIdleTTL-10) // sweep ran, but /a and /b are not idle yet → bucket
	u.add("/d", overflowMarker, 1, uriIdleTTL+20) // idle keys exist now, but the sweep was 30s ago → bucket again
	assert.EqualValues(t, 2, u.m[overflowMarker].count)
	assert.Len(t, u.m, 3)

	u.add("/e", overflowMarker, 1, uriIdleTTL+70) // interval elapsed → /a and /b evicted, /e gets a slot
	_, hasA := u.m["/a"]
	assert.False(t, hasA)
	assert.EqualValues(t, 1, u.m["/e"].count)
}

func TestURICounters_StatusKeyedOverflow(t *testing.T) {
	u := newURICounters[statusURI](1, 100)
	u.add(statusURI{"404", "/a"}, statusURI{"404", overflowMarker}, 1, 0)
	u.add(statusURI{"404", "/b"}, statusURI{"404", overflowMarker}, 1, 1)
	u.add(statusURI{"403", "/b"}, statusURI{"403", overflowMarker}, 1, 1)

	assert.EqualValues(t, 1, u.m[statusURI{"404", overflowMarker}].count)
	assert.EqualValues(t, 1, u.m[statusURI{"403", overflowMarker}].count, "the bucket is per status, like the keys")
}

func TestURICounters_DailyBudgetSendsNewKeysToBucket(t *testing.T) {
	u := newURICounters[string](10, 2)
	u.add("/a", overflowMarker, 1, 0)
	u.add("/b", overflowMarker, 1, 0)

	u.add("/c", overflowMarker, 1, 10) // map has room, but today's budget is spent
	u.add("/a", overflowMarker, 1, 20) // a known key is still counted

	_, hasC := u.m["/c"]
	assert.False(t, hasC)
	assert.EqualValues(t, 1, u.m[overflowMarker].count)
	assert.EqualValues(t, 2, u.m["/a"].count)
}

func TestURICounters_EvictionDoesNotRefundBudget(t *testing.T) {
	u := newURICounters[string](2, 3)
	u.add("/a", overflowMarker, 1, 0)
	u.add("/b", overflowMarker, 1, 0)
	u.add("/c", overflowMarker, 1, uriIdleTTL+1) // /a and /b evicted, /c admitted — budget 3 of 3
	u.add("/d", overflowMarker, 1, uriIdleTTL+2) // a free slot is left, but not a single unit of budget

	require.Contains(t, u.m, "/c")
	assert.NotContains(t, u.m, "/d")
	assert.EqualValues(t, 1, u.m[overflowMarker].count)
}

func TestURICounters_DailyBudgetResetsAtUTCMidnight(t *testing.T) {
	u := newURICounters[string](10, 1)
	lastSecond := secondsPerDay - 1
	u.add("/a", overflowMarker, 1, lastSecond)
	u.add("/b", overflowMarker, 1, lastSecond) // budget spent → bucket

	u.add("/c", overflowMarker, 1, secondsPerDay) // 00:00:00 UTC — a fresh budget

	assert.NotContains(t, u.m, "/b")
	assert.EqualValues(t, 1, u.m["/c"].count)
}

func TestURICounters_FullMapDoesNotSpendBudget(t *testing.T) {
	u := newURICounters[string](1, 2)
	u.add("/a", overflowMarker, 1, 0) // budget 1 of 2
	u.add("/b", overflowMarker, 1, 1) // map full, /a is live → bucket, no budget spent

	u.add("/c", overflowMarker, 1, uriIdleTTL+70) // /a and the bucket evicted → the last unit goes to /c

	assert.EqualValues(t, 1, u.m["/c"].count, "/b must not have spent the unit /c needed")
}
