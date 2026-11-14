package nginx

import "time"

// Eviction policy for the per-URI maps (uri4xx, uri5xx, bytesByURI).
//
// Until September 2026 a map that reached maxCardinalityURI simply stopped
// accepting new keys: the first 1000 URIs seen after agent start kept their
// slots forever. On public hosts those are mostly one-off scanner paths
// (scanner probes like /joomla.zip or /app_debug — on one production host 389
// of the 1000 4xx series had <= 3 hits), while genuine URIs that showed up
// later were never counted at all. Now a full map first evicts keys not seen
// for uriIdleTTL; if every key is still live, the new one is counted under
// overflowMarker so the per-family sum still matches http_requests_total.
//
// Eviction bounds the live map, not the distinct keys a day — and a TSDB
// counts every one of them as a series in its daily index. So new keys are
// also capped per UTC day, see admit.
const (
	overflowMarker   = "/:other"
	uriIdleTTL       = int64(time.Hour / time.Second)   // seconds without hits before a key may be evicted
	uriSweepInterval = int64(time.Minute / time.Second) // at most one full sweep per minute
	secondsPerDay    = int64(24 * time.Hour / time.Second)
)

type uriCounter struct {
	count    uint64
	lastSeen int64 // unix seconds
}

// uriCounters is a bounded key → counter map with idle eviction and a daily
// budget for new keys.
type uriCounters[K comparable] struct {
	m         map[K]uriCounter
	limit     int
	lastSweep int64

	dailyNew int   // new keys allowed per UTC day
	day      int64 // UTC day number (unix seconds / secondsPerDay) of admitted
	admitted int   // new keys admitted on day
}

func newURICounters[K comparable](limit, dailyNew int) uriCounters[K] {
	return uriCounters[K]{m: make(map[K]uriCounter), limit: limit, dailyNew: dailyNew}
}

// add increments key by n. A known key is always counted; a new key lands in
// overflow once the daily budget is spent, and on a full map it first tries
// to free a slot via sweep — the bucket is accepted even above the limit.
func (u *uriCounters[K]) add(key, overflow K, n uint64, now int64) {
	if e, ok := u.m[key]; ok {
		e.count += n
		e.lastSeen = now
		u.m[key] = e
		return
	}
	if len(u.m) >= u.limit {
		u.sweep(now)
	}
	if len(u.m) >= u.limit || !u.admit(now) {
		key = overflow
	}
	e := u.m[key]
	e.count += n
	e.lastSeen = now
	u.m[key] = e
}

// admit spends one unit of the daily budget for a new key and reports whether
// there was one. Days are UTC, the boundary of a TSDB daily index, so a family
// reaches at most limit (carried over) + dailyNew distinct keys a day. A key
// evicted and seen again the same day is charged twice — the cap errs safe.
// The budget lives in memory: an agent restart starts a fresh one.
func (u *uriCounters[K]) admit(now int64) bool {
	if day := now / secondsPerDay; day != u.day {
		u.day, u.admitted = day, 0
	}
	if u.admitted >= u.dailyNew {
		return false
	}
	u.admitted++
	return true
}

// sweep drops keys idle for longer than uriIdleTTL. Throttled to
// uriSweepInterval: with a hot map of 1000 live keys every scanner line would
// otherwise trigger a full pass.
func (u *uriCounters[K]) sweep(now int64) {
	if now-u.lastSweep < uriSweepInterval {
		return
	}
	u.lastSweep = now
	for k, e := range u.m {
		if now-e.lastSeen > uriIdleTTL {
			delete(u.m, k)
		}
	}
}

// nowUnix is the clock behind add; kept here so log.go doesn't import time
// for a single call.
func nowUnix() int64 { return time.Now().Unix() }
