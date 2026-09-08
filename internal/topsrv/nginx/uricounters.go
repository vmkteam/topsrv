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
const (
	overflowMarker   = "/:other"
	uriIdleTTL       = int64(time.Hour / time.Second)   // seconds without hits before a key may be evicted
	uriSweepInterval = int64(time.Minute / time.Second) // at most one full sweep per minute
)

type uriCounter struct {
	count    uint64
	lastSeen int64 // unix seconds
}

// uriCounters is a bounded key → counter map with idle eviction.
type uriCounters[K comparable] struct {
	m         map[K]uriCounter
	limit     int
	lastSweep int64
}

func newURICounters[K comparable](limit int) uriCounters[K] {
	return uriCounters[K]{m: make(map[K]uriCounter), limit: limit}
}

// add increments key by n. A known key is always counted; a new key on a full
// map first tries to free a slot via sweep and otherwise lands in overflow —
// the bucket is accepted even above the limit.
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
	if len(u.m) >= u.limit {
		key = overflow
	}
	e := u.m[key]
	e.count += n
	e.lastSeen = now
	u.m[key] = e
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
