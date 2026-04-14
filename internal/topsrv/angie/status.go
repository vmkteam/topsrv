package angie

// StatusResponse is the root of the Angie /status/ JSON API response.
type StatusResponse struct {
	Connections Connections         `json:"connections"`
	HTTP        HTTPStatus          `json:"http"`
	Slabs       map[string]SlabZone `json:"slabs"`
}

// Connections holds global connection counters.
type Connections struct {
	Accepted int64 `json:"accepted"`
	Dropped  int64 `json:"dropped"`
	Active   int64 `json:"active"`
	Idle     int64 `json:"idle"`
}

// HTTPStatus holds all HTTP-related status sections.
type HTTPStatus struct {
	ServerZones   map[string]ServerZone `json:"server_zones"`
	LocationZones map[string]ServerZone `json:"location_zones"`
	Upstreams     map[string]Upstream   `json:"upstreams"`
	Caches        map[string]Cache      `json:"caches"`
	LimitConns    map[string]LimitConn  `json:"limit_conns"`
	LimitReqs     map[string]LimitReq   `json:"limit_reqs"`
}

// ServerZone holds per-zone metrics for a server or location block.
type ServerZone struct {
	SSL       ZoneSSL          `json:"ssl"`
	Requests  ZoneRequests     `json:"requests"`
	Responses map[string]int64 `json:"responses"` // "200": 4305, "302": 12
	Data      ZoneData         `json:"data"`
}

// ZoneSSL holds SSL/TLS handshake counters.
type ZoneSSL struct {
	Handshaked int64 `json:"handshaked"`
	Reuses     int64 `json:"reuses"`
	Timedout   int64 `json:"timedout"`
	Failed     int64 `json:"failed"`
}

// ZoneRequests holds request counters.
type ZoneRequests struct {
	Total      int64 `json:"total"`
	Processing int64 `json:"processing"`
	Discarded  int64 `json:"discarded"`
}

// ZoneData holds data transfer counters.
type ZoneData struct {
	Received int64 `json:"received"`
	Sent     int64 `json:"sent"`
}

// Upstream holds upstream group metrics including per-peer data.
type Upstream struct {
	Peers     map[string]UpstreamPeer `json:"peers"`
	Keepalive int64                   `json:"keepalive"`
}

// UpstreamPeer holds per-peer metrics within an upstream group.
type UpstreamPeer struct {
	Server    string           `json:"server"`
	State     string           `json:"state"` // "up", "down", "unavailable", "recovering", "busy"
	Selected  PeerSelected     `json:"selected"`
	MaxConns  int64            `json:"max_conns"`
	Responses map[string]int64 `json:"responses"` // "200": 2140, "502": 10
	Data      ZoneData         `json:"data"`
	Health    PeerHealth       `json:"health"`
}

// PeerSelected holds selection counters for a peer.
type PeerSelected struct {
	Current int64 `json:"current"`
	Total   int64 `json:"total"`
}

// PeerHealth holds health check counters for a peer.
type PeerHealth struct {
	Fails       int64 `json:"fails"`
	Unavailable int64 `json:"unavailable"`
	Downtime    int64 `json:"downtime"` // milliseconds
}

// Cache holds cache zone metrics.
type Cache struct {
	Size        int64      `json:"size"`
	Cold        bool       `json:"cold"`
	Hit         CacheStats `json:"hit"`
	Stale       CacheStats `json:"stale"`
	Updating    CacheStats `json:"updating"`
	Revalidated CacheStats `json:"revalidated"`
	Miss        CacheStats `json:"miss"`
	Expired     CacheStats `json:"expired"`
	Bypass      CacheStats `json:"bypass"`
}

// CacheStats holds response/byte counters for a cache status.
type CacheStats struct {
	Responses int64 `json:"responses"`
	Bytes     int64 `json:"bytes"`
}

// LimitConn holds connection rate limiting counters.
type LimitConn struct {
	Passed    int64 `json:"passed"`
	Skipped   int64 `json:"skipped"`
	Rejected  int64 `json:"rejected"`
	Exhausted int64 `json:"exhausted"`
}

// LimitReq holds request rate limiting counters.
type LimitReq struct {
	Passed    int64 `json:"passed"`
	Skipped   int64 `json:"skipped"`
	Delayed   int64 `json:"delayed"`
	Rejected  int64 `json:"rejected"`
	Exhausted int64 `json:"exhausted"`
}

// SlabZone holds shared memory slab allocator metrics.
type SlabZone struct {
	Pages SlabPages `json:"pages"`
}

// SlabPages holds page usage counters.
type SlabPages struct {
	Used int64 `json:"used"`
	Free int64 `json:"free"`
}
