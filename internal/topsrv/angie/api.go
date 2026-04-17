package angie

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/vmkteam/topsrv/internal/topsrv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vmkteam/embedlog"
)

var _ topsrv.Collector = (*APICollector)(nil)

// peerStateValues maps Angie peer state strings to numeric gauge values.
var peerStateValues = map[string]float64{
	"up":          1,
	"down":        2,
	"unavailable": 3,
	"recovering":  4,
	"busy":        5,
}

// APICollector collects metrics from the Angie JSON API (/status/).
type APICollector struct {
	embedlog.Logger

	url    string
	client *http.Client

	// Connections.
	up           *prometheus.Desc
	connAccepted *prometheus.Desc
	connDropped  *prometheus.Desc
	connActive   *prometheus.Desc
	connIdle     *prometheus.Desc

	// HTTP server zones.
	szRequests          *prometheus.Desc
	szRequestsProc      *prometheus.Desc
	szRequestsDiscarded *prometheus.Desc
	szResponses         *prometheus.Desc
	szRecvBytes         *prometheus.Desc
	szSentBytes         *prometheus.Desc
	szSSLHandshakes     *prometheus.Desc
	szSSLFailed         *prometheus.Desc

	// HTTP upstreams.
	upPeerState       *prometheus.Desc
	upPeerReqTotal    *prometheus.Desc
	upPeerReqCurrent  *prometheus.Desc
	upPeerResponses   *prometheus.Desc
	upPeerSentBytes   *prometheus.Desc
	upPeerRecvBytes   *prometheus.Desc
	upPeerHealthFails *prometheus.Desc
	upPeerHealthDown  *prometheus.Desc
	upKeepalive       *prometheus.Desc

	// HTTP caches.
	cacheSize      *prometheus.Desc
	cacheResponses *prometheus.Desc
	cacheBytes     *prometheus.Desc

	// Rate limiting.
	limitConns *prometheus.Desc
	limitReqs  *prometheus.Desc

	// Shared memory slabs.
	slabPages *prometheus.Desc
}

func NewAPICollector(logger embedlog.Logger, statusURL string) *APICollector {
	return &APICollector{
		Logger: logger,
		url:    statusURL,
		client: &http.Client{},

		// Connections.
		up:           prometheus.NewDesc("topsrv_angie_up", "Angie API is reachable (1=yes, 0=no).", nil, nil),
		connAccepted: prometheus.NewDesc("topsrv_angie_connections_accepted_total", "Total accepted connections.", nil, nil),
		connDropped:  prometheus.NewDesc("topsrv_angie_connections_dropped_total", "Total dropped connections.", nil, nil),
		connActive:   prometheus.NewDesc("topsrv_angie_connections_active", "Active connections.", nil, nil),
		connIdle:     prometheus.NewDesc("topsrv_angie_connections_idle", "Idle connections.", nil, nil),

		// HTTP server zones.
		szRequests:          prometheus.NewDesc("topsrv_angie_server_zone_requests_total", "Total requests per server zone.", []string{"zone"}, nil),
		szRequestsProc:      prometheus.NewDesc("topsrv_angie_server_zone_requests_processing", "Requests currently processing per server zone.", []string{"zone"}, nil),
		szRequestsDiscarded: prometheus.NewDesc("topsrv_angie_server_zone_requests_discarded_total", "Discarded requests per server zone.", []string{"zone"}, nil),
		szResponses:         prometheus.NewDesc("topsrv_angie_server_zone_responses_total", "Responses by HTTP status code per server zone.", []string{"zone", "code"}, nil),
		szRecvBytes:         prometheus.NewDesc("topsrv_angie_server_zone_received_bytes_total", "Bytes received per server zone.", []string{"zone"}, nil),
		szSentBytes:         prometheus.NewDesc("topsrv_angie_server_zone_sent_bytes_total", "Bytes sent per server zone.", []string{"zone"}, nil),
		szSSLHandshakes:     prometheus.NewDesc("topsrv_angie_server_zone_ssl_handshakes_total", "Successful SSL handshakes per server zone.", []string{"zone"}, nil),
		szSSLFailed:         prometheus.NewDesc("topsrv_angie_server_zone_ssl_failed_total", "Failed SSL handshakes per server zone.", []string{"zone"}, nil),

		// HTTP upstreams.
		upPeerState:       prometheus.NewDesc("topsrv_angie_upstream_peer_state", "Upstream peer state (1=up, 2=down, 3=unavailable, 4=recovering, 5=busy).", []string{"upstream", "peer"}, nil),
		upPeerReqTotal:    prometheus.NewDesc("topsrv_angie_upstream_peer_requests_total", "Total requests to upstream peer.", []string{"upstream", "peer"}, nil),
		upPeerReqCurrent:  prometheus.NewDesc("topsrv_angie_upstream_peer_requests_current", "Current requests to upstream peer.", []string{"upstream", "peer"}, nil),
		upPeerResponses:   prometheus.NewDesc("topsrv_angie_upstream_peer_responses_total", "Responses by HTTP status code per upstream peer.", []string{"upstream", "peer", "code"}, nil),
		upPeerSentBytes:   prometheus.NewDesc("topsrv_angie_upstream_peer_sent_bytes_total", "Bytes sent to upstream peer.", []string{"upstream", "peer"}, nil),
		upPeerRecvBytes:   prometheus.NewDesc("topsrv_angie_upstream_peer_received_bytes_total", "Bytes received from upstream peer.", []string{"upstream", "peer"}, nil),
		upPeerHealthFails: prometheus.NewDesc("topsrv_angie_upstream_peer_health_fails_total", "Health check failures per upstream peer.", []string{"upstream", "peer"}, nil),
		upPeerHealthDown:  prometheus.NewDesc("topsrv_angie_upstream_peer_health_downtime_seconds_total", "Total downtime per upstream peer.", []string{"upstream", "peer"}, nil),
		upKeepalive:       prometheus.NewDesc("topsrv_angie_upstream_keepalive", "Keepalive connections per upstream.", []string{"upstream"}, nil),

		// HTTP caches.
		cacheSize:      prometheus.NewDesc("topsrv_angie_cache_size_bytes", "Current cache size in bytes.", []string{"zone"}, nil),
		cacheResponses: prometheus.NewDesc("topsrv_angie_cache_responses_total", "Cache responses by status.", []string{"zone", "status"}, nil),
		cacheBytes:     prometheus.NewDesc("topsrv_angie_cache_bytes_total", "Cache bytes by status.", []string{"zone", "status"}, nil),

		// Rate limiting.
		limitConns: prometheus.NewDesc("topsrv_angie_limit_conns_total", "Connection limiting results by status.", []string{"zone", "status"}, nil),
		limitReqs:  prometheus.NewDesc("topsrv_angie_limit_reqs_total", "Request limiting results by status.", []string{"zone", "status"}, nil),

		// Shared memory slabs.
		slabPages: prometheus.NewDesc("topsrv_angie_slab_pages", "Slab allocator pages by state.", []string{"zone", "state"}, nil),
	}
}

func (c *APICollector) Name() string { return "angie" }

func (c *APICollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.connAccepted
	ch <- c.connDropped
	ch <- c.connActive
	ch <- c.connIdle

	ch <- c.szRequests
	ch <- c.szRequestsProc
	ch <- c.szRequestsDiscarded
	ch <- c.szResponses
	ch <- c.szRecvBytes
	ch <- c.szSentBytes
	ch <- c.szSSLHandshakes
	ch <- c.szSSLFailed

	ch <- c.upPeerState
	ch <- c.upPeerReqTotal
	ch <- c.upPeerReqCurrent
	ch <- c.upPeerResponses
	ch <- c.upPeerSentBytes
	ch <- c.upPeerRecvBytes
	ch <- c.upPeerHealthFails
	ch <- c.upPeerHealthDown
	ch <- c.upKeepalive

	ch <- c.cacheSize
	ch <- c.cacheResponses
	ch <- c.cacheBytes

	ch <- c.limitConns
	ch <- c.limitReqs

	ch <- c.slabPages
}

func (c *APICollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}

	resp, err := c.client.Do(req)
	if err != nil {
		c.Error(ctx, "angie: API request failed", "error", err)
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.Error(ctx, "angie: API returned error status", "status", resp.StatusCode)
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}

	var status StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		c.Error(ctx, "angie: failed to decode API response", "error", err)
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}

	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1)

	c.collectConnections(status.Connections, ch)
	c.collectServerZones(status.HTTP.ServerZones, ch)
	c.collectUpstreams(status.HTTP.Upstreams, ch)
	c.collectCaches(status.HTTP.Caches, ch)
	c.collectLimitConns(status.HTTP.LimitConns, ch)
	c.collectLimitReqs(status.HTTP.LimitReqs, ch)
	c.collectSlabs(status.Slabs, ch)
}

func (c *APICollector) collectConnections(conn Connections, ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.connAccepted, prometheus.CounterValue, float64(conn.Accepted))
	ch <- prometheus.MustNewConstMetric(c.connDropped, prometheus.CounterValue, float64(conn.Dropped))
	ch <- prometheus.MustNewConstMetric(c.connActive, prometheus.GaugeValue, float64(conn.Active))
	ch <- prometheus.MustNewConstMetric(c.connIdle, prometheus.GaugeValue, float64(conn.Idle))
}

func (c *APICollector) collectServerZones(zones map[string]ServerZone, ch chan<- prometheus.Metric) {
	for zone, sz := range zones {
		ch <- prometheus.MustNewConstMetric(c.szRequests, prometheus.CounterValue, float64(sz.Requests.Total), zone)
		ch <- prometheus.MustNewConstMetric(c.szRequestsProc, prometheus.GaugeValue, float64(sz.Requests.Processing), zone)
		ch <- prometheus.MustNewConstMetric(c.szRequestsDiscarded, prometheus.CounterValue, float64(sz.Requests.Discarded), zone)

		for code, count := range sz.Responses {
			ch <- prometheus.MustNewConstMetric(c.szResponses, prometheus.CounterValue, float64(count), zone, code)
		}

		ch <- prometheus.MustNewConstMetric(c.szRecvBytes, prometheus.CounterValue, float64(sz.Data.Received), zone)
		ch <- prometheus.MustNewConstMetric(c.szSentBytes, prometheus.CounterValue, float64(sz.Data.Sent), zone)
		ch <- prometheus.MustNewConstMetric(c.szSSLHandshakes, prometheus.CounterValue, float64(sz.SSL.Handshaked), zone)
		ch <- prometheus.MustNewConstMetric(c.szSSLFailed, prometheus.CounterValue, float64(sz.SSL.Failed), zone)
	}
}

func (c *APICollector) collectUpstreams(upstreams map[string]Upstream, ch chan<- prometheus.Metric) {
	for name, ups := range upstreams {
		ch <- prometheus.MustNewConstMetric(c.upKeepalive, prometheus.GaugeValue, float64(ups.Keepalive), name)

		for peer, p := range ups.Peers {
			stateVal := peerStateValues[p.State]
			ch <- prometheus.MustNewConstMetric(c.upPeerState, prometheus.GaugeValue, stateVal, name, peer)
			ch <- prometheus.MustNewConstMetric(c.upPeerReqTotal, prometheus.CounterValue, float64(p.Selected.Total), name, peer)
			ch <- prometheus.MustNewConstMetric(c.upPeerReqCurrent, prometheus.GaugeValue, float64(p.Selected.Current), name, peer)

			for code, count := range p.Responses {
				ch <- prometheus.MustNewConstMetric(c.upPeerResponses, prometheus.CounterValue, float64(count), name, peer, code)
			}

			ch <- prometheus.MustNewConstMetric(c.upPeerSentBytes, prometheus.CounterValue, float64(p.Data.Sent), name, peer)
			ch <- prometheus.MustNewConstMetric(c.upPeerRecvBytes, prometheus.CounterValue, float64(p.Data.Received), name, peer)
			ch <- prometheus.MustNewConstMetric(c.upPeerHealthFails, prometheus.CounterValue, float64(p.Health.Fails), name, peer)
			ch <- prometheus.MustNewConstMetric(c.upPeerHealthDown, prometheus.CounterValue, float64(p.Health.Downtime)/1000, name, peer)
		}
	}
}

func (c *APICollector) collectCaches(caches map[string]Cache, ch chan<- prometheus.Metric) {
	for zone, cache := range caches {
		ch <- prometheus.MustNewConstMetric(c.cacheSize, prometheus.GaugeValue, float64(cache.Size), zone)

		for _, cs := range [...]struct {
			status string
			stats  CacheStats
		}{
			{"hit", cache.Hit}, {"stale", cache.Stale}, {"updating", cache.Updating},
			{"revalidated", cache.Revalidated}, {"miss", cache.Miss},
			{"expired", cache.Expired}, {"bypass", cache.Bypass},
		} {
			ch <- prometheus.MustNewConstMetric(c.cacheResponses, prometheus.CounterValue, float64(cs.stats.Responses), zone, cs.status)
			ch <- prometheus.MustNewConstMetric(c.cacheBytes, prometheus.CounterValue, float64(cs.stats.Bytes), zone, cs.status)
		}
	}
}

func (c *APICollector) collectLimitConns(limits map[string]LimitConn, ch chan<- prometheus.Metric) {
	for zone, lc := range limits {
		ch <- prometheus.MustNewConstMetric(c.limitConns, prometheus.CounterValue, float64(lc.Passed), zone, "passed")
		ch <- prometheus.MustNewConstMetric(c.limitConns, prometheus.CounterValue, float64(lc.Skipped), zone, "skipped")
		ch <- prometheus.MustNewConstMetric(c.limitConns, prometheus.CounterValue, float64(lc.Rejected), zone, "rejected")
		ch <- prometheus.MustNewConstMetric(c.limitConns, prometheus.CounterValue, float64(lc.Exhausted), zone, "exhausted")
	}
}

func (c *APICollector) collectLimitReqs(limits map[string]LimitReq, ch chan<- prometheus.Metric) {
	for zone, lr := range limits {
		ch <- prometheus.MustNewConstMetric(c.limitReqs, prometheus.CounterValue, float64(lr.Passed), zone, "passed")
		ch <- prometheus.MustNewConstMetric(c.limitReqs, prometheus.CounterValue, float64(lr.Skipped), zone, "skipped")
		ch <- prometheus.MustNewConstMetric(c.limitReqs, prometheus.CounterValue, float64(lr.Delayed), zone, "delayed")
		ch <- prometheus.MustNewConstMetric(c.limitReqs, prometheus.CounterValue, float64(lr.Rejected), zone, "rejected")
		ch <- prometheus.MustNewConstMetric(c.limitReqs, prometheus.CounterValue, float64(lr.Exhausted), zone, "exhausted")
	}
}

func (c *APICollector) collectSlabs(slabs map[string]SlabZone, ch chan<- prometheus.Metric) {
	for zone, slab := range slabs {
		ch <- prometheus.MustNewConstMetric(c.slabPages, prometheus.GaugeValue, float64(slab.Pages.Used), zone, "used")
		ch <- prometheus.MustNewConstMetric(c.slabPages, prometheus.GaugeValue, float64(slab.Pages.Free), zone, "free")
	}
}
