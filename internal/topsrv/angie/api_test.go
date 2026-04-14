package angie

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

const apiStatusResponse = `{
  "connections": {
    "accepted": 1000,
    "dropped": 5,
    "active": 42,
    "idle": 10
  },
  "http": {
    "server_zones": {
      "http_main": {
        "ssl": {
          "handshaked": 500,
          "reuses": 30,
          "timedout": 2,
          "failed": 3
        },
        "requests": {
          "total": 10000,
          "processing": 7,
          "discarded": 15
        },
        "responses": {
          "200": 9500,
          "302": 200,
          "404": 280,
          "500": 20
        },
        "data": {
          "received": 1048576,
          "sent": 52428800
        }
      }
    },
    "location_zones": {},
    "upstreams": {
      "backend": {
        "peers": {
          "10.0.0.1:8080": {
            "server": "10.0.0.1:8080",
            "state": "up",
            "selected": { "current": 3, "total": 5000 },
            "max_conns": 0,
            "responses": { "200": 4900, "502": 100 },
            "data": { "sent": 500000, "received": 25000000 },
            "health": { "fails": 10, "unavailable": 1, "downtime": 5000 }
          },
          "10.0.0.2:8080": {
            "server": "10.0.0.2:8080",
            "state": "down",
            "selected": { "current": 0, "total": 100 },
            "max_conns": 0,
            "responses": { "200": 50, "503": 50 },
            "data": { "sent": 10000, "received": 500000 },
            "health": { "fails": 50, "unavailable": 5, "downtime": 120000 }
          }
        },
        "keepalive": 4
      }
    },
    "caches": {
      "static_cache": {
        "size": 268435456,
        "cold": false,
        "hit":         { "responses": 8000, "bytes": 40000000 },
        "stale":       { "responses": 10,   "bytes": 50000 },
        "updating":    { "responses": 5,    "bytes": 25000 },
        "revalidated": { "responses": 100,  "bytes": 500000 },
        "miss":        { "responses": 1500, "bytes": 7500000 },
        "expired":     { "responses": 200,  "bytes": 1000000 },
        "bypass":      { "responses": 50,   "bytes": 250000 }
      }
    },
    "limit_conns": {
      "conn_limit": {
        "passed": 9000,
        "skipped": 0,
        "rejected": 100,
        "exhausted": 5
      }
    },
    "limit_reqs": {
      "req_limit": {
        "passed": 8500,
        "skipped": 0,
        "delayed": 300,
        "rejected": 50,
        "exhausted": 2
      }
    }
  },
  "slabs": {
    "backend_zone": {
      "pages": { "used": 10, "free": 54 }
    }
  }
}`

func gatherMetrics(t *testing.T, c *APICollector) map[string]float64 {
	t.Helper()

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	metrics := make(map[string]float64)
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			key := mf.GetName()
			var sb strings.Builder
			for _, l := range m.GetLabel() {
				sb.WriteString("{" + l.GetName() + "=" + l.GetValue() + "}")
			}
			key += sb.String()
			if m.GetGauge() != nil {
				metrics[key] = m.GetGauge().GetValue()
			} else if m.GetCounter() != nil {
				metrics[key] = m.GetCounter().GetValue()
			}
		}
	}
	return metrics
}

func TestAPICollector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(apiStatusResponse))
	}))
	defer srv.Close()

	c := NewAPICollector(embedlog.Logger{}, srv.URL)
	assert.Equal(t, "angie", c.Name())

	metrics := gatherMetrics(t, c)

	// Connections.
	checks := map[string]float64{
		"topsrv_angie_up":                         1,
		"topsrv_angie_connections_accepted_total": 1000,
		"topsrv_angie_connections_dropped_total":  5,
		"topsrv_angie_connections_active":         42,
		"topsrv_angie_connections_idle":           10,

		// Server zone.
		"topsrv_angie_server_zone_requests_total{zone=http_main}":            10000,
		"topsrv_angie_server_zone_requests_processing{zone=http_main}":       7,
		"topsrv_angie_server_zone_requests_discarded_total{zone=http_main}":  15,
		"topsrv_angie_server_zone_responses_total{code=200}{zone=http_main}": 9500,
		"topsrv_angie_server_zone_responses_total{code=404}{zone=http_main}": 280,
		"topsrv_angie_server_zone_responses_total{code=500}{zone=http_main}": 20,
		"topsrv_angie_server_zone_received_bytes_total{zone=http_main}":      1048576,
		"topsrv_angie_server_zone_sent_bytes_total{zone=http_main}":          52428800,
		"topsrv_angie_server_zone_ssl_handshakes_total{zone=http_main}":      500,
		"topsrv_angie_server_zone_ssl_failed_total{zone=http_main}":          3,

		// Upstreams.
		"topsrv_angie_upstream_keepalive{upstream=backend}":                                              4,
		"topsrv_angie_upstream_peer_state{peer=10.0.0.1:8080}{upstream=backend}":                         1, // up
		"topsrv_angie_upstream_peer_state{peer=10.0.0.2:8080}{upstream=backend}":                         2, // down
		"topsrv_angie_upstream_peer_requests_total{peer=10.0.0.1:8080}{upstream=backend}":                5000,
		"topsrv_angie_upstream_peer_requests_current{peer=10.0.0.1:8080}{upstream=backend}":              3,
		"topsrv_angie_upstream_peer_responses_total{code=200}{peer=10.0.0.1:8080}{upstream=backend}":     4900,
		"topsrv_angie_upstream_peer_responses_total{code=502}{peer=10.0.0.1:8080}{upstream=backend}":     100,
		"topsrv_angie_upstream_peer_sent_bytes_total{peer=10.0.0.1:8080}{upstream=backend}":              500000,
		"topsrv_angie_upstream_peer_received_bytes_total{peer=10.0.0.1:8080}{upstream=backend}":          25000000,
		"topsrv_angie_upstream_peer_health_fails_total{peer=10.0.0.1:8080}{upstream=backend}":            10,
		"topsrv_angie_upstream_peer_health_downtime_seconds_total{peer=10.0.0.1:8080}{upstream=backend}": 5,   // 5000ms → 5s
		"topsrv_angie_upstream_peer_health_downtime_seconds_total{peer=10.0.0.2:8080}{upstream=backend}": 120, // 120000ms → 120s

		// Caches.
		"topsrv_angie_cache_size_bytes{zone=static_cache}":                      268435456,
		"topsrv_angie_cache_responses_total{status=hit}{zone=static_cache}":     8000,
		"topsrv_angie_cache_bytes_total{status=hit}{zone=static_cache}":         40000000,
		"topsrv_angie_cache_responses_total{status=miss}{zone=static_cache}":    1500,
		"topsrv_angie_cache_bytes_total{status=miss}{zone=static_cache}":        7500000,
		"topsrv_angie_cache_responses_total{status=expired}{zone=static_cache}": 200,
		"topsrv_angie_cache_responses_total{status=bypass}{zone=static_cache}":  50,

		// Rate limiting.
		"topsrv_angie_limit_conns_total{status=passed}{zone=conn_limit}":   9000,
		"topsrv_angie_limit_conns_total{status=rejected}{zone=conn_limit}": 100,
		"topsrv_angie_limit_reqs_total{status=passed}{zone=req_limit}":     8500,
		"topsrv_angie_limit_reqs_total{status=delayed}{zone=req_limit}":    300,
		"topsrv_angie_limit_reqs_total{status=rejected}{zone=req_limit}":   50,

		// Slabs.
		"topsrv_angie_slab_pages{state=used}{zone=backend_zone}": 10,
		"topsrv_angie_slab_pages{state=free}{zone=backend_zone}": 54,
	}

	for key, want := range checks {
		got, ok := metrics[key]
		assert.True(t, ok, "metric %s not found", key)
		assert.InDelta(t, want, got, 1e-9, key)
	}
}

func TestAPICollectorDown(t *testing.T) {
	c := NewAPICollector(embedlog.Logger{}, "http://127.0.0.1:1")

	metrics := gatherMetrics(t, c)

	assert.InDelta(t, float64(0), metrics["topsrv_angie_up"], 1e-9)

	// No other metrics should be present.
	assert.Len(t, metrics, 1)
}

func TestAPICollectorEmptyZones(t *testing.T) {
	resp := `{"connections": {"accepted": 1, "dropped": 0, "active": 1, "idle": 0}, "http": {}, "slabs": {}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(resp))
	}))
	defer srv.Close()

	c := NewAPICollector(embedlog.Logger{}, srv.URL)
	metrics := gatherMetrics(t, c)

	assert.InDelta(t, float64(1), metrics["topsrv_angie_up"], 1e-9)
	assert.InDelta(t, float64(1), metrics["topsrv_angie_connections_accepted_total"], 1e-9)
	assert.InDelta(t, float64(1), metrics["topsrv_angie_connections_active"], 1e-9)

	// Only up + 4 connection metrics.
	assert.Len(t, metrics, 5)
}

func TestAPICollectorPeerState(t *testing.T) {
	tests := map[string]float64{
		"up":          1,
		"down":        2,
		"unavailable": 3,
		"recovering":  4,
		"busy":        5,
		"unknown":     0,
	}
	for state, want := range tests {
		got := peerStateValues[state]
		assert.InDelta(t, want, got, 1e-9, state)
	}
}
