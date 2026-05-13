package angie

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

// acmeSampleJSON mirrors the real angie 1.x /status/http/acme_clients/
// response with date=epoch — map keyed by client name, each entry has
// state / certificate / details / next_run (Unix seconds).
const acmeSampleJSON = `{
	"client_alpha": {
		"state": "ready",
		"certificate": "valid",
		"details": "The client is ready to request a certificate.",
		"next_run": 1781333625
	},
	"client_beta": {
		"state": "ready",
		"certificate": "valid",
		"details": "The client is ready to request a certificate.",
		"next_run": 1781333641
	}
}`

// newACMETestServer returns an httptest server that answers the angie
// status API ACME endpoint with handler(body). Other paths get 404.
func newACMETestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/status/http/acme_clients/", handler)
	return httptest.NewServer(mux)
}

func TestACMECollectorHappyPath(t *testing.T) {
	srv := newACMETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "epoch", r.URL.Query().Get("date"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(acmeSampleJSON))
	})
	defer srv.Close()

	c, err := NewACMECollector(embedlog.Logger{}, srv.URL+"/status/")
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	require.NoError(t, err)

	got := map[string]map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			name := mf.GetName()
			value := m.GetGauge().GetValue()
			if got[name] == nil {
				got[name] = map[string]float64{}
			}
			got[name][fmt.Sprintf("%v", labels)] = value
		}
	}

	// state marker for both clients
	assert.InDelta(t, 1.0, got["topsrv_angie_acme_state"]["map[certificate:valid name:client_alpha state:ready]"], 1e-9)
	assert.InDelta(t, 1.0, got["topsrv_angie_acme_state"]["map[certificate:valid name:client_beta state:ready]"], 1e-9)

	// next_run pulled verbatim from epoch field (no string parsing)
	assert.InDelta(t, 1_781_333_625, got["topsrv_angie_acme_next_run_seconds"]["map[name:client_alpha]"], 1e-6)
	assert.InDelta(t, 1_781_333_641, got["topsrv_angie_acme_next_run_seconds"]["map[name:client_beta]"], 1e-6)
}

// TestACMECollectorOmitsZeroNextRun — angie omits next_run when state is
// disabled or requesting; it decodes to 0. The collector must not emit a
// next_run metric for those clients (otherwise dashboards see "1970" as
// the next renewal — confusing).
func TestACMECollectorOmitsZeroNextRun(t *testing.T) {
	body := `{"only_state":{"state":"requesting","certificate":"missing","details":"in flight"}}`
	srv := newACMETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	defer srv.Close()

	c, err := NewACMECollector(embedlog.Logger{}, srv.URL+"/status/")
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() != "topsrv_angie_acme_next_run_seconds" {
			continue
		}
		assert.Empty(t, mf.GetMetric(), "next_run must not be emitted when angie omitted it")
	}
}

// TestACMECollector404Silent — when angie doesn't have acme_client configured,
// the endpoint 404s. Collector must stay silent (no logs, no metrics) so a
// host without ACME doesn't generate noise on every scrape.
func TestACMECollector404Silent(t *testing.T) {
	srv := newACMETestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	defer srv.Close()

	c, err := NewACMECollector(embedlog.Logger{}, srv.URL+"/status/")
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	require.NoError(t, err)

	for _, mf := range mfs {
		if mf.GetName() == "topsrv_angie_acme_state" || mf.GetName() == "topsrv_angie_acme_next_run_seconds" {
			assert.Empty(t, mf.GetMetric(), "404 must yield no ACME series")
		}
	}
}

// TestACMECollectorURLDerivation — collector takes a statusURL (the same
// one APICollector consumes), extends path with /http/acme_clients/, and
// attaches date=epoch. Host/port/scheme must survive untouched; the base
// path (e.g. /status/) must be preserved so we ride into the right
// sub-tree. The double-suffix case guards against a misconfigured
// statusURL that already points at the ACME endpoint — we shouldn't
// build /status/http/acme_clients/http/acme_clients/ on top.
func TestACMECollectorURLDerivation(t *testing.T) {
	cases := []struct {
		name       string
		statusURL  string
		wantScheme string
		wantHost   string
		wantPath   string
	}{
		{"trailing slash", "http://127.0.0.1:8080/status/", "http", "127.0.0.1:8080", "/status/http/acme_clients/"},
		{"no trailing slash", "http://127.0.0.1:8080/status", "http", "127.0.0.1:8080", "/status/http/acme_clients/"},
		{"https ipv6", "https://[::1]:443/status/", "https", "[::1]:443", "/status/http/acme_clients/"},
		{"named host nondefault port", "http://angie.test:81/status/", "http", "angie.test:81", "/status/http/acme_clients/"},
		{"already at acme endpoint", "http://angie.test:81/status/http/acme_clients/", "http", "angie.test:81", "/status/http/acme_clients/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewACMECollector(embedlog.Logger{}, tc.statusURL)
			require.NoError(t, err)

			u, err := url.Parse(c.url)
			require.NoError(t, err)
			assert.Equal(t, tc.wantScheme, u.Scheme, "scheme must be preserved")
			assert.Equal(t, tc.wantHost, u.Host, "host:port must be preserved")
			assert.Equal(t, tc.wantPath, u.Path)
			assert.Equal(t, "date=epoch", u.RawQuery)
		})
	}
}

// TestACMECollectorMalformedURL — bad URL surfaces as a constructor error,
// not a runtime panic during Collect.
func TestACMECollectorMalformedURL(t *testing.T) {
	_, err := NewACMECollector(embedlog.Logger{}, "://not-a-url")
	assert.Error(t, err)
}
