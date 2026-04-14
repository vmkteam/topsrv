//go:build integration

package angie

import (
	"net/http"
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmkteam/embedlog"
)

func angieAPIURL() string {
	if v := os.Getenv("TEST_ANGIE_API"); v != "" {
		return v
	}
	return "http://127.0.0.1:18082/status/"
}

func angieHTTPURL() string {
	if v := os.Getenv("TEST_ANGIE_HTTP"); v != "" {
		return v
	}
	return "http://127.0.0.1:18081/"
}

func TestIntegrationAngieAPI(t *testing.T) {
	url := angieAPIURL()

	// Verify Angie API is reachable.
	resp, err := http.Get(url)
	require.NoError(t, err, "angie API not reachable at %s", url)
	resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	// Generate some traffic so server_zone metrics are non-zero.
	for range 5 {
		r, _ := http.Get(angieHTTPURL())
		if r != nil {
			r.Body.Close()
		}
	}

	c := NewAPICollector(embedlog.Logger{}, url)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, mfs, "angie collector returned no metrics")

	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}

	// Core metrics must be present.
	for _, name := range []string{
		"topsrv_angie_up",
		"topsrv_angie_connections_accepted_total",
		"topsrv_angie_connections_active",
		"topsrv_angie_server_zone_requests_total",
		"topsrv_angie_server_zone_responses_total",
		"topsrv_angie_server_zone_sent_bytes_total",
	} {
		assert.True(t, names[name], "missing metric: %s", name)
	}

	t.Logf("angie integration: %d metric families", len(mfs))
}
